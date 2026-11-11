//! 內建 ACME（Let's Encrypt，Cloudflare DNS-01，規格 07 第 3 節）
//!
//! - 不用開 80 埠：在 `_acme-challenge.<網域>` 加 TXT 記錄驗證，完成後刪掉
//! - 憑證存成 PEM（DoT / DoQ / DoH / DoH3 用），CertStore 10 秒內自動換上，不用重啟
//! - 開機時憑證不存在或快到期（`acme.renewDays`）就先申請，之後每天檢查一次
//! - Cloudflare API Token 預設跟 DDNS 共用（權限：Zone → DNS → Edit、Zone → Zone → Read）
//! - OpenWrt 用 acme.sh（`/usr/libexec/kuroshio/acme.sh`）；ACME 用戶端只編進 `acme` 功能（Windows 版）

use crate::cloudflare::Cloudflare;
use anyhow::{bail, Result};
use kuroshio_config::get;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

pub const LETSENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub directory: String,
    pub email: String,
    pub domains: Vec<String>,
    pub renew_days: i64,
    pub token: String,
    pub api: String,
    pub zone: String,
    pub cert: PathBuf,
    pub key: PathBuf,
    /// ACME 帳號金鑰（只寫一次）
    pub account: PathBuf,
    /// 加完 TXT 記錄後等多久再通知 CA（Cloudflare 通常幾秒就生效）
    pub propagation: Duration,
}

/// 憑證檔位置：`acme.certFile` → `listen.dot.cert` → `listen.doh.cert` → `<設定目錄>/cert.pem`
pub fn cert_paths(cfg: &Value, base: &Path) -> (PathBuf, PathBuf) {
    let s = |k: &str| get(cfg, k).and_then(Value::as_str).filter(|v| !v.is_empty()).map(str::to_string);
    let rel = |p: String| {
        let p = PathBuf::from(p);
        if p.is_absolute() {
            p
        } else {
            base.join(p)
        }
    };
    let pair = s("acme.certFile")
        .zip(s("acme.keyFile"))
        .or_else(|| s("listen.dot.cert").zip(s("listen.dot.key")))
        .or_else(|| s("listen.doh.cert").zip(s("listen.doh.key")));
    match pair {
        Some((c, k)) => (rel(c), rel(k)),
        None => (base.join("cert.pem"), base.join("key.pem")),
    }
}

impl AcmeConfig {
    /// `acme.enabled` 關閉時 None
    pub fn from_cfg(cfg: &Value, base: &Path, state_dir: &Path) -> Option<AcmeConfig> {
        if !get(cfg, "acme.enabled").and_then(Value::as_bool).unwrap_or(false) {
            return None;
        }
        let s = |k: &str| get(cfg, k).and_then(Value::as_str).unwrap_or("").trim().to_string();
        let mut domains: Vec<String> = get(cfg, "acme.domains")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(|d| d.trim().to_lowercase())
                    .filter(|d| !d.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        if domains.is_empty() {
            // 沒寫網域：用公開頁的網域，再不然用 DDNS 的第一筆記錄
            let fallback = [s("site.hostname")]
                .into_iter()
                .chain(
                    get(cfg, "ddns.records")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_string),
                )
                .find(|d| !d.is_empty());
            domains.extend(fallback.map(|d| d.to_lowercase()));
        }
        let directory = match s("acme.server").as_str() {
            "" | "letsencrypt" => LETSENCRYPT.to_string(),
            "letsencrypt-staging" | "staging" => LETSENCRYPT_STAGING.to_string(),
            url => url.to_string(),
        };
        let token = [s("acme.apiToken"), s("ddns.apiToken")]
            .into_iter()
            .find(|t| !t.is_empty())
            .unwrap_or_default();
        let (cert, key) = cert_paths(cfg, base);
        Some(AcmeConfig {
            directory,
            email: s("acme.email"),
            domains,
            renew_days: get(cfg, "acme.renewDays").and_then(Value::as_i64).unwrap_or(30),
            token,
            api: [s("acme.api"), s("ddns.api")]
                .into_iter()
                .find(|t| !t.is_empty())
                .unwrap_or_else(|| "https://api.cloudflare.com/client/v4".into()),
            zone: [s("acme.zone"), s("ddns.zone")]
                .into_iter()
                .find(|t| !t.is_empty())
                .unwrap_or_default(),
            cert,
            key,
            account: state_dir.join("acme-account.json"),
            propagation: Duration::from_secs(get(cfg, "acme.propagationSec").and_then(Value::as_u64).unwrap_or(15)),
        })
    }

    pub fn check(&self) -> Result<()> {
        if self.domains.is_empty() {
            bail!("沒有設定網域（acme.domains，或 site.hostname / ddns.records）");
        }
        if self.token.is_empty() {
            bail!("沒有設定 Cloudflare API Token（acme.apiToken 或 ddns.apiToken）");
        }
        Ok(())
    }
}

/// 要不要申請：檔案不存在、讀不出來、剩不到 renew_days 天、或網域沒涵蓋全部 → 要
pub fn renewal_reason(cert: &Path, domains: &[String], renew_days: i64) -> Option<String> {
    let info = match crate::certinfo::read(cert) {
        Err(e) => return Some(e),
        Ok(v) => v,
    };
    let left = info["daysLeft"].as_i64().unwrap_or(-1);
    if left < renew_days {
        return Some(format!("剩 {left} 天到期"));
    }
    let names: Vec<String> = info["san"]
        .as_str()
        .unwrap_or("")
        .split(", ")
        .filter_map(|n| n.strip_prefix("DNS:"))
        .map(str::to_lowercase)
        .collect();
    let covered = |d: &String| {
        names.iter().any(|n| {
            n == d
                || n.strip_prefix("*.")
                    .is_some_and(|w| d.split_once('.').is_some_and(|(_, rest)| rest == w))
        })
    };
    if let Some(d) = domains.iter().find(|d| !covered(d)) {
        return Some(format!("憑證沒有涵蓋 {d}"));
    }
    None
}

/// DNS-01 的記錄名稱（萬用字元網域驗證的是去掉 `*.` 的名稱）
pub fn challenge_name(domain: &str) -> String {
    format!("_acme-challenge.{}", domain.trim_start_matches("*."))
}

pub struct Acme {
    pub cfg: AcmeConfig,
    #[cfg_attr(not(feature = "acme"), allow(dead_code))]
    cf: Cloudflare,
    status: Mutex<Value>,
    busy: tokio::sync::Mutex<()>,
}

impl Acme {
    pub fn new(cfg: AcmeConfig) -> Arc<Acme> {
        let cf = Cloudflare::new(&cfg.api, &cfg.token, &cfg.zone);
        Arc::new(Acme {
            status: Mutex::new(json!({ "enabled": true, "domains": cfg.domains, "cert": cfg.cert })),
            cfg,
            cf,
            busy: tokio::sync::Mutex::new(()),
        })
    }

    pub fn status(&self) -> Value {
        let mut v = self.status.lock().unwrap().clone();
        v["certInfo"] = crate::certinfo::read(&self.cfg.cert).unwrap_or(Value::Null);
        v["builtin"] = json!(cfg!(feature = "acme"));
        v
    }

    fn set(&self, k: &str, v: Value) {
        self.status.lock().unwrap()[k] = v;
    }

    /// 需要時申請；force = 不管到期日都重新申請
    pub async fn ensure(self: &Arc<Self>, force: bool) -> Result<bool> {
        let _g = self.busy.lock().await;
        self.cfg.check()?;
        let reason = if force {
            Some("手動要求".to_string())
        } else {
            renewal_reason(&self.cfg.cert, &self.cfg.domains, self.cfg.renew_days)
        };
        let Some(reason) = reason else { return Ok(false) };
        info!("申請憑證 {}（{reason}）", self.cfg.domains.join(", "));
        self.set("running", json!(true));
        let r = self.issue().await;
        self.set("running", json!(false));
        self.set("lastRun", json!(kuroshio_net::fetch::now_ms()));
        match &r {
            Ok(()) => {
                info!("憑證已更新：{}", self.cfg.cert.display());
                self.set("error", Value::Null);
            }
            Err(e) => {
                warn!("申請憑證失敗：{e:#}");
                self.set("error", json!(format!("{e:#}")));
            }
        }
        r.map(|_| true)
    }

    /// 開機後每天檢查一次（失敗時 1 小時後再試）
    pub fn spawn(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                let wait = match me.ensure(false).await {
                    Err(_) => Duration::from_secs(3600),
                    Ok(_) => Duration::from_secs(86400),
                };
                tokio::time::sleep(wait).await;
            }
        });
    }

    /// 在 Cloudflare 加 TXT，回傳要清掉的 (名稱, id)
    #[cfg_attr(not(feature = "acme"), allow(dead_code))]
    async fn publish(&self, name: &str, value: &str) -> Result<(String, String)> {
        let id = self.cf.add_txt(name, value).await?;
        Ok((name.to_string(), id))
    }

    #[cfg_attr(not(feature = "acme"), allow(dead_code))]
    async fn cleanup(&self, recs: &[(String, String)]) {
        for (name, id) in recs {
            if let Err(e) = self.cf.delete_record(name, id).await {
                warn!("刪除驗證記錄 {name} 失敗：{e:#}");
            }
        }
    }

    #[cfg(not(feature = "acme"))]
    async fn issue(&self) -> Result<()> {
        bail!("這個版本沒有內建 ACME 用戶端（OpenWrt 請用 acme.sh：設定頁「憑證」）")
    }

    #[cfg(feature = "acme")]
    async fn issue(&self) -> Result<()> {
        use anyhow::Context;
        use instant_acme::{
            Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
        };
        let c = &self.cfg;
        // 帳號：第一次建立並存下金鑰，之後沿用
        let account = match std::fs::read(&c.account)
            .ok()
            .and_then(|b| serde_json::from_slice::<AccountCredentials>(&b).ok())
        {
            Some(cred) => Account::builder()?.from_credentials(cred).await.context("讀取 ACME 帳號")?,
            None => {
                let contact = (!c.email.is_empty()).then(|| format!("mailto:{}", c.email));
                let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
                let (acc, cred) = Account::builder()?
                    .create(
                        &NewAccount {
                            contact: &contacts,
                            terms_of_service_agreed: true,
                            only_return_existing: false,
                        },
                        c.directory.clone(),
                        None,
                    )
                    .await
                    .context("建立 ACME 帳號")?;
                crate::persist::write_atomic(&c.account, serde_json::to_string(&cred)?.as_bytes())?;
                acc
            }
        };
        let ids: Vec<Identifier> = c.domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
        let mut order = account.new_order(&NewOrder::new(&ids)).await.context("建立訂單")?;
        let mut recs = Vec::new();
        let res: Result<String> = async {
            {
                let mut auths = order.authorizations();
                while let Some(a) = auths.next().await {
                    let mut a = a?;
                    if a.status == AuthorizationStatus::Valid {
                        continue;
                    }
                    if a.status != AuthorizationStatus::Pending {
                        bail!("驗證狀態 {:?}", a.status);
                    }
                    let ch = a
                        .challenge(ChallengeType::Dns01)
                        .ok_or_else(|| anyhow::anyhow!("CA 沒有提供 DNS-01 驗證"))?;
                    let name = challenge_name(&ch.identifier().to_string());
                    recs.push(self.publish(&name, &ch.key_authorization().dns_value()).await?);
                }
            }
            tokio::time::sleep(c.propagation).await;
            {
                let mut auths = order.authorizations();
                while let Some(a) = auths.next().await {
                    let mut a = a?;
                    if a.status != AuthorizationStatus::Pending {
                        continue;
                    }
                    if let Some(mut ch) = a.challenge(ChallengeType::Dns01) {
                        ch.set_ready().await?;
                    }
                }
            }
            let st = order.poll_ready(&RetryPolicy::default()).await?;
            if st != OrderStatus::Ready {
                bail!("訂單狀態 {st:?}（DNS 驗證沒有通過）");
            }
            let key = order.finalize().await?;
            let chain = order.poll_certificate(&RetryPolicy::default()).await?;
            // 先寫金鑰再寫憑證：CertStore 看到憑證變動時金鑰已經是新的
            crate::persist::write_atomic(&c.key, key.as_bytes())?;
            crate::persist::write_atomic(&c.cert, chain.as_bytes())?;
            Ok(chain)
        }
        .await;
        self.cleanup(&recs).await;
        res.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_fallbacks() {
        let base = Path::new("/etc/kuroshio");
        let state = Path::new("/etc/kuroshio/state");
        assert!(AcmeConfig::from_cfg(&json!({}), base, state).is_none());
        let cfg = json!({
            "acme": { "enabled": true, "server": "staging" },
            "ddns": { "apiToken": "t", "records": ["home.example.net"] },
            "listen": { "dot": { "cert": "tls/c.pem", "key": "/abs/k.pem" } }
        });
        let a = AcmeConfig::from_cfg(&cfg, base, state).unwrap();
        assert_eq!(a.domains, vec!["home.example.net"]);
        assert_eq!(a.directory, LETSENCRYPT_STAGING);
        assert_eq!(a.token, "t");
        assert_eq!(a.cert, PathBuf::from("/etc/kuroshio/tls/c.pem"));
        assert_eq!(a.key, PathBuf::from("/abs/k.pem"));
        assert!(a.check().is_ok());
        let a = AcmeConfig::from_cfg(&json!({ "acme": { "enabled": true } }), base, state).unwrap();
        assert_eq!(a.cert, PathBuf::from("/etc/kuroshio/cert.pem"));
        assert!(a.check().is_err(), "沒有網域、沒有 token");
    }

    #[test]
    fn challenge_names() {
        assert_eq!(challenge_name("a.example.net"), "_acme-challenge.a.example.net");
        assert_eq!(challenge_name("*.example.net"), "_acme-challenge.example.net");
    }

    #[test]
    fn missing_cert_needs_issue() {
        let r = renewal_reason(Path::new("/nonexistent/cert.pem"), &["a.example.net".into()], 30);
        assert!(r.is_some());
    }
}
