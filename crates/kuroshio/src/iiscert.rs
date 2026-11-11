//! IIS 反向代理模式的憑證（規格 07 第 3 節）：把黑潮 DNS 用的 PEM 憑證放進 Windows「本機電腦\個人」存放區，
//! 綁到 IIS 站台的 HTTPS（SNI）；憑證續期後自動重新匯入並更新綁定，舊的憑證在新綁定生效後移除。
//!
//! - `kuroshio iis cert <站台>`：立即同步一次（`kuroshio iis setup` 也會做）
//! - 服務執行中：設定裡有 `listen.doh.iisSite` 時每 10 分鐘比對憑證指紋，變了就重新同步（服務以 LocalSystem 執行才有權限）
//!
//! PEM → PFX 的轉換與指令內容跨平台（可以在任何系統上測試）；真正執行 certutil / appcmd / netsh 只在 Windows。

use anyhow::{anyhow, bail, Context, Result};
use kuroshio_config::get;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// IIS 自己的應用程式 ID（用這個 ID 綁定，IIS 管理員裡才看得到是站台的憑證）
pub const IIS_APPID: &str = "{4dc3e181-e14b-4a21-b022-59fc669b0914}";
/// 記錄目前綁在 IIS 上的是哪一張（state 目錄）
pub const STATE_FILE: &str = "iis-cert.json";

/// 讀進來的憑證鏈（DER，第一張是伺服器憑證）與私鑰（PKCS#8 DER）
pub struct Material {
    pub chain: Vec<Vec<u8>>,
    pub key_pkcs8: Vec<u8>,
}

/// DER 的 TLV
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

/// 讀一個 TLV：回傳 (tag, 內容, 剩下的)
fn read_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    let (&l0, rest) = rest.split_first()?;
    let (len, rest) = if l0 < 0x80 {
        (l0 as usize, rest)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        (rest[..n].iter().fold(0usize, |a, b| (a << 8) | *b as usize), &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

const OID_RSA: [u8; 11] = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC_PUBLIC_KEY: [u8; 9] = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

fn pkcs8(algorithm: &[u8], key: &[u8]) -> Vec<u8> {
    let mut body = vec![0x02, 0x01, 0x00]; // version 0
    body.extend_from_slice(&tlv(0x30, algorithm));
    body.extend_from_slice(&tlv(0x04, key));
    tlv(0x30, &body)
}

/// 各種 PEM 私鑰格式統一成 PKCS#8（PFX 只收這種）
pub fn to_pkcs8(key: &rustls::pki_types::PrivateKeyDer<'_>) -> Result<Vec<u8>> {
    use rustls::pki_types::PrivateKeyDer as K;
    match key {
        K::Pkcs8(k) => Ok(k.secret_pkcs8_der().to_vec()),
        // 舊式 RSA（BEGIN RSA PRIVATE KEY）
        K::Pkcs1(k) => {
            let mut alg = OID_RSA.to_vec();
            alg.extend_from_slice(&[0x05, 0x00]);
            Ok(pkcs8(&alg, k.secret_pkcs1_der()))
        }
        // 舊式 EC（BEGIN EC PRIVATE KEY）：曲線寫在金鑰裡的 [0] 參數
        K::Sec1(k) => {
            let der = k.secret_sec1_der();
            let (_, mut inner, _) = read_tlv(der).filter(|t| t.0 == 0x30).ok_or_else(|| anyhow!("EC 私鑰格式錯誤"))?;
            let mut curve = None;
            while let Some((tag, content, rest)) = read_tlv(inner) {
                if tag == 0xa0 {
                    curve = read_tlv(content).filter(|t| t.0 == 0x06).map(|_| content.to_vec());
                }
                inner = rest;
            }
            let curve = curve.ok_or_else(|| anyhow!("EC 私鑰沒有標明曲線，請先轉成 PKCS#8（openssl pkcs8 -topk8 -nocrypt）"))?;
            let mut alg = OID_EC_PUBLIC_KEY.to_vec();
            alg.extend_from_slice(&curve);
            Ok(pkcs8(&alg, der))
        }
        _ => bail!("不認識的私鑰格式"),
    }
}

pub fn load(cert: &Path, key: &Path) -> Result<Material> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let chain: Vec<Vec<u8>> = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("讀不到憑證 {}", cert.display()))?
        .filter_map(|c| c.ok())
        .map(|c| c.to_vec())
        .collect();
    if chain.is_empty() {
        bail!("{} 裡沒有憑證", cert.display());
    }
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| anyhow!("讀不到私鑰 {}：{e}", key.display()))?;
    Ok(Material {
        chain,
        key_pkcs8: to_pkcs8(&key)?,
    })
}

/// 憑證指紋（SHA-1，大寫十六進位）：Windows 憑證存放區與 netsh 用這個認憑證
pub fn thumbprint(cert_der: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, cert_der)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

/// 包成 PFX（PKCS#12，3DES / SHA-1：Windows Server 2012 以後的版本都能匯入）。密碼只用一次
#[cfg(any(windows, test))]
pub fn pfx(m: &Material, password: &str) -> Result<Vec<u8>> {
    let cas: Vec<&[u8]> = m.chain[1..].iter().map(Vec::as_slice).collect();
    let p = p12::PFX::new_with_cas(&m.chain[0], &m.key_pkcs8, &cas, password, "Kuroshio DNS").ok_or_else(|| anyhow!("無法產生 PFX"))?;
    Ok(p.to_der())
}

/// 黑潮 DNS 用的憑證與私鑰：DoH 自己指定的 → 共用的 `tls.cert` → DoT 的 → 內建 ACME 的輸出位置
pub fn cert_files(cfg: &Value, base: &Path) -> (PathBuf, PathBuf) {
    crate::app::cert_for(cfg, "doh", base)
        .or_else(|| crate::app::cert_for(cfg, "dot", base))
        .unwrap_or_else(|| crate::acme::cert_paths(cfg, base))
}

pub fn domain(cfg: &Value) -> Option<String> {
    ["site.hostname", "domain"]
        .iter()
        .filter_map(|k| get(cfg, k).and_then(Value::as_str))
        .map(|d| d.trim().trim_end_matches('.').to_lowercase())
        .find(|d| !d.is_empty())
}

/// IIS 站台名稱與網域只允許安全的字元（會放進指令參數）
pub fn valid_site(site: &str) -> bool {
    !site.is_empty() && site.len() <= 128 && site.chars().all(|c| c.is_alphanumeric() || " ._-()".contains(c))
}

pub fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.split('.')
            .all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

/// 要執行的指令（程式, 參數, 失敗要不要緊）
pub struct Step {
    pub cmd: String,
    pub args: Vec<String>,
    pub required: bool,
}

/// 同步的步驟：匯入 PFX → 站台加上 HTTPS（SNI）繫結 → 綁上這張憑證 → 移除舊憑證
#[allow(clippy::too_many_arguments)]
pub fn steps(
    appcmd: &str,
    site: &str,
    domain: &str,
    thumb: &str,
    pfx_file: &str,
    password: &str,
    has_binding: bool,
    old_thumb: Option<&str>,
) -> Vec<Step> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let mut out = vec![Step {
        cmd: "certutil".into(),
        args: s(&["-f", "-p", password, "-importPFX", "My", pfx_file]),
        required: true,
    }];
    if !has_binding {
        out.push(Step {
            cmd: appcmd.into(),
            args: vec![
                "set".into(),
                "site".into(),
                format!("/site.name:{site}"),
                format!("/+bindings.[protocol='https',bindingInformation='*:443:{domain}',sslFlags='1']"),
            ],
            required: true,
        });
    }
    let hostport = format!("hostnameport={domain}:443");
    out.push(Step {
        cmd: "netsh".into(),
        args: s(&["http", "delete", "sslcert", &hostport]),
        required: false,
    });
    out.push(Step {
        cmd: "netsh".into(),
        args: s(&[
            "http",
            "add",
            "sslcert",
            &hostport,
            &format!("certhash={thumb}"),
            &format!("appid={IIS_APPID}"),
            "certstorename=MY",
        ]),
        required: true,
    });
    if let Some(old) = old_thumb.filter(|o| !o.eq_ignore_ascii_case(thumb)) {
        out.push(Step {
            cmd: "certutil".into(),
            args: s(&["-delstore", "My", old]),
            required: false,
        });
    }
    out
}

/// IIS 反向代理模式要的設定（寫進使用者的 config.json）：DoH 改聽本機的純 HTTP、記下站台名稱（續期時自動同步憑證）。
/// 回傳改了哪些欄位
pub fn apply_iis_config(user: &mut Value, site: &str) -> Vec<String> {
    let mut changed = Vec::new();
    if !user.is_object() {
        *user = serde_json::json!({});
    }
    let root = user.as_object_mut().unwrap();
    let listen = root.entry("listen").or_insert_with(|| serde_json::json!({}));
    if !listen.is_object() {
        *listen = serde_json::json!({});
    }
    let doh = listen
        .as_object_mut()
        .unwrap()
        .entry("doh")
        .or_insert_with(|| serde_json::json!({}));
    if !doh.is_object() {
        *doh = serde_json::json!({});
    }
    let doh = doh.as_object_mut().unwrap();
    let mut set = |k: &str, v: Value| {
        if doh.get(k) != Some(&v) {
            changed.push(format!("listen.doh.{k} = {v}"));
            doh.insert(k.to_string(), v);
        }
    };
    set("enabled", serde_json::json!(true));
    set("windowsMode", serde_json::json!("iis-proxy"));
    set("host", serde_json::json!("127.0.0.1"));
    set("iisSite", serde_json::json!(site));
    // 443 是 IIS 的：黑潮 DNS 的 DoH 改聽 8053（已經是別的埠就不動）
    let port = doh.get("port").and_then(Value::as_u64).unwrap_or(0);
    if port == 0 || port == 443 {
        changed.push("listen.doh.port = 8053".into());
        doh.insert("port".into(), serde_json::json!(8053));
    }
    changed
}

#[cfg(not(windows))]
pub fn sync(_cfg: &Value, _site: &str, _base: &Path, _state_dir: &Path, _force: bool) -> Result<String> {
    bail!("IIS 只在 Windows 上")
}

/// 服務執行中：憑證換了就重新同步到 IIS（只有 Windows、而且設定了 `listen.doh.iisSite` 才會動）
pub fn spawn_auto_sync(cfg: &Value, base: PathBuf, state_dir: PathBuf) {
    let site = get(cfg, "listen.doh.iisSite")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if !cfg!(windows) || site.is_empty() {
        return;
    }
    let cfg = cfg.clone();
    tokio::spawn(async move {
        let mut last_error = String::new();
        loop {
            let (c, b, s, st) = (cfg.clone(), base.clone(), site.clone(), state_dir.clone());
            match tokio::task::spawn_blocking(move || sync(&c, &s, &b, &st, false)).await {
                Ok(Ok(msg)) => {
                    if !msg.contains("已經是最新") {
                        tracing::info!("IIS 憑證：{msg}");
                    }
                    last_error.clear();
                }
                Ok(Err(e)) => {
                    // 同一個錯誤只記一次（例如 cmd 執行時沒有系統管理員權限）
                    let e = format!("{e:#}");
                    if e != last_error {
                        tracing::warn!("IIS 憑證同步失敗：{e}");
                        last_error = e;
                    }
                }
                Err(_) => {}
            }
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        }
    });
}

#[cfg(windows)]
pub use imp::sync;

#[cfg(windows)]
mod imp {
    use super::*;
    use serde_json::json;
    use std::process::Command;

    fn run(step: &Step) -> Result<String> {
        let out = Command::new(&step.cmd)
            .args(&step.args)
            .output()
            .with_context(|| format!("無法執行 {}", step.cmd))?;
        let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
        if !out.status.success() && step.required {
            // 不把一次性密碼印出來
            let shown: Vec<&str> = step
                .args
                .iter()
                .map(String::as_str)
                .filter(|a| !a.starts_with("-p"))
                .take(4)
                .collect();
            bail!("{} {} 失敗：{}", step.cmd, shown.join(" "), text.trim());
        }
        Ok(text)
    }

    fn appcmd() -> PathBuf {
        let windir = std::env::var_os("windir")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        windir.join(r"System32\inetsrv\appcmd.exe")
    }

    /// 把目前的憑證同步到 IIS 站台。回傳做了什麼（給人看的一句話）
    pub fn sync(cfg: &Value, site: &str, base: &Path, state_dir: &Path, force: bool) -> Result<String> {
        if !valid_site(site) {
            bail!("IIS 站台名稱含有不允許的字元：{site}");
        }
        let domain = domain(cfg).ok_or_else(|| anyhow!("沒有設定網域（domain / site.hostname）：IIS 的 HTTPS 繫結需要網域"))?;
        if !valid_domain(&domain) {
            bail!("網域格式不對：{domain}");
        }
        let (cert, key) = cert_files(cfg, base);
        let m = load(&cert, &key)?;
        if let Some(why) = crate::acme::renewal_reason(&cert, std::slice::from_ref(&domain), 0) {
            if !force {
                bail!("憑證 {} 不能用在 {domain}：{why}（確定要用請加 --force）", cert.display());
            }
        }
        let thumb = thumbprint(&m.chain[0]);
        let appcmd = appcmd();
        if !appcmd.exists() {
            bail!("找不到 IIS（{}）", appcmd.display());
        }
        let a = appcmd.to_string_lossy().to_string();
        let state_file = state_dir.join(STATE_FILE);
        let old: Value = std::fs::read(&state_file)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null);
        let old_thumb = old["thumbprint"].as_str().map(str::to_string);
        let hostport = format!("hostnameport={domain}:443");
        let bound = Command::new("netsh")
            .args(["http", "show", "sslcert", &hostport])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).replace(' ', "").to_uppercase().contains(&thumb))
            .unwrap_or(false);
        if bound && !force && old_thumb.as_deref() == Some(thumb.as_str()) && old["site"] == json!(site) {
            return Ok(format!("{domain} 已經是最新的憑證（{thumb}）"));
        }
        let bindings = run(&Step {
            cmd: a.clone(),
            args: vec!["list".into(), "site".into(), site.into(), "/text:bindings".into()],
            required: true,
        })
        .with_context(|| format!("找不到 IIS 站台「{site}」"))?;
        let has_binding = bindings.to_lowercase().contains(&format!("https/*:443:{domain}"));
        // PFX 只存在匯入的這一瞬間，密碼是隨機的一次性密碼
        let password = crate::webui::random_hex(16);
        std::fs::create_dir_all(state_dir)?;
        let pfx_file = state_dir.join(format!("iis-{}.pfx", crate::webui::random_hex(6)));
        std::fs::write(&pfx_file, pfx(&m, &password)?)?;
        let plan = steps(
            &a,
            site,
            &domain,
            &thumb,
            &pfx_file.to_string_lossy(),
            &password,
            has_binding,
            old_thumb.as_deref(),
        );
        let result = plan.iter().try_for_each(|s| run(s).map(|_| ()));
        let _ = std::fs::remove_file(&pfx_file);
        result?;
        crate::persist::write_atomic(
            &state_file,
            serde_json::to_string_pretty(&json!({ "site": site, "domain": domain, "thumbprint": thumb, "cert": cert }))?.as_bytes(),
        )?;
        Ok(format!(
            "已把 {} 的憑證（{thumb}）匯入「本機電腦\\個人」並綁到 IIS 站台「{site}」的 https://{domain}:443{}",
            cert.display(),
            if has_binding { "" } else { "（新增了 HTTPS 繫結）" }
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivateKeyDer;
    use serde_json::json;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kuroshio-iiscert-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn der_helpers() {
        assert_eq!(tlv(0x04, &[1, 2]), vec![0x04, 2, 1, 2]);
        let long = tlv(0x30, &[0u8; 300]);
        assert_eq!(&long[..4], &[0x30, 0x82, 0x01, 0x2c]);
        let (tag, content, rest) = read_tlv(&long).unwrap();
        assert_eq!((tag, content.len(), rest.len()), (0x30, 300, 0));
        assert!(read_tlv(&[0x30, 0x05, 1]).is_none(), "長度超過內容");
        assert!(read_tlv(&[0x30, 0x80]).is_none(), "不接受不定長度");
    }

    #[test]
    fn pfx_round_trip_with_chain() {
        let dir = tmp("pfx");
        let ca = rcgen::generate_simple_self_signed(vec!["ca.example.net".into()]).unwrap();
        let leaf = rcgen::generate_simple_self_signed(vec!["dns.example.net".into()]).unwrap();
        std::fs::write(dir.join("cert.pem"), format!("{}{}", leaf.cert.pem(), ca.cert.pem())).unwrap();
        std::fs::write(dir.join("key.pem"), leaf.key_pair.serialize_pem()).unwrap();
        let m = load(&dir.join("cert.pem"), &dir.join("key.pem")).unwrap();
        assert_eq!(m.chain.len(), 2);
        let der = pfx(&m, "pw123").unwrap();
        let back = p12::PFX::parse(&der).unwrap();
        assert!(back.verify_mac("pw123") && !back.verify_mac("wrong"));
        assert_eq!(back.cert_x509_bags("pw123").unwrap(), m.chain, "伺服器憑證在前，中繼憑證在後");
        assert_eq!(back.key_bags("pw123").unwrap(), vec![m.key_pkcs8.clone()]);
        let t = thumbprint(&m.chain[0]);
        assert!(t.len() == 40 && t.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 手動交叉驗證用：`KUROSHIO_PFX_DIR=<有 cert.pem / key.pem 的資料夾> cargo test -p kuroshio --lib pfx_for_openssl -- --ignored`
    /// 會寫出 out.pfx（密碼 pw123）並印出指紋，再用 openssl pkcs12 讀回來比對
    #[test]
    #[ignore]
    fn pfx_for_openssl() {
        let dir = PathBuf::from(std::env::var("KUROSHIO_PFX_DIR").expect("KUROSHIO_PFX_DIR"));
        let key = std::env::var("KUROSHIO_PFX_KEY").unwrap_or_else(|_| "key.pem".into());
        let m = load(&dir.join("cert.pem"), &dir.join(key)).unwrap();
        std::fs::write(dir.join("out.pfx"), pfx(&m, "pw123").unwrap()).unwrap();
        println!("THUMB={}", thumbprint(&m.chain[0]));
    }

    #[test]
    fn legacy_key_formats_become_pkcs8() {
        // PKCS#1（RSA）：包一層演算法標頭
        let pkcs1 = vec![0x30, 0x03, 0x02, 0x01, 0x00];
        let k = PrivateKeyDer::Pkcs1(pkcs1.clone().into());
        let out = to_pkcs8(&k).unwrap();
        let (tag, body, _) = read_tlv(&out).unwrap();
        assert_eq!(tag, 0x30);
        assert_eq!(&body[..3], &[0x02, 0x01, 0x00]);
        assert!(out.windows(OID_RSA.len()).any(|w| w == OID_RSA) && out.ends_with(&pkcs1));
        // SEC1（EC）：曲線從 [0] 參數拿（P-256 = 1.2.840.10045.3.1.7）
        let p256 = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        let mut inner = vec![0x02, 0x01, 0x01];
        inner.extend_from_slice(&tlv(0x04, &[7u8; 32]));
        inner.extend_from_slice(&tlv(0xa0, &p256));
        let sec1 = tlv(0x30, &inner);
        let out = to_pkcs8(&PrivateKeyDer::Sec1(sec1.clone().into())).unwrap();
        assert!(out.windows(OID_EC_PUBLIC_KEY.len()).any(|w| w == OID_EC_PUBLIC_KEY));
        assert!(out.windows(p256.len()).any(|w| w == p256) && out.ends_with(&sec1));
        // 沒有標明曲線：說清楚怎麼處理，不亂猜
        let mut inner = vec![0x02, 0x01, 0x01];
        inner.extend_from_slice(&tlv(0x04, &[7u8; 32]));
        let e = to_pkcs8(&PrivateKeyDer::Sec1(tlv(0x30, &inner).into())).unwrap_err();
        assert!(e.to_string().contains("PKCS#8"));
    }

    #[test]
    fn command_plan() {
        let s = steps(
            "appcmd.exe",
            "Default Web Site",
            "dns.example.net",
            "ABCD",
            r"C:\x\iis.pfx",
            "pw",
            false,
            Some("OLD1"),
        );
        let line = |i: usize| format!("{} {}", s[i].cmd, s[i].args.join(" "));
        assert_eq!(line(0), r"certutil -f -p pw -importPFX My C:\x\iis.pfx");
        assert_eq!(
            line(1),
            "appcmd.exe set site /site.name:Default Web Site /+bindings.[protocol='https',bindingInformation='*:443:dns.example.net',sslFlags='1']"
        );
        assert_eq!(line(2), "netsh http delete sslcert hostnameport=dns.example.net:443");
        assert!(!s[2].required, "還沒綁過的時候刪除會失敗，不要緊");
        assert_eq!(
            line(3),
            format!("netsh http add sslcert hostnameport=dns.example.net:443 certhash=ABCD appid={IIS_APPID} certstorename=MY")
        );
        assert_eq!(line(4), "certutil -delstore My OLD1");
        // 已經有繫結、憑證沒換：不加繫結、不刪憑證
        let s = steps(
            "appcmd.exe",
            "Default Web Site",
            "dns.example.net",
            "ABCD",
            "f",
            "pw",
            true,
            Some("abcd"),
        );
        assert_eq!(s.len(), 3);
        assert!(s
            .iter()
            .all(|x| !x.args.iter().any(|a| a.contains("delstore") || a.contains("bindings"))));
    }

    #[test]
    fn names_are_validated() {
        assert!(valid_site("Default Web Site") && valid_site("dns-site_1 (prod)"));
        assert!(!valid_site("a\" /b") && !valid_site("x'y") && !valid_site("") && !valid_site("a&b"));
        assert!(valid_domain("dns.example.net") && !valid_domain("dns..net") && !valid_domain("a b.net") && !valid_domain("x.net'"));
        assert_eq!(domain(&json!({ "domain": "DNS.Example.Net." })).as_deref(), Some("dns.example.net"));
        assert_eq!(
            domain(&json!({ "domain": "a.example", "site": { "hostname": "b.example" } })).as_deref(),
            Some("b.example")
        );
    }

    #[test]
    fn iis_config_is_applied_once() {
        let mut user = json!({ "listen": { "doh": { "port": 443, "path": "/dns-query" } }, "domain": "dns.example.net" });
        let c = apply_iis_config(&mut user, "Default Web Site");
        assert_eq!(c.len(), 5, "{c:?}");
        assert_eq!(
            user["listen"]["doh"],
            json!({ "port": 8053, "path": "/dns-query", "enabled": true, "windowsMode": "iis-proxy", "host": "127.0.0.1", "iisSite": "Default Web Site" })
        );
        assert_eq!(user["domain"], "dns.example.net", "其他設定不動");
        assert!(apply_iis_config(&mut user, "Default Web Site").is_empty(), "再跑一次不會再改");
        // 自訂的埠保留
        let mut user = json!({ "listen": { "doh": { "port": 8100 } } });
        apply_iis_config(&mut user, "x");
        assert_eq!(user["listen"]["doh"]["port"], 8100);
        // 空的設定檔
        let mut user = json!(null);
        apply_iis_config(&mut user, "x");
        assert_eq!(user["listen"]["doh"]["port"], 8053);
    }

    #[test]
    fn cert_file_order() {
        let base = Path::new("/cfg");
        let p = |c: Value| cert_files(&c, base).0;
        assert_eq!(p(json!({})), PathBuf::from("/cfg/cert.pem"));
        assert_eq!(
            p(json!({ "tls": { "cert": "tls/c.pem", "key": "tls/k.pem" } })),
            PathBuf::from("/cfg/tls/c.pem")
        );
        assert_eq!(
            p(json!({ "tls": { "cert": "t.pem", "key": "t.key" }, "listen": { "doh": { "cert": "/abs/d.pem", "key": "/abs/d.key" } } })),
            PathBuf::from("/abs/d.pem")
        );
    }
}
