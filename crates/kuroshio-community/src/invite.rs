//! 好友邀請碼（規格 03 第 6.1 節）
//!
//! 一段可以貼上、也可以掃 QR 的文字：`KRS1.` + base32（RFC 4648，大寫、不補 `=`），內容是
//! `版本 1 | 指紋 16 | 密鑰 16 | 端點（0 = 預設；1 doq / 2 dot / 3 https + 埠 2） | 網域長度 1 | 網域 | 檢查碼 4`。
//! 檢查碼 = SHA-256("kuroshio-invite\0" || 前面全部)[0..4]，打錯一個字就會被發現。
//!
//! - 邀請碼固定：密鑰存在金鑰目錄的 `invite.json`（只有擁有者能讀寫，跟 key.pem 同一套寫法），重新啟動不變；
//!   使用者按「重新產生」才換，舊的立刻失效。可以重複使用。
//! - 指紋是我的身分金鑰；對方貼上後先回連我的網域取身分文件，指紋不符就中止（可能有人冒充）。
//! - 好友請求不帶密鑰本身，只帶 `HMAC-SHA256(密鑰, 寄件者 | 收件者 | nonce | reqId)`（[`proof`]），用常數時間比對。
//! - 密鑰錯誤的請求當成一般好友請求處理（照自動規則），回應跟沒有邀請碼時一樣，不透露邀請碼存不存在。

use crate::identity::{fingerprint_bytes, fingerprint_text, write_atomic};
use crate::node::{apply_rotation, Community, OldVersion, PeerIdentity};
use crate::peers::{PeerKey, Rel};
use crate::transport::{Endpoint, Scheme};
use crate::util::{b64, hex, now_ms, random_bytes, sha256, unb64, valid_domain};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

pub const PREFIX: &str = "KRS1.";
const VERSION: u8 = 1;
const SUM_CONTEXT: &[u8] = b"kuroshio-invite\0";
const PROOF_CONTEXT: &[u8] = b"kuroshio/2-invite\0";
pub const FILE: &str = "invite.json";

/// 解開的邀請碼
#[derive(Clone, PartialEq, Eq)]
pub struct Invite {
    pub domain: String,
    /// 非預設的端點（全部端點都不在預設埠時才放）
    pub endpoint: Option<Endpoint>,
    pub fingerprint: [u8; 16],
    pub secret: [u8; 16],
}

/// 密鑰不能出現在日誌裡：Debug 只印網域與指紋
impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite")
            .field("domain", &self.domain)
            .field("endpoint", &self.endpoint)
            .field("fingerprint", &fingerprint_text(&self.fingerprint))
            .field("secret", &"***")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// 不是邀請碼（開頭、字元、長度）
    Format,
    /// 檢查碼不符：多半是打錯字或少貼了一段
    Checksum,
    /// 新版的邀請碼
    Version,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ParseError::Format => "這不是黑潮 DNS 的邀請碼（應該是 KRS1. 開頭的一串英數字）",
            ParseError::Checksum => "邀請碼檢查碼不符：可能打錯字或少貼了一段，請直接複製貼上",
            ParseError::Version => "邀請碼版本較新，請先更新黑潮 DNS",
        })
    }
}

impl std::error::Error for ParseError {}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn b32_encode(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for x in b {
        acc = (acc << 8) | *x as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// 嚴格解碼：最後多出來的位元一定要是 0（改到最後一個字也會被發現）
fn b32_decode(s: &str) -> Option<Vec<u8>> {
    if matches!(s.len() % 8, 1 | 3 | 6) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = B32.iter().position(|x| *x == c)? as u32;
        acc = ((acc << 5) | v) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let d = sha256(&[SUM_CONTEXT, payload]);
    [d[0], d[1], d[2], d[3]]
}

impl Invite {
    pub fn encode(&self) -> String {
        let mut p = vec![VERSION];
        p.extend_from_slice(&self.fingerprint);
        p.extend_from_slice(&self.secret);
        match &self.endpoint {
            None => p.push(0),
            Some(e) => {
                p.push(match e.scheme {
                    Scheme::Doq => 1,
                    Scheme::Dot => 2,
                    Scheme::Https => 3,
                });
                p.extend_from_slice(&e.port.to_be_bytes());
            }
        }
        p.push(self.domain.len() as u8);
        p.extend_from_slice(self.domain.as_bytes());
        let sum = checksum(&p);
        p.extend_from_slice(&sum);
        format!("{PREFIX}{}", b32_encode(&p))
    }

    /// 解析使用者貼上的文字：前後空白、中間的空白與換行忽略；大小寫不分；0 / 1 / 8 當成 O / I / B
    pub fn parse(input: &str) -> Result<Invite, ParseError> {
        let s: String = input
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_uppercase();
        let body = s.strip_prefix(PREFIX).ok_or(ParseError::Format)?;
        let body: String = body
            .chars()
            .map(|c| match c {
                '0' => 'O',
                '1' => 'I',
                '8' => 'B',
                c => c,
            })
            .collect();
        let b = b32_decode(&body).ok_or(ParseError::Format)?;
        if b.len() < 1 + 16 + 16 + 1 + 1 + 4 {
            return Err(ParseError::Format);
        }
        let (p, sum) = b.split_at(b.len() - 4);
        if checksum(p) != sum {
            return Err(ParseError::Checksum);
        }
        if p[0] != VERSION {
            return Err(ParseError::Version);
        }
        let mut fingerprint = [0u8; 16];
        fingerprint.copy_from_slice(&p[1..17]);
        let mut secret = [0u8; 16];
        secret.copy_from_slice(&p[17..33]);
        let mut i = 33;
        let scheme = match p[i] {
            0 => None,
            1 => Some(Scheme::Doq),
            2 => Some(Scheme::Dot),
            3 => Some(Scheme::Https),
            _ => return Err(ParseError::Format),
        };
        i += 1;
        let port = match scheme {
            Some(_) => {
                let port = u16::from_be_bytes(p.get(i..i + 2).ok_or(ParseError::Format)?.try_into().unwrap());
                i += 2;
                if port == 0 {
                    return Err(ParseError::Format);
                }
                port
            }
            None => 0,
        };
        let n = *p.get(i).ok_or(ParseError::Format)? as usize;
        i += 1;
        if p.len() != i + n {
            return Err(ParseError::Format);
        }
        let domain = std::str::from_utf8(&p[i..]).map_err(|_| ParseError::Format)?.to_string();
        if !valid_domain(&domain) || domain != domain.to_ascii_lowercase() {
            return Err(ParseError::Format);
        }
        Ok(Invite {
            endpoint: scheme.map(|scheme| Endpoint {
                scheme,
                host: domain.clone(),
                port,
            }),
            domain,
            fingerprint,
            secret,
        })
    }
}

/// 好友請求裡的邀請證明：HMAC-SHA256(密鑰, 寄件者 \0 收件者 \0 nonce \0 reqId)
pub fn proof(secret: &[u8; 16], from: &str, to: &str, nonce: &[u8], req_id: &str) -> Vec<u8> {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    ring::hmac::sign(&key, &proof_input(from, to, nonce, req_id)).as_ref().to_vec()
}

/// 常數時間比對
pub fn proof_ok(secret: &[u8; 16], from: &str, to: &str, nonce: &[u8], req_id: &str, got: &[u8]) -> bool {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    ring::hmac::verify(&key, &proof_input(from, to, nonce, req_id), got).is_ok()
}

fn proof_input(from: &str, to: &str, nonce: &[u8], req_id: &str) -> Vec<u8> {
    let mut m = PROOF_CONTEXT.to_vec();
    for part in [from.as_bytes(), to.as_bytes(), nonce] {
        m.extend_from_slice(part);
        m.push(0);
    }
    m.extend_from_slice(req_id.as_bytes());
    m
}

/// 存在金鑰目錄的邀請密鑰
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Stored {
    /// base64（16 bytes）
    secret: String,
    pub created_at: u64,
}

impl Stored {
    pub(crate) fn secret(&self) -> Option<[u8; 16]> {
        unb64(&self.secret).and_then(|b| b.try_into().ok())
    }

    fn generate() -> Stored {
        Stored {
            secret: b64(&random_bytes::<16>()),
            created_at: now_ms(),
        }
    }

    /// 讀 `dir/invite.json`（沒有或格式錯誤 → None）；權限太寬就收緊成只有擁有者能讀
    pub(crate) fn load(dir: &Path) -> Option<Stored> {
        let f = dir.join(FILE);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::metadata(&f).is_ok_and(|m| m.permissions().mode() & 0o077 != 0) {
                let _ = std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600));
            }
        }
        let s: Stored = serde_json::from_slice(&std::fs::read(f).ok()?).ok()?;
        s.secret().map(|_| s)
    }

    /// 產生新的密鑰並寫檔（只有使用者第一次查看、或按「重新產生」時才寫，不是定時寫入）
    fn create(dir: &Path) -> anyhow::Result<Stored> {
        let s = Stored::generate();
        std::fs::create_dir_all(dir)?;
        write_atomic(&dir.join(FILE), &serde_json::to_vec_pretty(&s)?)?;
        Ok(s)
    }
}

fn fail(stage: &str, reason: impl std::fmt::Display, steps: Vec<Value>) -> Value {
    json!({ "ok": false, "stage": stage, "reason": reason.to_string(), "steps": steps })
}

fn step(name: &str, ok: bool, text: impl std::fmt::Display) -> Value {
    json!({ "step": name, "ok": ok, "text": text.to_string() })
}

/// 身分文件的簽名金鑰是不是邀請碼裡的那一把：直接相同，或由那一把簽的輪替聲明換過來的
fn identity_matches(idn: &PeerIdentity, fp: &[u8; 16], now: u64) -> bool {
    let signer = hex(&idn.signer);
    for k in idn.keys.iter().filter(|k| fingerprint_bytes(&k.public) == *fp) {
        if k.kid == idn.signer {
            return true;
        }
        let mut keys = vec![PeerKey {
            kid: hex(&k.kid),
            public: b64(&k.public),
            since: k.since,
            until: None,
        }];
        for stmt in &idn.rot {
            apply_rotation(&mut keys, &idn.domain, &stmt.body, &stmt.sig, now);
        }
        if keys.iter().any(|x| x.kid == signer) {
            return true;
        }
    }
    false
}

impl Community {
    fn invite_lock(&self) -> std::sync::MutexGuard<'_, Option<Stored>> {
        self.invite.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 我的邀請碼（沒有密鑰就先產生一個並存檔）；網域還沒設定時回 None
    pub fn invite_code(&self) -> anyhow::Result<Option<(String, u64)>> {
        let cfg = self.config();
        if !valid_domain(&cfg.domain) {
            return Ok(None);
        }
        let stored = {
            let mut g = self.invite_lock();
            if g.is_none() {
                *g = Some(Stored::create(&self.key_dir)?);
            }
            g.clone().unwrap()
        };
        let Some(secret) = stored.secret() else {
            return Ok(None);
        };
        let eps: Vec<Endpoint> = self.my_endpoints().iter().filter_map(|e| Endpoint::parse(e)).collect();
        // 有任何一個端點在預設埠（443 / 853）時對方照預設就找得到，不用寫進邀請碼
        let endpoint = if eps.iter().any(|e| e.port == if e.scheme == Scheme::Https { 443 } else { 853 }) {
            None
        } else {
            eps.into_iter().next()
        };
        let inv = Invite {
            domain: cfg.domain,
            endpoint,
            fingerprint: fingerprint_bytes(&self.ident.read().unwrap().key.public),
            secret,
        };
        Ok(Some((inv.encode(), stored.created_at)))
    }

    /// `GET /api/community/invite`：只有擁有者自己的管理介面會拿到邀請碼本身
    pub fn invite_json(&self) -> Value {
        let (ready, problems) = {
            let st = self.lock();
            (st.check.ready, st.check.problems.clone())
        };
        let ready = ready && self.config().enabled;
        match self.invite_code() {
            Ok(Some((code, at))) => json!({
                "ok": true, "code": code, "createdAt": at, "domain": self.domain(), "fingerprint": self.fingerprint(),
                "ready": ready, "problems": problems,
            }),
            Ok(None) => json!({ "ok": false, "reason": "還沒有設定網域，無法產生邀請碼", "ready": ready, "problems": problems }),
            Err(e) => json!({ "ok": false, "reason": format!("無法儲存邀請碼：{e}"), "ready": ready, "problems": problems }),
        }
    }

    /// `POST /api/community/invite/refresh`：換新的密鑰，舊的邀請碼立刻失效
    pub fn refresh_invite(&self) -> Value {
        match Stored::create(&self.key_dir) {
            Ok(s) => {
                *self.invite_lock() = Some(s);
                self.lock().store.event("-", "重新產生邀請碼", "舊的邀請碼已失效");
                self.invite_json()
            }
            Err(e) => json!({ "ok": false, "reason": format!("無法儲存邀請碼：{e}") }),
        }
    }

    /// 邀請碼的建立時間（狀態頁用；不含邀請碼本身）
    pub(crate) fn invite_created_at(&self) -> Option<u64> {
        self.invite_lock().as_ref().map(|s| s.created_at)
    }

    /// 伺服器端：好友請求帶的邀請證明對不對（常數時間）。沒有密鑰一律不對
    pub(crate) fn invite_proof_ok(&self, from: &str, to: &str, nonce: &[u8], req_id: &str, got: &[u8]) -> bool {
        let Some(secret) = self.invite_lock().as_ref().and_then(|s| s.secret()) else {
            return false;
        };
        proof_ok(&secret, from, to, nonce, req_id, got)
    }

    /// `POST /api/community/invite/use?code=`：貼上好友的邀請碼。回傳每一步的結果；
    /// `stage` = 停在哪一步：format / ready / self / identity / fingerprint / request / sent / accepted
    pub async fn use_invite(&self, code: &str) -> Value {
        let mut steps = vec![];
        let inv = match Invite::parse(code) {
            Ok(x) => x,
            Err(e) => {
                steps.push(step("format", false, &e));
                return fail("format", e, steps);
            }
        };
        steps.push(step("format", true, format!("邀請碼格式正確：{}", inv.domain)));
        // 我這邊也要符合社群條件（雙向，不做單向訂閱）：沒就緒就列出缺什麼，不送任何東西
        if !self.is_ready() {
            self.check().await;
        }
        if !self.is_ready() {
            let problems = self.lock().check.problems.clone();
            let mut problems = problems;
            if !self.config().enabled && !problems.iter().any(|p| p.contains("沒有啟用")) {
                problems.insert(0, "社群模式沒有啟用".into());
            }
            steps.push(step("ready", false, format!("你的社群模式還沒就緒：{}", problems.join("；"))));
            let mut v = fail("ready", "你的社群模式還沒就緒，雙方都要符合社群條件才能加好友", steps);
            v["problems"] = json!(problems);
            return v;
        }
        steps.push(step("ready", true, "你的社群模式已就緒"));
        let me = self.domain();
        if inv.domain == me {
            steps.push(step("self", false, "這是你自己的邀請碼"));
            return fail("self", "這是你自己的邀請碼，請貼上好友的", steps);
        }
        let domain = inv.domain.clone();
        // 回連對方網域取身分文件（一般的社群管道，TLS 驗證憑證）
        let mut cands = vec![];
        if let Some(e) = &inv.endpoint {
            cands.push(e.clone());
            cands.extend(Endpoint::defaults(&domain, Some(e.port)));
        }
        for e in Endpoint::defaults(&domain, None) {
            if !cands.contains(&e) {
                cands.push(e);
            }
        }
        let now = now_ms();
        let idn = match self.fetch_identity(&domain, cands, false, true).await {
            Ok(x) => x,
            Err(e) => {
                let msg = if e.downcast_ref::<OldVersion>().is_some() {
                    "對方版本較舊（v1），不支援邀請碼".to_string()
                } else {
                    format!("連不上 {domain} 或無法驗證對方的身分文件：{e}")
                };
                steps.push(step("identity", false, &msg));
                return fail("identity", msg, steps);
            }
        };
        steps.push(step(
            "identity",
            true,
            format!("已取得 {domain} 的身分文件（經 {}）", idn.channel.as_str()),
        ));
        if !identity_matches(&idn, &inv.fingerprint, now) {
            // 可能是 DNS 被冒充：不送請求、不記住這份身分文件
            self.lock().id_cache.remove(&domain);
            let got = idn
                .keys
                .iter()
                .find(|k| k.kid == idn.signer)
                .map(|k| crate::identity::fingerprint(&k.public))
                .unwrap_or_default();
            let msg = format!(
                "身分指紋不符：邀請碼是 {}，{domain} 目前是 {got}。可能有人冒充對方，已中止，沒有送出任何請求",
                fingerprint_text(&inv.fingerprint)
            );
            self.lock().store.event(&domain, "邀請碼指紋不符", "可能有人冒充，已中止");
            steps.push(step("fingerprint", false, &msg));
            return fail("fingerprint", msg, steps);
        }
        steps.push(step(
            "fingerprint",
            true,
            format!("身分指紋相符：{}", fingerprint_text(&inv.fingerprint)),
        ));
        if self.peer(&domain).map(|p| p.rel == Rel::Friend).unwrap_or(false) {
            steps.push(step("request", true, "已經是好友"));
            return json!({ "ok": true, "stage": "accepted", "status": "accepted", "domain": domain, "steps": steps });
        }
        let port = inv.endpoint.as_ref().map(|e| e.port);
        let r = self.request_start(&domain, port, true, Some((idn, inv.secret))).await;
        let status = r["status"].as_str().unwrap_or("").to_string();
        if r["ok"] != true {
            let reason = r["reason"].as_str().unwrap_or("送出好友請求失敗").to_string();
            steps.push(step("request", false, &reason));
            return fail("request", reason, steps);
        }
        steps.push(step("request", true, "已送出好友請求（附邀請證明）"));
        let (ok, stage, text) = match status.as_str() {
            "accepted" => (true, "accepted", "對方已自動同意，成為好友；馬上開始第一次同步".to_string()),
            "pending" => (
                true,
                "sent",
                "對方沒有自動同意（邀請碼可能已重新產生、對方曾刪除你，或好友數已滿），等待對方審核".to_string(),
            ),
            "rejected" => (false, "request", "對方拒絕了你的請求".to_string()),
            "blocked" => (false, "request", "對方封鎖了你".to_string()),
            other => (
                false,
                "request",
                format!(
                    "對方回應 {other}{}",
                    r["error"].as_str().map(|e| format!("：{e}")).unwrap_or_default()
                ),
            ),
        };
        steps.push(step(stage, ok, &text));
        let mut v = json!({ "ok": ok, "stage": stage, "status": status, "domain": domain, "steps": steps });
        if !ok {
            v["reason"] = json!(text);
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ep: Option<Endpoint>) -> Invite {
        Invite {
            domain: "dns.example.com".into(),
            endpoint: ep,
            fingerprint: [7; 16],
            secret: [9; 16],
        }
    }

    #[test]
    fn roundtrip() {
        for ep in [
            None,
            Some(Endpoint {
                scheme: Scheme::Doq,
                host: "dns.example.com".into(),
                port: 8853,
            }),
        ] {
            let inv = sample(ep);
            let code = inv.encode();
            assert!(code.starts_with(PREFIX));
            assert!(code[PREFIX.len()..].bytes().all(|c| B32.contains(&c)), "{code}");
            assert_eq!(Invite::parse(&code).unwrap(), inv);
            // 小寫、前後空白、中間換行都可以
            let messy = format!("  {}\n{}  ", &code[..20].to_ascii_lowercase(), &code[20..]);
            assert_eq!(Invite::parse(&messy).unwrap(), inv);
        }
    }

    #[test]
    fn typo_is_detected() {
        let code = sample(None).encode();
        // 每一個位置換成別的字：一律被拒絕（檢查碼或多出來的位元）
        for i in PREFIX.len()..code.len() {
            let mut b = code.clone().into_bytes();
            b[i] = if b[i] == b'A' { b'B' } else { b'A' };
            let bad = String::from_utf8(b).unwrap();
            assert!(Invite::parse(&bad).is_err(), "位置 {i} 改了沒發現");
        }
        // 少貼一段
        assert!(Invite::parse(&code[..code.len() - 3]).is_err());
        assert_eq!(Invite::parse("hello"), Err(ParseError::Format));
        assert_eq!(Invite::parse("KRS1.!!!!"), Err(ParseError::Format));
        let mut b = code.into_bytes();
        let i = b.len() / 2;
        b[i] = if b[i] == b'C' { b'D' } else { b'C' };
        assert_eq!(Invite::parse(&String::from_utf8(b).unwrap()), Err(ParseError::Checksum));
    }

    #[test]
    fn debug_hides_secret() {
        let s = format!("{:?}", sample(None));
        assert!(s.contains("***") && !s.contains("9, 9"), "{s}");
    }

    #[test]
    fn proofs() {
        let p = proof(&[1; 16], "a.example", "b.example", &[0; 12], "r");
        assert!(proof_ok(&[1; 16], "a.example", "b.example", &[0; 12], "r", &p));
        assert!(!proof_ok(&[2; 16], "a.example", "b.example", &[0; 12], "r", &p), "密鑰不同");
        assert!(!proof_ok(&[1; 16], "c.example", "b.example", &[0; 12], "r", &p), "寄件者不同");
        assert!(!proof_ok(&[1; 16], "a.example", "b.example", &[1; 12], "r", &p), "nonce 不同");
        assert!(!proof_ok(&[1; 16], "a.example", "b.example", &[0; 12], "r", &p[..31]));
    }
}
