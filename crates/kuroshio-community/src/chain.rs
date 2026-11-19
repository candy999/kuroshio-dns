//! 串接模式的協定編解碼（規格 `docs/spec/10-chain.md` 第 1.2、1.3、3.2、4.2 節）
//!
//! - 通道：一般 DNS 的 CH TXT 查詢，名稱在 `chain.kuroshio` 底下
//! - 回應內容是二進位（不是 base64），切成每段最多 255 bytes 的 TXT 字串
//! - 外層 `Sealed = { body, sig }`（CBOR），`sig = Ed25519("kuroshio-chain/1\0" || kind || 0x00 || body)`；
//!   前綴跟社群共享的 `kuroshio/2\0` 不同，兩邊的簽章不能互相冒用
//! - body 不認得的欄位一律忽略（結構不加 `deny_unknown_fields`）；`AuthBody` 預留的 `dot` 欄位 3.4.0 不定義，解碼時當成不認得的欄位略過
//!
//! 這個模組全部是純函式：不做網路或檔案 IO。

use crate::envelope::{from_cbor, to_cbor};
use crate::identity::{kid_of, verify, KeyPair};
use crate::util::{hex, unhex, valid_domain};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

/// 簽章輸入的前綴
pub const SIG_CONTEXT: &[u8] = b"kuroshio-chain/1\0";
/// 協定版本（body 的 `v`）
pub const PROTO: u8 = 1;
/// 串接訊息的區域
pub const ZONE: &str = "chain.kuroshio";
/// 下游登記（reg）的查詢名稱
pub const REG_NAME: &str = "r.chain.kuroshio";
/// 共用結果清單（manifest）的查詢名稱
pub const MANIFEST_NAME: &str = "m.s.chain.kuroshio";
/// 登記請求放在這個 EDNS 選項裡
pub const OPT_CODE: u16 = 65313;
/// 節點 ID 鏈的上限（`path.len() >= MAX_DEPTH` 就太深）
pub const MAX_DEPTH: usize = 4;
/// 共用結果每段的大小
pub const CHUNK: usize = 32 * 1024;
/// 支援串接的最低版本
pub const MIN_VERSION: (u32, u32, u32) = (3, 4, 0);
/// 登記憑據（`tok`）的時間窗
pub const TOKEN_WINDOW_MS: u64 = 300_000;
/// 登記最多帶幾個主機名稱
pub const MAX_REG_NAMES: usize = 32;
/// 分段編號最多幾位數（十進位）
const MAX_IDX_DIGITS: usize = 6;

const ZONE_SUFFIX: &str = ".chain.kuroshio";

// ---------------- 名稱 ----------------

/// 查詢名稱（已經 normalize：小寫、沒有結尾的點）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Name {
    /// `<nonce>.a.chain.kuroshio`
    Auth([u8; 16]),
    /// `r.chain.kuroshio`
    Reg,
    /// `m.s.chain.kuroshio`
    Manifest,
    /// `<idx>.<oid>.s.chain.kuroshio`
    Chunk { oid: [u8; 8], idx: u32 },
}

/// 名稱是不是在 `chain.kuroshio` 區域裡（等於 ZONE 或以 `.chain.kuroshio` 結尾）。
///
/// 不分大小寫、容忍一個結尾的點：區域裡的查詢不論格式對不對都要交給串接模組回 `REFUSED`，
/// 不能因為大小寫不同就被轉給上游。
pub fn in_zone(qname: &str) -> bool {
    let n = qname.strip_suffix('.').unwrap_or(qname);
    let len = n.len();
    if len == ZONE.len() {
        return n.eq_ignore_ascii_case(ZONE);
    }
    len > ZONE_SUFFIX.len() && n.as_bytes()[len - ZONE_SUFFIX.len()..].eq_ignore_ascii_case(ZONE_SUFFIX.as_bytes())
}

/// 固定長度的小寫十六進位字 → bytes
fn lower_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return None;
    }
    unhex(s)?.try_into().ok()
}

/// 分段編號：不含正負號、1～6 位的十進位，不可以有多餘的前導 0（同一段只有一種寫法）
fn parse_idx(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > MAX_IDX_DIGITS || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse().ok()
}

/// 解析區域裡的名稱；不在區域裡、或在區域裡但格式不對（含大寫、多或少標籤）→ `None`
pub fn parse_name(qname: &str) -> Option<Name> {
    let rest = qname.strip_suffix(ZONE_SUFFIX)?;
    let labels: Vec<&str> = rest.split('.').collect();
    match labels.as_slice() {
        ["r"] => Some(Name::Reg),
        ["m", "s"] => Some(Name::Manifest),
        [nonce, "a"] => lower_hex::<16>(nonce).map(Name::Auth),
        [idx, oid, "s"] => Some(Name::Chunk {
            oid: lower_hex::<8>(oid)?,
            idx: parse_idx(idx)?,
        }),
        _ => None,
    }
}

/// auth 挑戰的查詢名稱
pub fn auth_name(nonce: &[u8; 16]) -> String {
    format!("{}.a{ZONE_SUFFIX}", hex(nonce))
}

/// 共用結果分段的查詢名稱（`idx` 最大 999,999；8 MiB 的物件也只有 256 段）
pub fn chunk_name(oid: &[u8; 8], idx: u32) -> String {
    debug_assert!(idx <= 999_999, "分段編號超過 6 位數");
    format!("{idx}.{}.s{ZONE_SUFFIX}", hex(oid))
}

// ---------------- TXT ----------------

/// 原始 bytes → TXT 記錄的 RDATA（每段最多 255 bytes；空的內容是一個長度 0 的字串）
pub fn txt_rdata(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload.len() / 255 + 1);
    if payload.is_empty() {
        out.push(0);
        return out;
    }
    for seg in payload.chunks(255) {
        out.push(seg.len() as u8);
        out.extend_from_slice(seg);
    }
    out
}

/// TXT 記錄的 RDATA → 原始 bytes（所有字串接起來）；RDATA 是空的或被截斷 → `None`
pub fn txt_payload(rdata: &[u8]) -> Option<Vec<u8>> {
    if rdata.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(rdata.len());
    let mut i = 0;
    while i < rdata.len() {
        let n = rdata[i] as usize;
        out.extend_from_slice(rdata.get(i + 1..i + 1 + n)?);
        i += 1 + n;
    }
    Some(out)
}

// ---------------- 簽章外層 ----------------

/// 外層：`{ "body": bytes, "sig": bytes(64) }`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// 簽章輸入：`SIG_CONTEXT || kind || 0x00 || body`
pub fn signing_input(kind: &str, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIG_CONTEXT.len() + kind.len() + 1 + body.len());
    v.extend_from_slice(SIG_CONTEXT);
    v.extend_from_slice(kind.as_bytes());
    v.push(0);
    v.extend_from_slice(body);
    v
}

/// 簽章並編成 CBOR(Sealed)
pub fn seal(key: &KeyPair, kind: &str, body: Vec<u8>) -> Vec<u8> {
    let sig = key.sign(&signing_input(kind, &body)).to_vec();
    to_cbor(&Sealed { body, sig })
}

fn decode_sealed(bytes: &[u8]) -> Result<Sealed> {
    let s: Sealed = from_cbor(bytes)?;
    if s.sig.len() != 64 {
        bail!("簽章長度不對（{} bytes）", s.sig.len());
    }
    Ok(s)
}

/// 用指定公鑰驗簽，回 body
pub fn open(bytes: &[u8], kind: &str, public: &[u8]) -> Result<Vec<u8>> {
    let s = decode_sealed(bytes)?;
    if !verify(public, &signing_input(kind, &s.body), &s.sig) {
        bail!("{kind} 的簽章驗不過");
    }
    Ok(s.body)
}

/// 還沒驗簽的 body（公鑰在 body 裡的訊息用：先取出公鑰，再用 [`open`] 驗）
pub fn peek_body(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(decode_sealed(bytes)?.body)
}

// ---------------- 訊息 ----------------

/// `Vec<Vec<u8>>` 編成 CBOR 的 bytes 陣列（serde_bytes 不支援巢狀）
mod bytes_list {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_bytes::{ByteBuf, Bytes};

    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        v.iter().map(|b| Bytes::new(b)).collect::<Vec<_>>().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Ok(Vec::<ByteBuf>::deserialize(d)?.into_iter().map(ByteBuf::into_vec).collect())
    }
}

/// auth 回應（上游 → 下游，上游簽章，kind = `auth`）
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthBody {
    pub v: u8,
    pub t: String,
    /// 查詢名稱裡的 nonce 原樣帶回（16 bytes）
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// 上游的時間（Unix 毫秒），只供顯示與除錯
    #[serde(default)]
    pub ts: u64,
    /// 上游節點 ID（`kid_of(pub)`，8 bytes）
    #[serde(with = "serde_bytes")]
    pub kid: Vec<u8>,
    /// 上游 Ed25519 公鑰（32 bytes）
    #[serde(rename = "pub", with = "serde_bytes")]
    pub public: Vec<u8>,
    /// 上游版本
    #[serde(default)]
    pub app: String,
    /// 上游的 `allow_downstream`
    #[serde(default)]
    pub allow: bool,
    /// 能力：`share`、`reg`
    #[serde(default)]
    pub caps: Vec<String>,
    /// 上游看到的用戶端位址
    #[serde(default)]
    pub peer: String,
    /// 登記用的一次性憑據（16 bytes）
    #[serde(default, with = "serde_bytes")]
    pub tok: Vec<u8>,
    /// 節點 ID 鏈，從最上層到上游自己（每個 8 bytes）
    #[serde(default, with = "bytes_list")]
    pub path: Vec<Vec<u8>>,
}

/// 登記請求（下游 → 上游，下游簽章，kind = `reg`）
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegBody {
    pub v: u8,
    pub t: String,
    /// 上游的 kid（簽給別台的登記不能拿來這台用）
    #[serde(with = "serde_bytes")]
    pub up: Vec<u8>,
    /// 最近一次 auth 回應裡的 `tok`
    #[serde(with = "serde_bytes")]
    pub tok: Vec<u8>,
    /// 最近一次 auth 回應裡的 `peer`
    pub peer: String,
    /// 下游的節點 ID
    #[serde(with = "serde_bytes")]
    pub kid: Vec<u8>,
    /// 下游的公鑰
    #[serde(rename = "pub", with = "serde_bytes")]
    pub public: Vec<u8>,
    /// 下游版本
    #[serde(default)]
    pub app: String,
    /// 下游的上游主機名稱（最多 32 個）
    #[serde(default)]
    pub names: Vec<String>,
    /// `peer` 是不是下游自己某張網卡的位址（否 = 中間有 NAT）
    #[serde(default)]
    pub local: bool,
}

/// 登記回應（上游簽章，kind = `regack`）
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegAck {
    pub v: u8,
    pub t: String,
    /// 下游的 kid
    #[serde(with = "serde_bytes")]
    pub kid: Vec<u8>,
    /// 登記有效秒數
    pub ttl: u32,
}

/// 共用結果的清單（上游簽章，kind = `manifest`）
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestBody {
    pub v: u8,
    pub t: String,
    /// 上游節點 ID
    #[serde(with = "serde_bytes")]
    pub kid: Vec<u8>,
    /// 產生時間（Unix 毫秒，顯示用）
    #[serde(default)]
    pub at: u64,
    /// 上游版本
    #[serde(default)]
    pub app: String,
    #[serde(default)]
    pub objects: Vec<Object>,
}

/// 清單裡的一個物件
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Object {
    /// 種類：`upstreams`、`cdn-pools`、`cdn-v6`、`cdn-ranges`、`filter-copy`
    pub k: String,
    /// 這個種類的格式版本
    pub fmt: u8,
    /// `sha` 的前 8 bytes（查詢名稱裡的 `<oid>`）
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    /// 傳輸內容（壓縮後）的 SHA-256
    #[serde(with = "serde_bytes")]
    pub sha: Vec<u8>,
    /// 傳輸內容的大小
    pub size: u64,
    /// 解壓縮後的大小
    #[serde(default)]
    pub raw: u64,
    /// `zstd` 或 `none`
    #[serde(default)]
    pub enc: String,
    /// `filter-copy`：清單網址；其他種類是空字串
    #[serde(default)]
    pub name: String,
    /// 資料的時間
    #[serde(default)]
    pub at: u64,
    /// 只有 `filter-copy`：規則數
    #[serde(default)]
    pub rules: u64,
    /// 只有 `filter-copy`：原始內容的雜湊
    #[serde(default)]
    pub hash: String,
    /// 只有 `filter-copy`：上游下載時拿到的 ETag
    #[serde(default)]
    pub etag: String,
    /// 只有 `filter-copy`：上游下載時拿到的 Last-Modified
    #[serde(default, rename = "lastModified")]
    pub last_modified: String,
}

// ---------------- auth 與 reg 的檢查 ----------------

/// auth 回應驗不過的原因（規格 1.5 第 4 步）
#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    /// `Sealed` 或 body 解不開、欄位型別或長度不對
    Malformed,
    /// `v` 不是自己認得的版本
    Version(u8),
    /// `t` 不是 `"auth"`
    Kind,
    /// nonce 跟查詢的不同
    Nonce,
    /// `kid` 跟 `kid_of(pub)` 不符（含公鑰長度不對）
    Kid,
    /// 簽章驗不過
    Signature,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Malformed => write!(f, "auth 回應的格式不對"),
            AuthError::Version(v) => write!(f, "auth 回應的協定版本 {v} 不支援"),
            AuthError::Kind => write!(f, "auth 回應的種類不對"),
            AuthError::Nonce => write!(f, "auth 回應的 nonce 不符"),
            AuthError::Kid => write!(f, "auth 回應的節點 ID 跟公鑰不符"),
            AuthError::Signature => write!(f, "auth 回應的簽章驗不過"),
        }
    }
}

impl std::error::Error for AuthError {}

/// 只看版本與種類（先看這兩個，版本太新的 body 結構可能不同）
#[derive(Deserialize)]
struct Head {
    v: u8,
    #[serde(default)]
    t: String,
}

/// 下游：解開 auth 回應並做規格 1.5 第 4 步的全部檢查
///
/// 順序：`Sealed` 解得開 → `t == "auth"` → `v == 1` → nonce 相同 → `kid == kid_of(pub)` → 驗簽。
pub fn open_auth(bytes: &[u8], nonce: &[u8; 16]) -> Result<AuthBody, AuthError> {
    let s = decode_sealed(bytes).map_err(|_| AuthError::Malformed)?;
    let head: Head = from_cbor(&s.body).map_err(|_| AuthError::Malformed)?;
    if head.t != "auth" {
        return Err(AuthError::Kind);
    }
    if head.v != PROTO {
        return Err(AuthError::Version(head.v));
    }
    let body: AuthBody = from_cbor(&s.body).map_err(|_| AuthError::Malformed)?;
    if body.path.iter().any(|k| k.len() != 8) {
        return Err(AuthError::Malformed);
    }
    if body.nonce.as_slice() != nonce {
        return Err(AuthError::Nonce);
    }
    if body.public.len() != 32 || body.kid.as_slice() != kid_of(&body.public) {
        return Err(AuthError::Kid);
    }
    if !verify(&body.public, &signing_input("auth", &s.body), &s.sig) {
        return Err(AuthError::Signature);
    }
    Ok(body)
}

/// 上游：解開 reg（公鑰取自 body），檢查 `kid == kid_of(pub)`、簽章、names 合法、數量 ≤ 32。
///
/// `up` 是不是自己、`peer` 跟來源位址、`tok` 有沒有效由呼叫端檢查（規格 4.2 的第 2～4 項）。
pub fn open_reg(bytes: &[u8]) -> Result<RegBody> {
    let s = decode_sealed(bytes)?;
    let head: Head = from_cbor(&s.body)?;
    if head.t != "reg" {
        bail!("登記的種類不對");
    }
    if head.v != PROTO {
        bail!("登記的協定版本 {} 不支援", head.v);
    }
    let body: RegBody = from_cbor(&s.body)?;
    if body.public.len() != 32 || body.kid.as_slice() != kid_of(&body.public) {
        bail!("登記的節點 ID 跟公鑰不符");
    }
    if body.up.len() != 8 || body.tok.len() != 16 {
        bail!("登記的欄位長度不對");
    }
    if !verify(&body.public, &signing_input("reg", &s.body), &s.sig) {
        bail!("登記的簽章驗不過");
    }
    if body.names.len() > MAX_REG_NAMES {
        bail!("登記的主機名稱太多（{} 個，上限 {MAX_REG_NAMES}）", body.names.len());
    }
    if let Some(bad) = body.names.iter().find(|n| !valid_domain(n)) {
        return Err(anyhow!("登記的主機名稱不合法：{bad}"));
    }
    Ok(body)
}

// ---------------- 版本 ----------------

/// 取版本字串開頭的數字部分：`"3.4.0-rc1"` → `(3, 4, 0)`
pub fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let mut it = s.trim().splitn(3, '.');
    let major = it.next()?;
    let minor = it.next()?;
    let rest = it.next()?;
    let digits = |p: &str| -> Option<u32> {
        if p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        p.parse().ok()
    };
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    let (patch, tail) = rest.split_at(end);
    // 後面只接受 -rc1、+build 這類後綴，不接受 3.4.0.1、3.4.0x
    if !(tail.is_empty() || tail.starts_with('-') || tail.starts_with('+')) {
        return None;
    }
    Some((digits(major)?, digits(minor)?, digits(patch)?))
}

/// 版本 ≥ [`MIN_VERSION`]
pub fn version_ok(s: &str) -> bool {
    parse_version(s).is_some_and(|v| v >= MIN_VERSION)
}

// ---------------- 登記憑據 ----------------

/// `HMAC-SHA256(secret, "tok" || peer || 時間窗編號（u64 big-endian）)[..16]`
pub fn token(secret: &[u8; 32], peer: &str, window: u64) -> [u8; 16] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let mut c = ring::hmac::Context::with_key(&key);
    c.update(b"tok");
    c.update(peer.as_bytes());
    c.update(&window.to_be_bytes());
    let tag = c.sign();
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag.as_ref()[..16]);
    out
}

/// 不洩漏時間差的比較
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `tok` 對這個 `peer` 在目前或前一個時間窗有效
pub fn token_ok(secret: &[u8; 32], peer: &str, now_ms: u64, tok: &[u8]) -> bool {
    if tok.len() != 16 {
        return false;
    }
    let w = now_ms / TOKEN_WINDOW_MS;
    let cur = ct_eq(&token(secret, peer, w), tok);
    let prev = w > 0 && ct_eq(&token(secret, peer, w - 1), tok);
    cur | prev
}

// ---------------- 節點 ID 鏈 ----------------

/// 節點 ID 鏈不能用的原因
#[derive(Debug, PartialEq, Eq)]
pub enum PathError {
    /// 鏈裡有自己
    Loop,
    /// 鏈已經有 [`MAX_DEPTH`] 層
    TooDeep,
}

/// path：上游給的鏈；own：自己的 kid（含輪替中的舊 kid）
pub fn check_path(path: &[Vec<u8>], own: &[[u8; 8]]) -> Result<(), PathError> {
    if path.iter().any(|k| own.iter().any(|o| k.as_slice() == o)) {
        return Err(PathError::Loop);
    }
    if path.len() >= MAX_DEPTH {
        return Err(PathError::TooDeep);
    }
    Ok(())
}

/// 自己對外公告的鏈：上游的鏈（沒串接是空的）＋自己
pub fn own_path(upstream: Option<&[Vec<u8>]>, me: &[u8; 8]) -> Vec<Vec<u8>> {
    let mut p = upstream.map(<[Vec<u8>]>::to_vec).unwrap_or_default();
    p.push(me.to_vec());
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_suffix_matches_zone() {
        assert_eq!(ZONE_SUFFIX, format!(".{ZONE}"));
        assert!(in_zone(REG_NAME) && in_zone(MANIFEST_NAME));
        assert!(!in_zone("xchain.kuroshio"));
    }
}
