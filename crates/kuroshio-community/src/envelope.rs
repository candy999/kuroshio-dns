//! 編碼與簽名（規格 03 第 3 節）
//!
//! 信封 = CBOR map `{v:2, kid, body, sig}`（sync 回應多一個 `enc:"zstd"`）；
//! 簽名對象是**原始 body 位元組**：`Ed25519("kuroshio/2\0" || 動作 || "\0" || body)`，驗過才解碼。
//!
//! TLS / QUIC 管道沒有網址路徑，請求的信封多帶一個 `a`（動作名稱）；身分文件請求是 `{v:2, a:"identity"}`。
//! 錯誤回應（三種管道一樣）是 `{v:2, err:狀態碼, error:代碼, ...}`，HTTPS 另外用同一個 HTTP 狀態碼。

use crate::identity::{KeyInfo, KeyPair, SignedStmt};
use crate::util::sha256;
use anyhow::{anyhow, bail, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::Read;

pub const PROTO: u8 = 2;
pub const ALPN: &[u8] = b"kuroshio/2";
/// HTTPS 路徑前綴：`POST /.well-known/kuroshio/v2/<動作>`
pub const BASE_PATH: &str = "/.well-known/kuroshio/v2";
/// 請求上限
pub const MAX_REQUEST: usize = 64 * 1024;
/// 回應上限：線上（壓縮後）8 MB
pub const MAX_RESPONSE_WIRE: usize = 8 * 1024 * 1024;
/// 回應上限：解壓後 32 MB（另外受等級的 community.maxBundleMB 限制）
pub const MAX_RESPONSE_PLAIN: usize = 32 * 1024 * 1024;
pub const SIG_CONTEXT: &[u8] = b"kuroshio/2\0";
pub const POW_CONTEXT: &[u8] = b"kuroshio/2-pow\0";

pub const ACTIONS: [&str; 6] = ["identity", "request", "relation", "sync", "poke", "rotate"];

pub fn signing_input(action: &str, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIG_CONTEXT.len() + action.len() + 1 + body.len());
    v.extend_from_slice(SIG_CONTEXT);
    v.extend_from_slice(action.as_bytes());
    v.push(0);
    v.extend_from_slice(body);
    v
}

pub fn to_cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("CBOR 編碼");
    out
}

pub fn from_cbor<T: DeserializeOwned>(b: &[u8]) -> Result<T> {
    ciborium::from_reader(b).map_err(|e| anyhow!("CBOR 格式錯誤：{e}"))
}

// ---------------- 信封 ----------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<serde_bytes::ByteBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_bytes::ByteBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<serde_bytes::ByteBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc: Option<String>,
    /// 動作名稱（只有 TLS / QUIC 管道的請求帶）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a: Option<String>,
    /// 錯誤回應
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub err: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, rename = "powBits", skip_serializing_if = "Option::is_none")]
    pub pow_bits: Option<u8>,
}

impl Envelope {
    pub fn encode(&self) -> Vec<u8> {
        to_cbor(self)
    }

    pub fn decode(b: &[u8]) -> Result<Envelope> {
        let e: Envelope = from_cbor(b)?;
        if e.v != PROTO {
            bail!("協定版本 {} 不支援", e.v);
        }
        Ok(e)
    }

    pub fn kid(&self) -> Option<[u8; 8]> {
        self.kid.as_ref().and_then(|k| k.as_slice().try_into().ok())
    }

    pub fn body(&self) -> &[u8] {
        self.body.as_deref().map(|b| b.as_slice()).unwrap_or(&[])
    }

    /// 用指定公鑰驗證（簽名對象是信封裡的 body 原始位元組，壓縮過的就是壓縮後的位元組）
    pub fn verify_with(&self, action: &str, public: &[u8]) -> bool {
        let (Some(body), Some(sig)) = (&self.body, &self.sig) else {
            return false;
        };
        sig.len() == 64 && crate::identity::verify(public, &signing_input(action, body), sig)
    }

    /// 驗過簽名之後取出明文 body（zstd 解壓有上限，邊解邊數）
    pub fn plain_body(&self, max_plain: usize) -> Result<Vec<u8>> {
        match self.enc.as_deref() {
            None => Ok(self.body().to_vec()),
            Some("zstd") => decompress(self.body(), max_plain),
            Some(other) => bail!("不支援的壓縮 {other}"),
        }
    }
}

/// 產生簽好名的信封
pub fn seal(key: &KeyPair, action: &str, body: Vec<u8>, enc: Option<&str>) -> Envelope {
    let sig = key.sign(&signing_input(action, &body));
    Envelope {
        v: PROTO,
        kid: Some(serde_bytes::ByteBuf::from(key.kid.to_vec())),
        body: Some(serde_bytes::ByteBuf::from(body)),
        sig: Some(serde_bytes::ByteBuf::from(sig.to_vec())),
        enc: enc.map(str::to_string),
        ..Default::default()
    }
}

/// 錯誤回應
pub fn error_reply(status: u16, code: &str) -> Vec<u8> {
    Envelope {
        v: PROTO,
        err: Some(status),
        error: Some(code.to_string()),
        ..Default::default()
    }
    .encode()
}

pub fn pow_reply(bits: u8) -> Vec<u8> {
    Envelope {
        v: PROTO,
        err: Some(400),
        error: Some("pow".into()),
        pow_bits: Some(bits),
        ..Default::default()
    }
    .encode()
}

// ---------------- 壓縮 ----------------

pub fn compress(b: &[u8]) -> Vec<u8> {
    zstd::bulk::compress(b, 3).expect("zstd 壓縮")
}

/// 解壓 zstd，超過 `max` 就中止（防壓縮炸彈：邊解邊數，不會先配置整塊記憶體）
pub fn decompress(b: &[u8], max: usize) -> Result<Vec<u8>> {
    let dec = zstd::stream::read::Decoder::new(b).map_err(|e| anyhow!("zstd：{e}"))?;
    let mut out = Vec::new();
    let mut lim = dec.take(max as u64 + 1);
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = lim.read(&mut buf).map_err(|e| anyhow!("zstd 解壓失敗：{e}"))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        if out.len() > max {
            bail!("解壓後超過 {} MB", max / (1024 * 1024));
        }
    }
    Ok(out)
}

// ---------------- 工作量證明 ----------------

pub fn leading_zero_bits(b: &[u8]) -> u32 {
    let mut n = 0;
    for x in b {
        if *x == 0 {
            n += 8;
            continue;
        }
        return n + x.leading_zeros();
    }
    n
}

pub fn pow_ok(body: &[u8], bits: u8) -> bool {
    leading_zero_bits(&sha256(&[POW_CONTEXT, body])) >= bits as u32
}

/// 好友請求的 body 最後一個欄位是 `pow: bstr(8)`，編碼後就是 body 最後 8 bytes：直接改那 8 bytes 找答案
pub fn solve_pow(mut body: Vec<u8>, bits: u8) -> Vec<u8> {
    let n = body.len();
    assert!(n >= 9 && body[n - 9] == 0x48, "pow 必須是 body 最後一個欄位");
    let mut i: u64 = 0;
    loop {
        body[n - 8..].copy_from_slice(&i.to_be_bytes());
        if pow_ok(&body, bits) {
            return body;
        }
        i += 1;
    }
}

// ---------------- 訊息本體 ----------------

/// 每則訊息都有的欄位（先解這些來檢查收件者、時間、重放）
#[derive(Debug, Clone, Deserialize)]
pub struct Head {
    pub t: String,
    pub from: String,
    #[serde(default)]
    pub to: Option<String>,
    pub ts: u64,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default)]
    pub colo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityBody {
    pub t: String,
    pub from: String,
    pub ts: u64,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    pub keys: Vec<KeyInfo>,
    pub endpoints: Vec<String>,
    pub proto: Vec<u8>,
    pub caps: Vec<String>,
    pub since: u64,
    pub net: NetInfo,
    #[serde(default)]
    pub friends: Vec<serde_bytes::ByteBuf>,
    /// 輪替聲明（擴充：舊金鑰簽的 rotate body，錯過通知的好友讀身分文件時也能驗證）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rot: Vec<SignedStmt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestBody {
    pub t: String,
    pub from: String,
    pub to: String,
    pub ts: u64,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// 簽這個請求的金鑰（對方回連身分文件後用這把驗證）
    #[serde(with = "serde_bytes")]
    pub kid: Vec<u8>,
    pub endpoints: Vec<String>,
    pub req_id: String,
    /// 邀請碼證明（擴充欄位，舊版不認得會略過）：HMAC-SHA256(邀請密鑰, …)，見 [`crate::invite::proof`]。
    /// 密鑰本身不上線
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite: Option<serde_bytes::ByteBuf>,
    /// 一定要是最後一個欄位（solve_pow 直接改 body 的最後 8 bytes）
    #[serde(with = "serde_bytes")]
    pub pow: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationBody {
    pub t: String,
    pub from: String,
    pub to: String,
    pub ts: u64,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_id: Option<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub req_id: Option<String>,
    /// rejected 的期限（Unix 毫秒）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncRequest {
    pub t: String,
    pub from: String,
    pub to: String,
    pub ts: u64,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<serde_bytes::ByteBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
}

/// 分享記錄（四種 kind 共用一個結構，沒用到的欄位不編碼）
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WireRecord {
    pub kind: String,
    pub key: String,
    pub seq: u64,
    pub obs: u64,
    pub exp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fam: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pop: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h: Option<serde_bytes::ByteBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ips: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<f32>,
}

/// 收到的記錄：單筆格式錯誤不讓整包失敗，只記為 invalid（一次只展開一筆，不會把整包變成大樹）
#[derive(Debug, Clone, Default)]
pub struct Lenient(pub Option<WireRecord>);

impl Serialize for Lenient {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for Lenient {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let v = ciborium::Value::deserialize(d)?;
        Ok(Lenient(v.deserialized::<WireRecord>().ok()))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub t: String,
    pub from: String,
    pub to: String,
    pub ts: u64,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<serde_bytes::ByteBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctx: Option<NetInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upserts: Vec<Lenient>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deletes: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PokeBody {
    pub t: String,
    pub from: String,
    pub to: String,
    pub ts: u64,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_id: Option<String>,
    pub what: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateBody {
    pub t: String,
    pub from: String,
    pub ts: u64,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub old: Vec<u8>,
    pub new: KeyInfo,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pow_patch_last_bytes() {
        let body = RequestBody {
            t: "request".into(),
            from: "a.test".into(),
            to: "b.test".into(),
            ts: 1,
            nonce: vec![0; 12],
            kid: vec![1; 8],
            endpoints: vec![],
            req_id: "r".into(),
            invite: None,
            pow: vec![0; 8],
        };
        let b = solve_pow(to_cbor(&body), 10);
        assert!(pow_ok(&b, 10));
        let back: RequestBody = from_cbor(&b).unwrap();
        assert_eq!(back.req_id, "r");
        assert_eq!(back.pow.len(), 8);
    }

    #[test]
    fn bomb_is_stopped() {
        let zeros = vec![0u8; 3 * 1024 * 1024];
        let c = compress(&zeros);
        assert!(c.len() < 4096);
        assert!(decompress(&c, 1024 * 1024).is_err());
        assert_eq!(decompress(&c, 4 * 1024 * 1024).unwrap().len(), zeros.len());
        assert!(decompress(b"not zstd", 100).is_err());
    }

    #[test]
    fn lenient_records() {
        #[derive(Serialize)]
        struct Raw {
            upserts: Vec<ciborium::Value>,
        }
        let good = ciborium::Value::serialized(&WireRecord {
            kind: "node".into(),
            key: "p/1.1.1.1".into(),
            ..Default::default()
        })
        .unwrap();
        let bad = ciborium::Value::Text("garbage".into());
        #[derive(Deserialize)]
        struct Back {
            upserts: Vec<Lenient>,
        }
        let b: Back = from_cbor(&to_cbor(&Raw { upserts: vec![good, bad] })).unwrap();
        assert!(b.upserts[0].0.is_some());
        assert!(b.upserts[1].0.is_none());
    }
}
