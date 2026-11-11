//! 身分與金鑰（規格 03 第 4 節）
//!
//! - Ed25519，私鑰存成 PKCS#8 PEM（跟 2.x 的 `community/key.pem` 同一種格式，升級後身分不變）
//! - kid = SHA-256(公鑰 32 bytes)[0..8]
//! - 指紋沿用 v1：SHA-256(SPKI DER) 前 16 bytes，每 4 個十六進位字一組（給人眼核對）
//! - 金鑰輪替：新金鑰由舊金鑰簽一份 `rotate` 聲明；7 天內身分文件同時列出兩把

use crate::util::{b64, hex, now_ms, random_bytes, sha256, unb64, DAY};
use anyhow::{anyhow, bail, Context, Result};
use ring::signature::{Ed25519KeyPair, KeyPair as _, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// PKCS#8 v1（RFC 8410）Ed25519 私鑰的固定前綴，後面接 32 bytes 種子；node 的 `export({type:'pkcs8'})` 就是這個格式
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// SPKI DER 前綴（v1 的公鑰格式，指紋也用這個算）
const SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// 輪替後舊金鑰還列在身分文件裡的時間
pub const ROTATE_OVERLAP_MS: u64 = 7 * DAY;

pub type Kid = [u8; 8];

pub fn kid_of(public: &[u8]) -> Kid {
    let d = sha256(&[public]);
    let mut k = [0u8; 8];
    k.copy_from_slice(&d[..8]);
    k
}

/// v1 的公鑰指紋（例如 3F2A-91C0-…，8 組）
pub fn fingerprint(public: &[u8]) -> String {
    let mut der = SPKI_PREFIX.to_vec();
    der.extend_from_slice(public);
    let h = hex(&sha256(&[&der])[..16]).to_ascii_uppercase();
    h.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// v1 的公鑰（base64 SPKI DER）→ 32 bytes 原始公鑰
pub fn public_from_v1(spki_b64: &str) -> Option<[u8; 32]> {
    let der = unb64(spki_b64)?;
    if der.len() != 44 || der[..12] != SPKI_PREFIX {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&der[12..]);
    Some(out)
}

pub fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    UnparsedPublicKey::new(&ED25519, public).verify(msg, sig).is_ok()
}

pub struct KeyPair {
    kp: Ed25519KeyPair,
    seed: [u8; 32],
    pub public: [u8; 32],
    pub kid: Kid,
}

impl KeyPair {
    pub fn from_seed(seed: &[u8; 32]) -> KeyPair {
        let kp = Ed25519KeyPair::from_seed_unchecked(seed).expect("Ed25519 種子");
        let mut public = [0u8; 32];
        public.copy_from_slice(kp.public_key().as_ref());
        KeyPair {
            kp,
            seed: *seed,
            public,
            kid: kid_of(&public),
        }
    }

    pub fn generate() -> KeyPair {
        KeyPair::from_seed(&random_bytes::<32>())
    }

    /// 讀 PKCS#8 PEM（v1 node 產生的，或本程式寫的）
    pub fn from_pem(pem: &str) -> Result<KeyPair> {
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).map(str::trim).collect();
        let der = unb64(&body).ok_or_else(|| anyhow!("金鑰檔不是有效的 PEM"))?;
        if der.len() == 48 && der[..16] == PKCS8_PREFIX {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&der[16..]);
            return Ok(KeyPair::from_seed(&seed));
        }
        // 其他工具產生的 PKCS#8 v2（含公鑰）：交給 ring 解析，再從 DER 裡取種子
        Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der).map_err(|_| anyhow!("金鑰檔不是 Ed25519 PKCS#8"))?;
        let pos = der
            .windows(4)
            .position(|w| w == [0x04, 0x22, 0x04, 0x20])
            .ok_or_else(|| anyhow!("讀不到 Ed25519 種子"))?;
        let seed: [u8; 32] = der
            .get(pos + 4..pos + 36)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| anyhow!("讀不到 Ed25519 種子"))?;
        Ok(KeyPair::from_seed(&seed))
    }

    pub fn to_pem(&self) -> String {
        let mut der = PKCS8_PREFIX.to_vec();
        der.extend_from_slice(&self.seed);
        let b = b64(&der);
        format!("-----BEGIN PRIVATE KEY-----\n{b}\n-----END PRIVATE KEY-----\n")
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out.copy_from_slice(self.kp.sign(msg).as_ref());
        out
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public)
    }
}

/// 公開金鑰資訊（身分文件的 keys）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyInfo {
    #[serde(with = "serde_bytes")]
    pub kid: Vec<u8>,
    #[serde(rename = "pub", with = "serde_bytes")]
    pub public: Vec<u8>,
    pub since: u64,
}

/// 簽過名的聲明（輪替聲明放進身分文件，讓錯過通知的好友也能驗證）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedStmt {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// 輪替紀錄（存在金鑰目錄的 rotation.json）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rotation {
    pub old_kid: String,
    pub old_pub: String,
    pub old_since: u64,
    pub at: u64,
    /// rotate 聲明的 body（base64）與舊金鑰的簽名（base64）
    pub body: String,
    pub sig: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityMeta {
    /// 身分建立時間（輪替不會重設，對方用來算「運作天數」）
    since: u64,
    /// 目前金鑰開始使用的時間
    key_since: u64,
    #[serde(default)]
    rotation: Option<Rotation>,
}

/// 我的身分：目前金鑰 + 輪替狀態；檔案放在金鑰目錄（OpenWrt：/etc/kuroshio/community）
pub struct Identity {
    dir: Option<PathBuf>,
    pub key: KeyPair,
    pub since: u64,
    pub key_since: u64,
    pub rotation: Option<Rotation>,
}

/// 寫私鑰與身分資料：暫存檔一建立就是 0600（先寫再 chmod 會有別人讀得到的空檔），不跟著別人放的符號連結走
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(&tmp).with_context(|| format!("寫入 {}", tmp.display()))?;
    f.write_all(data).with_context(|| format!("寫入 {}", tmp.display()))?;
    let _ = f.sync_all();
    drop(f);
    std::fs::rename(&tmp, path).with_context(|| format!("改名 {}", path.display()))?;
    Ok(())
}

impl Identity {
    /// 讀取（沒有就建立）`dir/key.pem`；金鑰屬於設定類資料，只在第一次建立與輪替時寫入
    pub fn load_or_create(dir: &Path) -> Result<Identity> {
        std::fs::create_dir_all(dir).with_context(|| format!("建立 {}", dir.display()))?;
        let key_file = dir.join("key.pem");
        // 舊版寫的金鑰可能是 0644：收緊成只有擁有者能讀
        #[cfg(unix)]
        for n in ["key.pem", "key.old.pem"] {
            use std::os::unix::fs::PermissionsExt;
            let f = dir.join(n);
            if std::fs::metadata(&f).is_ok_and(|m| m.permissions().mode() & 0o077 != 0) {
                let _ = std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600));
            }
        }
        let meta_file = dir.join("identity.json");
        let key = if key_file.exists() {
            KeyPair::from_pem(&std::fs::read_to_string(&key_file)?).with_context(|| format!("讀取 {}", key_file.display()))?
        } else {
            let k = KeyPair::generate();
            write_atomic(&key_file, k.to_pem().as_bytes())?;
            k
        };
        let mtime = std::fs::metadata(&key_file)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or_else(now_ms);
        let meta: IdentityMeta = std::fs::read(&meta_file)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(IdentityMeta {
                since: mtime,
                key_since: mtime,
                rotation: None,
            });
        Ok(Identity {
            dir: Some(dir.to_path_buf()),
            key,
            since: meta.since,
            key_since: meta.key_since,
            rotation: meta.rotation,
        })
    }

    /// 只在記憶體（測試向量用）
    pub fn ephemeral(key: KeyPair, since: u64) -> Identity {
        Identity {
            dir: None,
            key,
            since,
            key_since: since,
            rotation: None,
        }
    }

    fn save_meta(&self) -> Result<()> {
        if let Some(dir) = &self.dir {
            let meta = IdentityMeta {
                since: self.since,
                key_since: self.key_since,
                rotation: self.rotation.clone(),
            };
            write_atomic(&dir.join("identity.json"), &serde_json::to_vec_pretty(&meta)?)?;
        }
        Ok(())
    }

    /// 目前有效的金鑰（輪替 7 天內包含舊的）
    pub fn keys(&self, now: u64) -> Vec<KeyInfo> {
        let mut v = vec![KeyInfo {
            kid: self.key.kid.to_vec(),
            public: self.key.public.to_vec(),
            since: self.key_since,
        }];
        if let Some(r) = self.rotation.as_ref().filter(|r| now < r.at + ROTATE_OVERLAP_MS) {
            if let (Some(kid), Some(public)) = (crate::util::unhex(&r.old_kid), unb64(&r.old_pub)) {
                v.push(KeyInfo {
                    kid,
                    public,
                    since: r.old_since,
                });
            }
        }
        v
    }

    /// 輪替期間的聲明（放進身分文件）
    pub fn rotation_stmts(&self, now: u64) -> Vec<SignedStmt> {
        self.rotation
            .as_ref()
            .filter(|r| now < r.at + ROTATE_OVERLAP_MS)
            .and_then(|r| {
                Some(SignedStmt {
                    body: unb64(&r.body)?,
                    sig: unb64(&r.sig)?,
                })
            })
            .into_iter()
            .collect()
    }

    /// 換新金鑰：`make_body(old, new)` 產生 rotate 聲明的 body（由呼叫者編碼），用舊金鑰簽名後存檔
    pub fn rotate(&mut self, now: u64, make_body: impl FnOnce(&KeyPair, &KeyPair, u64) -> Vec<u8>) -> Result<SignedStmt> {
        let new = KeyPair::generate();
        let body = make_body(&self.key, &new, now);
        let sig = self.key.sign(&crate::envelope::signing_input("rotate", &body));
        if let Some(dir) = &self.dir {
            // 先留一份舊金鑰（萬一寫到一半斷電，還找得回來）
            write_atomic(&dir.join("key.old.pem"), self.key.to_pem().as_bytes())?;
            write_atomic(&dir.join("key.pem"), new.to_pem().as_bytes())?;
        }
        let old = std::mem::replace(&mut self.key, new);
        self.rotation = Some(Rotation {
            old_kid: hex(&old.kid),
            old_pub: b64(&old.public),
            old_since: self.key_since,
            at: now,
            body: b64(&body),
            sig: b64(&sig),
        });
        self.key_since = now;
        self.save_meta()?;
        Ok(SignedStmt { body, sig: sig.to_vec() })
    }

    /// DNS TXT 記錄建議值：`_kuroshio.<網域>` = `v=cd2; k=<kid hex>`
    pub fn txt_value(&self) -> String {
        format!("v=cd2; k={}", hex(&self.key.kid))
    }
}

/// 解析 `_kuroshio` TXT：回傳宣告的 kid（只認 v=cd2）
pub fn parse_txt(s: &str) -> Option<Kid> {
    let mut v = None;
    let mut k = None;
    for part in s.split(';') {
        let (a, b) = part.trim().split_once('=')?;
        match a.trim() {
            "v" => v = Some(b.trim().to_string()),
            "k" => k = crate::util::unhex(b.trim()),
            _ => {}
        }
    }
    if v.as_deref() != Some("cd2") {
        return None;
    }
    k.and_then(|k| k.try_into().ok())
}

/// 檢查 bytes 長度轉成固定陣列
pub fn as_kid(b: &[u8]) -> Result<Kid> {
    b.try_into().map_err(|_| anyhow!("kid 長度錯誤"))
}

pub fn ensure_len(b: &[u8], n: usize, what: &str) -> Result<()> {
    if b.len() != n {
        bail!("{what} 長度錯誤");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_roundtrip_and_kid() {
        let k = KeyPair::from_seed(&[7u8; 32]);
        let k2 = KeyPair::from_pem(&k.to_pem()).unwrap();
        assert_eq!(k.public, k2.public);
        assert_eq!(k.kid, kid_of(&k.public));
        let sig = k.sign(b"hello");
        assert!(verify(&k.public, b"hello", &sig));
        assert!(!verify(&k.public, b"hellO", &sig));
    }

    #[cfg(unix)]
    #[test]
    fn key_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kuroshio-ident-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mode = |n: &str| std::fs::metadata(dir.join(n)).unwrap().permissions().mode() & 0o777;
        Identity::load_or_create(&dir).unwrap();
        assert_eq!(mode("key.pem"), 0o600);
        // 舊版留下的 0644 金鑰：下次啟動收緊
        std::fs::set_permissions(dir.join("key.pem"), std::fs::Permissions::from_mode(0o644)).unwrap();
        Identity::load_or_create(&dir).unwrap();
        assert_eq!(mode("key.pem"), 0o600);
        // 暫存檔的位置先被放了符號連結：不跟著寫出去
        let victim = dir.join("victim");
        std::fs::write(&victim, "v").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join("x.tmp")).unwrap();
        write_atomic(&dir.join("x.pem"), b"secret").unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "v");
        assert_eq!(mode("x.pem"), 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn txt() {
        assert_eq!(parse_txt("v=cd2; k=0102030405060708"), Some([1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(parse_txt("v=cd1; k=0102030405060708"), None);
        assert_eq!(parse_txt("garbage"), None);
    }
}
