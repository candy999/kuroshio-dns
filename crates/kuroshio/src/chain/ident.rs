//! 串接用的節點金鑰（規格 1.9：跟社群共享同一把，社群共享沒啟用也要能載入）
//!
//! - 第一次需要時才 `Identity::load_or_create`（不在啟動時建立金鑰）
//! - 之後最多每 60 秒看一次 `key.pem` 的修改時間，變了才重讀（社群共享做了金鑰輪替）；不會每個查詢都讀檔

use anyhow::Result;
use kuroshio_community::identity::{Identity, KeyPair, Kid, ROTATE_OVERLAP_MS};
use kuroshio_community::util::{now_ms, unhex};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// 最多隔多久看一次 `key.pem` 的修改時間
const RECHECK: Duration = Duration::from_secs(60);

/// 已經載入的金鑰
struct Loaded {
    key: Arc<KeyPair>,
    /// 載入時 `key.pem` 的修改時間（讀不到是 None）
    mtime: Option<SystemTime>,
    /// 上次看修改時間的時間
    checked: Instant,
    /// 輪替中的舊 kid 與輪替時間（Unix 毫秒）
    old: Option<(Kid, u64)>,
}

/// 節點金鑰（跟社群共享共用同一把）
pub struct NodeKey {
    dir: PathBuf,
    state: Mutex<Option<Loaded>>,
}

fn mtime_of(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

impl NodeKey {
    /// 只記住目錄，不讀檔
    pub fn new(key_dir: PathBuf) -> NodeKey {
        NodeKey {
            dir: key_dir,
            state: Mutex::new(None),
        }
    }

    /// 金鑰目錄
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn load(&self) -> Result<Loaded> {
        let id = Identity::load_or_create(&self.dir)?;
        let old = id.rotation.as_ref().and_then(|r| {
            let kid: Kid = unhex(&r.old_kid)?.try_into().ok()?;
            Some((kid, r.at))
        });
        Ok(Loaded {
            key: Arc::new(id.key),
            mtime: mtime_of(&self.dir.join("key.pem")),
            checked: Instant::now(),
            old,
        })
    }

    /// 目前的金鑰：第一次呼叫才讀（沒有就建立）；之後 `key.pem` 的修改時間變了才重讀
    pub fn get(&self) -> Result<Arc<KeyPair>> {
        let mut st = self.state.lock().unwrap();
        if let Some(l) = st.as_mut() {
            if l.checked.elapsed() < RECHECK {
                return Ok(l.key.clone());
            }
            l.checked = Instant::now();
            let now = mtime_of(&self.dir.join("key.pem"));
            if now.is_some() && now == l.mtime {
                return Ok(l.key.clone());
            }
            // 修改時間變了（或檔案不見了）：重讀；讀不到就先沿用記憶體裡的那把
            match self.load() {
                Ok(n) => {
                    if n.key.public != l.key.public {
                        tracing::info!("串接：節點金鑰換過了（{}），改用新的金鑰", n.key.fingerprint());
                    }
                    *l = n;
                }
                Err(e) => tracing::warn!("串接：重新讀取節點金鑰失敗，先沿用原本的金鑰：{e:#}"),
            }
            return Ok(l.key.clone());
        }
        let n = self.load()?;
        let k = n.key.clone();
        *st = Some(n);
        Ok(k)
    }

    /// 已經載入、或金鑰檔已經存在時的金鑰（不會建立新的金鑰檔）
    fn peek(&self) -> Option<Arc<KeyPair>> {
        let loaded = self.state.lock().unwrap().as_ref().map(|l| l.key.clone());
        match loaded {
            Some(k) => Some(k),
            None if self.dir.join("key.pem").is_file() => self.get().ok(),
            None => None,
        }
    }

    /// 自己的 kid：目前的 ＋ 輪替 7 天內的舊 kid（防迴圈用）；還沒有金鑰是空的
    pub fn own_kids(&self) -> Vec<[u8; 8]> {
        let Some(k) = self.peek() else { return Vec::new() };
        let mut v = vec![k.kid];
        let st = self.state.lock().unwrap();
        if let Some((kid, at)) = st.as_ref().and_then(|l| l.old) {
            if now_ms() < at.saturating_add(ROTATE_OVERLAP_MS) && kid != k.kid {
                v.push(kid);
            }
        }
        v
    }

    /// 節點指紋（顯示用）；還沒有金鑰（也沒有金鑰檔）是 None
    pub fn fingerprint(&self) -> Option<String> {
        self.peek().map(|k| k.fingerprint())
    }

    /// 節點 ID（十六進位）；還沒有金鑰是 None
    pub fn node_id(&self) -> Option<String> {
        self.peek().map(|k| kuroshio_community::util::hex(&k.kid))
    }
}

/// 金鑰目錄：`community.dir`（相對路徑以設定目錄為基準），沒寫是設定目錄下的 `community`
pub fn key_dir(cfg: &Value, base_dir: &Path) -> PathBuf {
    kuroshio_config::get(cfg, "community.dir")
        .and_then(Value::as_str)
        .filter(|d| !d.is_empty())
        .map(|d| {
            let p = Path::new(d);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                base_dir.join(p.strip_prefix("./").unwrap_or(p))
            }
        })
        .unwrap_or_else(|| base_dir.join("community"))
}
