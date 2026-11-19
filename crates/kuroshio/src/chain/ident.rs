//! 串接用的節點金鑰（規格 1.9：跟社群共享同一把，社群共享沒啟用也要能載入）
//!
//! WP4 的最小可用版本：下游狀態機只需要「自己的 kid」（防迴圈）。完整版（上游回應器要用的
//! 簽章金鑰、`key.pem` 修改時間的重讀）由 WP3 提供，合併時以 WP3 的為準，公開的函式簽章相同。

use anyhow::Result;
use kuroshio_community::identity::{Identity, KeyPair};
use kuroshio_config::get;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// `key.pem` 的修改時間最多多久看一次
const RECHECK: Duration = Duration::from_secs(60);

struct Loaded {
    key: Arc<KeyPair>,
    /// 目前的 + 輪替 7 天內的舊 kid
    kids: Vec<[u8; 8]>,
    mtime: Option<SystemTime>,
    checked: Instant,
}

/// 節點金鑰（跟社群共享同一把）
pub struct NodeKey {
    dir: PathBuf,
    cur: Mutex<Option<Loaded>>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl NodeKey {
    /// 不讀檔
    pub fn new(key_dir: PathBuf) -> NodeKey {
        NodeKey {
            dir: key_dir,
            cur: Mutex::new(None),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn mtime(&self) -> Option<SystemTime> {
        std::fs::metadata(self.dir.join("key.pem")).and_then(|m| m.modified()).ok()
    }

    /// 已經載入過、修改時間沒變（最多每 60 秒看一次）就不重讀
    fn fresh(&self, cur: &mut Option<Loaded>) -> bool {
        let Some(l) = cur.as_mut() else { return false };
        if l.checked.elapsed() < RECHECK {
            return true;
        }
        l.checked = Instant::now();
        l.mtime == self.mtime()
    }

    fn load(&self, cur: &mut Option<Loaded>) -> Result<()> {
        let id = Identity::load_or_create(&self.dir)?;
        let kids = id.keys(now_ms()).iter().filter_map(|k| k.kid.as_slice().try_into().ok()).collect();
        *cur = Some(Loaded {
            key: Arc::new(id.key),
            kids,
            mtime: self.mtime(),
            checked: Instant::now(),
        });
        Ok(())
    }

    /// 第一次呼叫才 `Identity::load_or_create`（沒有就建立）；`key.pem` 的修改時間變了就重讀
    pub fn get(&self) -> Result<Arc<KeyPair>> {
        let mut cur = self.cur.lock().unwrap();
        if !self.fresh(&mut cur) {
            self.load(&mut cur)?;
        }
        Ok(cur.as_ref().expect("剛載入").key.clone())
    }

    /// 目前的 + 輪替 7 天內的舊 kid。金鑰還不存在時回空的，**不建立金鑰**（下游探測不需要自己的金鑰）
    pub fn own_kids(&self) -> Vec<[u8; 8]> {
        let mut cur = self.cur.lock().unwrap();
        if !self.fresh(&mut cur) && self.dir.join("key.pem").exists() && self.load(&mut cur).is_err() {
            return Vec::new();
        }
        cur.as_ref().map(|l| l.kids.clone()).unwrap_or_default()
    }

    /// 已經載入的金鑰的指紋（不建立金鑰）
    pub fn fingerprint(&self) -> Option<String> {
        self.cur.lock().unwrap().as_ref().map(|l| l.key.fingerprint())
    }
}

/// 金鑰目錄：跟 `app.rs::start_community` 算的同一個（`community.dir`，相對路徑以設定目錄為基準）
pub fn key_dir(cfg: &Value, base_dir: &Path) -> PathBuf {
    match get(cfg, "community.dir").and_then(Value::as_str).filter(|d| !d.is_empty()) {
        Some(d) => {
            let p = Path::new(d);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                base_dir.join(p.strip_prefix("./").unwrap_or(p))
            }
        }
        None => base_dir.join("community"),
    }
}
