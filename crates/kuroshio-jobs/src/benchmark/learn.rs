//! 評測學習資料（3.5.0，規格 11 第 0.3 節）：跨天的評測紀錄共用一個檔 `state/benchmark-learn.json`
//! （寫成 zstd 壓縮的 `.zst`；讀的時候兩種都接受）。
//!
//! ```json
//! { "v": 1, "day": 20781,
//!   "neverOk": { "<id>": { "since": 20780, "n": 2 } } }
//! ```
//!
//! - 丟了只是重新學，不影響正確性（`space.rs` 歸 `Rebuildable`）；不進備份的分享檔、不傳給下游與好友。
//! - 讀不到、格式不對、`v` 不認識、太大：當成空的，不失敗。
//! - 這一版只用到 `neverOk`（A7）；其他區段（之後的 `control`、`hist`、`h3skip`）原樣保留，不會被這裡蓋掉。
//! - `day` 是台北的日數（Unix 毫秒換算，`u32`）；系統時間倒退（還沒對時）時不寫。

use crate::time::{DAY_MS, TPE_OFFSET_MS};
use crate::util::write_atomic;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

/// 狀態目錄裡的檔名（實際寫的是 `.zst`）
pub const LEARN_FILE: &str = "benchmark-learn.json";
/// 格式版本
pub const VERSION: u64 = 1;
/// 解壓後最多讀這麼多（原始大小上限約 160 KB；超過當成壞掉的）
pub const MAX_RAW: u64 = 256 * 1024;
/// `neverOk` 最多幾筆（執行時上線以來從未成功的自動上游）
pub const MAX_NEVER_OK: usize = 32;
/// 連續幾次評測都排除後忘掉重來（它可能修好了）
pub const NEVER_OK_RUNS: u32 = 3;

/// 執行時上線以來從未成功、被先停用的自動上游（A7）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeverOk {
    /// 第一次登記的日數
    pub since: u32,
    /// 已經被幾次評測排除
    pub n: u32,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Learn {
    pub day: u32,
    pub never_ok: BTreeMap<String, NeverOk>,
    /// 這一版不認得的區段：原樣保留
    rest: Map<String, Value>,
}

/// 台北的日數
pub fn day_of(ms: u64) -> u32 {
    ((ms + TPE_OFFSET_MS) / DAY_MS) as u32
}

fn zst_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".zst");
    PathBuf::from(s)
}

fn read_raw(path: &Path) -> Option<Vec<u8>> {
    if let Ok(f) = std::fs::File::open(zst_path(path)) {
        let mut out = Vec::new();
        let dec = zstd::stream::read::Decoder::new(f).ok()?;
        dec.take(MAX_RAW + 1).read_to_end(&mut out).ok()?;
        return (out.len() as u64 <= MAX_RAW).then_some(out);
    }
    let b = std::fs::read(path).ok()?;
    (b.len() as u64 <= MAX_RAW).then_some(b)
}

impl Learn {
    /// 讀檔；讀不到、格式不對、版本不認識都當成空的
    pub fn load(path: &Path) -> Learn {
        let Some(b) = read_raw(path) else {
            return Learn::default();
        };
        let Ok(Value::Object(mut o)) = serde_json::from_slice::<Value>(&b) else {
            return Learn::default();
        };
        if o.get("v").and_then(Value::as_u64) != Some(VERSION) {
            return Learn::default();
        }
        o.remove("v");
        let day = o.remove("day").and_then(|d| d.as_u64()).unwrap_or(0) as u32;
        let mut never_ok = BTreeMap::new();
        if let Some(Value::Object(m)) = o.remove("neverOk") {
            for (id, e) in m {
                let f = |k: &str| e.get(k).and_then(Value::as_u64).map(|x| x.min(u32::MAX as u64) as u32);
                if let (Some(since), Some(n)) = (f("since"), f("n")) {
                    never_ok.insert(id, NeverOk { since, n });
                }
            }
        }
        let mut l = Learn { day, never_ok, rest: o };
        l.cap();
        l
    }

    /// 超過上限時先丟最舊的（`since` 最小的）
    fn cap(&mut self) {
        while self.never_ok.len() > MAX_NEVER_OK {
            let Some(oldest) = self.never_ok.iter().min_by_key(|(_, e)| e.since).map(|(k, _)| k.clone()) else {
                break;
            };
            self.never_ok.remove(&oldest);
        }
    }

    pub fn to_json(&self) -> Value {
        let mut o = self.rest.clone();
        o.insert("v".into(), json!(VERSION));
        o.insert("day".into(), json!(self.day));
        let m: Map<String, Value> = self
            .never_ok
            .iter()
            .map(|(k, e)| (k.clone(), json!({ "since": e.since, "n": e.n })))
            .collect();
        o.insert("neverOk".into(), Value::Object(m));
        Value::Object(o)
    }

    /// 寫成 `.zst`（暫存檔 + 改名），寫好之後刪掉舊的一般 JSON
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let raw = serde_json::to_vec(&self.to_json()).map_err(std::io::Error::other)?;
        let z = zstd::stream::encode_all(&raw[..], 3)?;
        write_atomic(&zst_path(path), &z)?;
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    /// 日數往前走：`today` 比檔案裡的舊（系統時間倒退、還沒對時）回 false，呼叫者就不要寫
    pub fn advance(&mut self, today: u32) -> bool {
        if today < self.day {
            return false;
        }
        self.day = today;
        true
    }

    /// 主程式登記執行時從未成功的上游（已經有的不動，次數照舊）
    pub fn add_never_ok(&mut self, ids: &[String], today: u32) -> bool {
        let mut changed = false;
        for id in ids {
            if !self.never_ok.contains_key(id) {
                self.never_ok.insert(id.clone(), NeverOk { since: today, n: 0 });
                changed = true;
            }
        }
        self.cap();
        changed
    }

    /// 評測開始時：這次要排除的（排除過不到 [`NEVER_OK_RUNS`] 次的）；排除夠多次的忘掉重來。
    /// 回傳（要排除的 id，有沒有變動）。次數在這裡就加上（這次評測算一次）
    pub fn take_never_ok_round(&mut self) -> (Vec<String>, bool) {
        let before = self.never_ok.len();
        self.never_ok.retain(|_, e| e.n < NEVER_OK_RUNS);
        let changed = before != self.never_ok.len() || !self.never_ok.is_empty();
        let ids: Vec<String> = self.never_ok.keys().cloned().collect();
        for e in self.never_ok.values_mut() {
            e.n += 1;
        }
        (ids, changed)
    }
}

/// 主程式在評測開始前：把執行時登記的從未成功的上游併進學習檔。回傳有沒有寫成功（沒有要寫的也算成功）
pub fn merge_never_ok(path: &Path, ids: &[String], now_ms: u64) -> bool {
    if ids.is_empty() {
        return true;
    }
    let mut l = Learn::load(path);
    let today = day_of(now_ms);
    if !l.advance(today) {
        return false;
    }
    if !l.add_never_ok(ids, today) {
        return true;
    }
    l.save(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kuroshio-learn-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join(LEARN_FILE)
    }

    #[test]
    fn missing_or_bad_file_is_empty() {
        let p = tmp("bad");
        assert_eq!(Learn::load(&p), Learn::default());
        std::fs::write(&p, b"not json").unwrap();
        assert_eq!(Learn::load(&p), Learn::default());
        std::fs::write(&p, br#"{"v":2,"day":5,"neverOk":{"a":{"since":1,"n":0}}}"#).unwrap();
        assert_eq!(Learn::load(&p), Learn::default(), "不認識的版本");
        std::fs::write(&p, vec![b' '; (MAX_RAW + 1) as usize]).unwrap();
        assert_eq!(Learn::load(&p), Learn::default(), "太大");
        // 舊的一般 JSON 照讀
        std::fs::write(&p, br#"{"v":1,"day":5,"neverOk":{"a":{"since":1,"n":2},"bad":{}}}"#).unwrap();
        let l = Learn::load(&p);
        assert_eq!(l.day, 5);
        assert_eq!(l.never_ok.len(), 1);
        assert_eq!(l.never_ok["a"], NeverOk { since: 1, n: 2 });
    }

    #[test]
    fn save_is_compressed_and_keeps_other_sections() {
        let p = tmp("save");
        std::fs::write(&p, br#"{"v":1,"day":10,"hist":{"x":{"t":1}},"neverOk":{}}"#).unwrap();
        let mut l = Learn::load(&p);
        assert!(l.add_never_ok(&["udp://192.0.2.1:53".into()], 10));
        l.save(&p).unwrap();
        assert!(!p.exists(), "舊的一般 JSON 刪掉");
        assert!(zst_path(&p).exists());
        let l = Learn::load(&p);
        assert_eq!(l.to_json()["hist"]["x"]["t"], 1, "不認得的區段原樣保留");
        assert_eq!(l.never_ok["udp://192.0.2.1:53"], NeverOk { since: 10, n: 0 });
    }

    #[test]
    fn never_ok_capped_and_rounds() {
        let mut l = Learn::default();
        let ids: Vec<String> = (0..40).map(|i| format!("udp://192.0.2.{i}:53")).collect();
        for (i, id) in ids.iter().enumerate() {
            l.add_never_ok(std::slice::from_ref(id), i as u32);
        }
        assert_eq!(l.never_ok.len(), MAX_NEVER_OK);
        assert!(!l.never_ok.contains_key(&ids[0]), "先丟最舊的");
        assert!(l.never_ok.contains_key(&ids[39]));
        // 已經有的不重設次數
        let mut l = Learn::default();
        l.add_never_ok(&["a".into()], 1);
        let (ex, _) = l.take_never_ok_round();
        assert_eq!(ex, ["a"]);
        assert!(!l.add_never_ok(&["a".into()], 2));
        assert_eq!(l.never_ok["a"].n, 1);
        assert_eq!(l.take_never_ok_round().0, ["a"]);
        assert_eq!(l.take_never_ok_round().0, ["a"]);
        // 排除 3 次之後忘掉重來
        let (ex, changed) = l.take_never_ok_round();
        assert!(ex.is_empty() && changed);
        assert!(l.never_ok.is_empty());
        let (_, changed) = l.take_never_ok_round();
        assert!(!changed, "沒有東西就不必寫");
    }

    #[test]
    fn clock_going_back_does_not_write() {
        let p = tmp("clock");
        let day = |d: u32| d as u64 * DAY_MS - TPE_OFFSET_MS + 3_600_000;
        assert!(merge_never_ok(&p, &["a".into()], day(20_000)));
        assert_eq!(Learn::load(&p).day, 20_000);
        assert_eq!(day_of(day(20_000)), 20_000);
        // 系統時間倒退（還沒對時的 1970 年）：不寫
        assert!(!merge_never_ok(&p, &["b".into()], 1000));
        assert!(!Learn::load(&p).never_ok.contains_key("b"));
        assert!(merge_never_ok(&p, &[], 1000), "沒有要寫的");
    }
}
