//! 評測學習資料（3.5.0，規格 11 第 0.3 節）：跨天的評測紀錄共用一個檔 `state/benchmark-learn.json`
//! （寫成 zstd 壓縮的 `.zst`；讀的時候兩種都接受）。
//!
//! ```json
//! { "v": 1, "day": 20781,
//!   "control": { "<id>": "ddddpd-u…" }, "controlDay": 20781,
//!   "hist":    { "<id>": [t, s, q, ms, dv, e, last] },
//!   "h3skip":  { "<h3:// 的 id>": { "f": 3, "n": 1, "until": 20790, "last": 20783 } },
//!   "neverOk": { "<id>": { "since": 20780, "n": 2 } } }
//! ```
//!
//! - 丟了只是重新學，不影響正確性（`space.rs` 歸 `Rebuildable`）；不進備份的分享檔、不傳給下游與好友。
//! - 讀不到、格式不對、`v` 不認識、太大：當成空的，不失敗。
//! - 用到的區段：`neverOk`（A7）、`h3skip`（A6）、`control`／`controlDay`（A2）、`hist`（A4）；不認得的區段原樣保留，不會被這裡蓋掉。
//! - `hist`（A4）：每個測過的一般候選一筆，寫成陣列省空間（2,000 筆要放得進上限）：
//!   `t`／`s`／`q` 是近 30 天的位元遮罩（最低位是 `last` 那天）：哪幾天測到、哪幾天倖存到最後、哪幾天有汙染／可疑；
//!   `ms`／`dv` 是倖存那幾天平均延遲的 EWMA 與它的平均偏差；`e` 是升降狀態（見 [`HistState`]）；`last` 是最後記錄的日數。
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
/// 解壓後最多讀這麼多（原始大小約 180 KB 以內：`hist` 2,000 筆約 130 KB；超過當成壞掉的）
pub const MAX_RAW: u64 = 384 * 1024;
/// `hist` 最多幾筆（預設名單約 1,800 個候選）
pub const MAX_HIST: usize = 2000;
/// `hist` 記最近幾天
pub const HIST_DAYS: u32 = 30;
const HIST_MASK: u32 = (1 << HIST_DAYS) - 1;

/// 依評測歷史的升降狀態（A4）。只影響「今天測不測」，不影響選不選
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HistState {
    /// 照人工分級
    #[default]
    Normal,
    /// B 級拉上來每天測（歷史夠長、夠好）
    Promoted,
    /// A 級降下去（歷史很差）：只在探索時輪到
    Demoted,
    /// B 級試用：探索時表現好，先每天測，累積到夠長的歷史再決定
    Trial,
}

impl HistState {
    fn code(self) -> u64 {
        match self {
            HistState::Normal => 0,
            HistState::Promoted => 1,
            HistState::Demoted => 2,
            HistState::Trial => 3,
        }
    }
    fn from_code(c: u64) -> HistState {
        match c {
            1 => HistState::Promoted,
            2 => HistState::Demoted,
            3 => HistState::Trial,
            _ => HistState::Normal,
        }
    }
}

/// 一個候選近 30 天的評測歷史（A4）
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Hist {
    /// 哪幾天測到（而且那天評測成功）；最低位是 `last` 那天
    pub t: u32,
    /// 哪幾天倖存到最後
    pub s: u32,
    /// 哪幾天被判汙染／可疑
    pub q: u32,
    /// 倖存那幾天平均延遲的 EWMA（毫秒）
    pub ms: f32,
    /// 延遲的平均偏差（EWMA）
    pub dv: f32,
    pub e: HistState,
    pub last: u32,
}

impl Hist {
    /// 換算到今天：依日數差位移，超過 30 天的掉出去。日數差 32 以上直接歸零（位移不能溢位）；
    /// 今天比 `last` 舊（系統時間倒退）時原樣回傳
    pub fn aged(mut self, today: u32) -> Hist {
        if today <= self.last {
            return self;
        }
        let gap = today - self.last;
        let shift = |m: u32| if gap >= 32 { 0 } else { (m << gap) & HIST_MASK };
        self.t = shift(self.t);
        self.s = shift(self.s);
        self.q = shift(self.q);
        self.last = today;
        self
    }
    /// 測到幾天
    pub fn tested(&self) -> u32 {
        (self.t & HIST_MASK).count_ones()
    }
    /// 倖存幾天
    pub fn survived(&self) -> u32 {
        (self.s & self.t & HIST_MASK).count_ones()
    }
    /// 幾天有汙染／可疑紀錄
    pub fn suspect(&self) -> u32 {
        (self.q & HIST_MASK).count_ones()
    }
    /// 倖存率（沒測過是 0）
    pub fn rate(&self) -> f32 {
        match self.tested() {
            0 => 0.0,
            n => self.survived() as f32 / n as f32,
        }
    }
    /// 延遲穩不穩：平均偏差不超過平均的一半（延遲很低時放寬到 10 ms，區網抖動幾毫秒不算不穩）
    pub fn stable(&self) -> bool {
        self.dv <= (self.ms * 0.5).max(10.0)
    }
    /// 歷史分數（只用來排序）：倖存率 × 穩定度 − 可疑懲罰。沒測過是 None
    pub fn score(&self) -> Option<f32> {
        if self.tested() == 0 {
            return None;
        }
        let cv = if self.ms > 0.0 { (self.dv / self.ms).min(1.0) } else { 0.0 };
        Some(self.rate() * (1.0 - cv * 0.5) - 0.25 * self.suspect() as f32)
    }
    /// 記下今天的結果。回 false＝沒記（系統時間倒退）。同一天再跑一次：換掉今天那一格，延遲不重複算
    pub fn record(&mut self, today: u32, survived: bool, suspect: bool, ms: Option<f32>) -> bool {
        if today < self.last {
            return false;
        }
        let again = self.last == today && self.t & 1 == 1;
        *self = self.aged(today);
        self.last = today;
        self.t |= 1;
        self.s = (self.s & !1) | survived as u32;
        self.q = (self.q & !1) | suspect as u32;
        if let (false, true, Some(x)) = (again, survived, ms.filter(|x| x.is_finite() && *x >= 0.0)) {
            if self.ms <= 0.0 {
                self.ms = x;
                self.dv = 0.0;
            } else {
                self.dv += ((x - self.ms).abs() - self.dv) / 4.0;
                self.ms += (x - self.ms) / 4.0;
            }
        }
        true
    }

    fn to_json(self) -> Value {
        let r = |x: f32| (x as f64 * 10.0).round() / 10.0;
        json!([self.t, self.s, self.q, r(self.ms), r(self.dv), self.e.code(), self.last])
    }

    fn from_json(v: &Value) -> Option<Hist> {
        let a = v.as_array()?;
        let u = |i: usize| a.get(i).and_then(Value::as_u64).map(|x| x.min(u32::MAX as u64) as u32);
        let f = |i: usize| {
            a.get(i)
                .and_then(Value::as_f64)
                .filter(|x| x.is_finite() && *x >= 0.0)
                .map(|x| x as f32)
        };
        Some(Hist {
            t: u(0)? & HIST_MASK,
            s: u(1)? & HIST_MASK,
            q: u(2)? & HIST_MASK,
            ms: f(3)?,
            dv: f(4)?,
            e: HistState::from_code(a.get(5)?.as_u64()?),
            last: u(6)?,
        })
    }
}
/// `neverOk` 最多幾筆（執行時上線以來從未成功的自動上游）
pub const MAX_NEVER_OK: usize = 32;
/// 連續幾次評測都排除後忘掉重來（它可能修好了）
pub const NEVER_OK_RUNS: u32 = 3;
/// `control` 最多幾筆（同對照組的上限 `MAX_PROTECTED`）
pub const MAX_CONTROL: usize = 64;
/// 對照組每台記最近幾天的結果
pub const CONTROL_DAYS: usize = 30;
/// 回歸判斷看前幾天（不含今天）
pub const CONTROL_RECENT: usize = 7;
/// 過去 [`CONTROL_RECENT`] 天裡幾天判出過，今天沒判出才算回歸
pub const CONTROL_REGRESS_DAYS: usize = 3;
/// 整體回歸：今天至少測到幾台才判斷
pub const CONTROL_MIN_TESTED: usize = 8;

/// 對照組一天的結果字元：`d`＝判出、`p`＝沒判出、`u`＝沒測到、`-`＝那天沒跑
fn control_char_ok(c: char) -> bool {
    matches!(c, 'd' | 'p' | 'u' | '-')
}

/// 對照組的回歸（A2）：今天 `p`（沒判出），過去 7 天（不含今天）裡有 3 天以上 `d`。
/// 字串第一個字元是今天；`u`、`-` 不算（路徑檢查略過一類協定不會誤報）
pub fn control_regress(hist: &str) -> bool {
    let mut it = hist.chars();
    it.next() == Some('p') && it.take(CONTROL_RECENT).filter(|c| *c == 'd').count() >= CONTROL_REGRESS_DAYS
}

/// 整體回歸（A2）：今天「判出」的比例比過去 7 天的中位數少一半以上（而且今天測到 8 台以上）。
/// 每一天只算那天測到（`d` 或 `p`）8 台以上的；過去沒有這種天數時不判斷。
/// 回傳（今天的比例, 過去的中位數），沒有回歸是 None
pub fn control_overall_drop<'a>(hists: impl Iterator<Item = &'a str> + Clone) -> Option<(f64, f64)> {
    let ratio = |k: usize| -> Option<f64> {
        let (mut d, mut n) = (0usize, 0usize);
        for h in hists.clone() {
            match h.chars().nth(k) {
                Some('d') => {
                    d += 1;
                    n += 1;
                }
                Some('p') => n += 1,
                _ => {}
            }
        }
        (n >= CONTROL_MIN_TESTED).then(|| d as f64 / n as f64)
    };
    let today = ratio(0)?;
    let mut past: Vec<f64> = (1..=CONTROL_RECENT).filter_map(ratio).collect();
    if past.is_empty() {
        return None;
    }
    past.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let m = past.len();
    let median = if m % 2 == 1 {
        past[m / 2]
    } else {
        (past[m / 2 - 1] + past[m / 2]) / 2.0
    };
    (today < median / 2.0).then_some((today, median))
}

/// `h3skip` 最多幾筆（不支援 HTTP/3 的 DoH，A6）
pub const MAX_H3_SKIP: usize = 512;
/// `h3://` 連續幾天（不同日期）QUIC 連不上、`https://` 正常，才開始跳過
pub const H3_FAIL_DAYS: u32 = 3;
/// 跳過的基本天數（第 n 輪是 `7 × 2^n`）
pub const H3_SKIP_BASE: u32 = 7;
/// 跳過的輪數最多算到幾（7、14、28 天之後一直是 28 天）
pub const H3_MAX_ROUND: u32 = 2;
/// 跳過最多幾天（含亂數）：一定會再試
pub const H3_MAX_SKIP: u32 = 30;
/// 亂數最多加幾天（0～3）
pub const H3_JITTER: u32 = 3;

/// 不支援 HTTP/3 的 DoH（A6）：`h3://` 連續幾天 QUIC 連不上、它的 `https://` 正常，跳過一段時間再試
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct H3Skip {
    /// 連續失敗的天數（同一天評測好幾次只算一天）
    pub f: u32,
    /// 已經跳過幾輪（最多 [`H3_MAX_ROUND`]）
    pub n: u32,
    /// 跳過到哪一天（這天以前不測；0 = 還沒開始跳過）
    pub until: u32,
    /// 最後一次記錄的日數（同一天不重複算、超過上限時先丟最舊的）
    pub last: u32,
}

/// 這次評測裡一個 `h3://` 候選的資格賽結果（給 [`Learn::h3_record`]）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3Seen {
    /// QUIC 連得上（有回答，不論答案對不對）：整筆刪掉
    Ok,
    /// 算一次失敗：連線錯誤、它的 `https://` 通過資格賽、今天 QUIC 沒有整條被擋
    Fail,
    /// 不算（`https://` 自己也失敗、QUIC 可能整條被擋）：不改
    Neutral,
}

/// `h3skip` 的變化（寫進 judge.log）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct H3Change {
    /// 多記了一天失敗（還沒開始跳過）
    pub counted: usize,
    /// 開始跳過（含到期再測又失敗、進下一輪的）
    pub skipped: usize,
    /// 恢復（QUIC 連得上，整筆刪掉）
    pub cleared: usize,
}

impl H3Change {
    pub fn any(&self) -> bool {
        self.counted + self.skipped + self.cleared > 0
    }
}

/// 跳過幾天：`7 × 2^n`（n 最多 2）再加 0～3 天亂數，合計最多 30 天。
/// 亂數用 id 的雜湊加日數（不用另外的亂數來源，測試才穩；同一天開始跳過的不會全部同一天回來）
pub fn h3_skip_days(id: &str, today: u32, n: u32) -> u32 {
    // FNV-1a：固定、跨平台一樣
    let mut h: u32 = 0x811c_9dc5;
    for b in id.as_bytes().iter().chain(&today.to_le_bytes()) {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    let jitter = h % (H3_JITTER + 1);
    ((H3_SKIP_BASE << n.min(H3_MAX_ROUND)) + jitter).min(H3_MAX_SKIP)
}

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
    /// 不支援 HTTP/3 的 DoH（A6），以 `h3://` 的 id 為鍵
    pub h3skip: BTreeMap<String, H3Skip>,
    /// 對照組最近 30 天的結果（A2）：第一個字元是 `control_day` 那天
    pub control: BTreeMap<String, String>,
    /// `control` 最後記錄的日數（跟檔案的 `day` 分開：主程式登記 `neverOk` 時也會更新 `day`）
    pub control_day: u32,
    /// 每個候選近 30 天的評測歷史（A4）
    pub hist: BTreeMap<String, Hist>,
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
        let mut h3skip = BTreeMap::new();
        if let Some(Value::Object(m)) = o.remove("h3skip") {
            for (id, e) in m {
                let f = |k: &str| e.get(k).and_then(Value::as_u64).map(|x| x.min(u32::MAX as u64) as u32);
                if let (Some(fd), Some(n), Some(until)) = (f("f"), f("n"), f("until")) {
                    let last = f("last").unwrap_or(until);
                    h3skip.insert(
                        id,
                        H3Skip {
                            f: fd,
                            n: n.min(H3_MAX_ROUND),
                            until,
                            last,
                        },
                    );
                }
            }
        }
        let mut control = BTreeMap::new();
        if let Some(Value::Object(m)) = o.remove("control") {
            for (id, e) in m {
                if let Some(h) = e.as_str() {
                    let h: String = h.chars().filter(|c| control_char_ok(*c)).take(CONTROL_DAYS).collect();
                    if !h.is_empty() {
                        control.insert(id, h);
                    }
                }
            }
        }
        let control_day = o.remove("controlDay").and_then(|d| d.as_u64()).unwrap_or(0).min(u32::MAX as u64) as u32;
        let mut hist = BTreeMap::new();
        if let Some(Value::Object(m)) = o.remove("hist") {
            for (id, e) in m {
                if let Some(h) = Hist::from_json(&e) {
                    hist.insert(id, h);
                }
            }
        }
        let mut l = Learn {
            day,
            hist,
            never_ok,
            h3skip,
            control,
            control_day,
            rest: o,
        };
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
        self.cap_h3();
        self.hist_cap(|_| true);
        // control：超過上限時丟「最後一次有結果」最久以前的
        while self.control.len() > MAX_CONTROL {
            let Some(k) = self
                .control
                .iter()
                .max_by_key(|(_, h)| h.chars().position(|c| c != '-').unwrap_or(usize::MAX))
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.control.remove(&k);
        }
    }

    /// `h3skip` 超過上限時丟 `last` 最舊的（名單裡已經沒有的由 [`h3_prune`](Self::h3_prune) 先丟）
    fn cap_h3(&mut self) {
        let over = self.h3skip.len().saturating_sub(MAX_H3_SKIP);
        if over == 0 {
            return;
        }
        let mut by_age: Vec<(u32, String)> = self.h3skip.iter().map(|(k, e)| (e.last, k.clone())).collect();
        by_age.sort();
        for (_, k) in by_age.into_iter().take(over) {
            self.h3skip.remove(&k);
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
        let h: Map<String, Value> = self
            .h3skip
            .iter()
            .map(|(k, e)| (k.clone(), json!({ "f": e.f, "n": e.n, "until": e.until, "last": e.last })))
            .collect();
        o.insert("h3skip".into(), Value::Object(h));
        let c: Map<String, Value> = self.control.iter().map(|(k, h)| (k.clone(), json!(h))).collect();
        o.insert("control".into(), Value::Object(c));
        o.insert("controlDay".into(), json!(self.control_day));
        let h: Map<String, Value> = self.hist.iter().map(|(k, e)| (k.clone(), e.to_json())).collect();
        o.insert("hist".into(), Value::Object(h));
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

impl Learn {
    /// 這個 `h3://` 今天要不要跳過（還在跳過期間）。系統時間倒退（今天比檔案的日數舊）時一律不跳過；
    /// `until` 離今天超過上限（時間曾經跳到未來又回來）也不跳過，不會卡住
    pub fn h3_skipping(&self, id: &str, today: u32) -> bool {
        if today < self.day {
            return false;
        }
        self.h3skip
            .get(id)
            .is_some_and(|e| e.until > today && e.until - today <= H3_MAX_SKIP)
    }

    /// 記下一個 `h3://` 候選今天的結果。回傳有沒有變動。
    /// - 還沒開始跳過：失敗一天記一天（同一天不重複），連續 [`H3_FAIL_DAYS`] 天就開始跳過 `h3_skip_days` 天；
    /// - 跳過到期再測：失敗 1 次就進下一輪（7 → 14 → 28 天）；
    /// - QUIC 連得上：整筆刪掉
    pub fn h3_record(&mut self, id: &str, today: u32, seen: H3Seen, change: &mut H3Change) -> bool {
        if today < self.day {
            return false;
        }
        match seen {
            H3Seen::Neutral => false,
            H3Seen::Ok => {
                let hit = self.h3skip.remove(id).is_some();
                change.cleared += hit as usize;
                hit
            }
            H3Seen::Fail => {
                let e = self.h3skip.entry(id.to_string()).or_default();
                if e.until > 0 {
                    // 跳過到期、再測又失敗：直接進下一輪
                    if e.until > today && e.until - today <= H3_MAX_SKIP {
                        return false; // 還在跳過期間（照理不會測到）
                    }
                    e.until = today + h3_skip_days(id, today, e.n);
                    e.n = (e.n + 1).min(H3_MAX_ROUND);
                    e.last = today;
                    change.skipped += 1;
                    return true;
                }
                if e.f > 0 && e.last == today {
                    return false;
                }
                e.f += 1;
                e.last = today;
                if e.f >= H3_FAIL_DAYS {
                    e.until = today + h3_skip_days(id, today, e.n);
                    e.n = (e.n + 1).min(H3_MAX_ROUND);
                    change.skipped += 1;
                } else {
                    change.counted += 1;
                }
                self.cap_h3();
                true
            }
        }
    }

    /// 名單裡已經沒有的（它的 `https://` 不在名單了）刪掉；回傳刪了幾筆
    pub fn h3_prune(&mut self, keep: impl Fn(&str) -> bool) -> usize {
        let before = self.h3skip.len();
        self.h3skip.retain(|k, _| keep(k));
        before - self.h3skip.len()
    }

    /// 記下對照組今天的結果（A2）：`results` 是名單裡每一台（id, `d`／`p`／`u`）；名單裡已經沒有的刪掉。
    /// 跨天時依日數差往右移，中間沒跑的那幾天補 `-`；同一天再跑一次就換掉今天那一格。最多 30 天。
    /// 系統時間倒退（今天比上次記錄的舊）時不改，回 false
    pub fn control_record(&mut self, today: u32, results: &[(String, char)]) -> bool {
        if today < self.control_day {
            return false;
        }
        let gap = if self.control_day == 0 {
            1
        } else {
            (today - self.control_day) as usize
        };
        let mut out = BTreeMap::new();
        for (id, c) in results.iter().take(MAX_CONTROL) {
            let old = self.control.get(id).map(String::as_str).unwrap_or("");
            let mut h = String::with_capacity(CONTROL_DAYS);
            h.push(*c);
            if gap == 0 {
                h.extend(old.chars().skip(1));
            } else if !old.is_empty() {
                h.extend(std::iter::repeat('-').take((gap - 1).min(CONTROL_DAYS)));
                h.push_str(old);
            }
            out.insert(id.clone(), h.chars().take(CONTROL_DAYS).collect::<String>());
        }
        self.control = out;
        self.control_day = today;
        true
    }

    /// `hist` 超過 [`MAX_HIST`] 筆時：先丟名單裡已經沒有的，再丟 `last` 最舊的。回傳丟了幾筆
    pub fn hist_cap(&mut self, listed: impl Fn(&str) -> bool) -> usize {
        let over = self.hist.len().saturating_sub(MAX_HIST);
        if over == 0 {
            return 0;
        }
        let mut order: Vec<(bool, u32, String)> = self.hist.iter().map(|(k, e)| (listed(k), e.last, k.clone())).collect();
        order.sort();
        for (_, _, k) in order.into_iter().take(over) {
            self.hist.remove(&k);
        }
        over
    }

    /// 今天在跳過期間的筆數
    pub fn h3_skipping_count(&self, today: u32) -> usize {
        self.h3skip.keys().filter(|k| self.h3_skipping(k, today)).count()
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
        std::fs::write(&p, br#"{"v":1,"day":10,"later":{"x":{"t":1}},"neverOk":{}}"#).unwrap();
        let mut l = Learn::load(&p);
        assert!(l.add_never_ok(&["udp://192.0.2.1:53".into()], 10));
        l.save(&p).unwrap();
        assert!(!p.exists(), "舊的一般 JSON 刪掉");
        assert!(zst_path(&p).exists());
        let l = Learn::load(&p);
        assert_eq!(l.to_json()["later"]["x"]["t"], 1, "不認得的區段原樣保留");
        assert_eq!(l.never_ok["udp://192.0.2.1:53"], NeverOk { since: 10, n: 0 });
    }

    #[test]
    fn hist_shift_across_days_and_gaps() {
        let mut h = Hist::default();
        assert!(h.record(100, true, false, Some(20.0)));
        assert_eq!((h.t, h.s, h.q, h.last), (1, 1, 0, 100));
        assert_eq!((h.ms, h.dv), (20.0, 0.0));
        // 隔天沒倖存、有可疑紀錄
        assert!(h.record(101, false, true, None));
        assert_eq!((h.t, h.s, h.q), (0b11, 0b10, 0b01));
        assert_eq!((h.tested(), h.survived(), h.suspect()), (2, 1, 1));
        // 同一天再跑一次：換掉今天那一格，延遲不重複算
        assert!(h.record(101, true, false, Some(60.0)));
        assert_eq!((h.t, h.s, h.q), (0b11, 0b11, 0));
        assert_eq!(h.ms, 20.0, "同一天的第二次不算進延遲");
        // 跳過 3 天沒測
        assert!(h.record(105, true, false, Some(28.0)));
        assert_eq!((h.t, h.s), (0b110001, 0b110001));
        assert_eq!((h.ms, h.dv), (22.0, 2.0));
        // 系統時間倒退：不記、不位移
        let before = h;
        assert!(!h.record(104, false, true, Some(1.0)));
        assert_eq!(h, before);
        assert_eq!(h.aged(90), before);
        // 30 天後最舊的掉出去；日數差 32 以上直接歸零（不會位移溢位）
        assert_eq!(h.aged(105 + 25).tested(), 2, "第 100、101 天還在 30 天內");
        assert_eq!(h.aged(105 + 29).tested(), 1);
        assert_eq!(h.aged(105 + 30).tested(), 0);
        for gap in [31, 32, 33, 64, 4_000_000] {
            let a = h.aged(105 + gap);
            assert_eq!((a.t, a.s, a.q), (0, 0, 0), "{gap}");
        }
        assert!(h.record(105 + 40, true, false, Some(22.0)));
        assert_eq!(h.t, 1);
        // 分數：倖存率 × 穩定度 − 可疑懲罰
        assert_eq!(Hist::default().score(), None);
        let good = Hist {
            t: 0b1111,
            s: 0b1111,
            ms: 20.0,
            dv: 2.0,
            ..Default::default()
        };
        let flaky = Hist {
            t: 0b1111,
            s: 0b0101,
            ms: 20.0,
            dv: 2.0,
            ..Default::default()
        };
        let jumpy = Hist {
            t: 0b1111,
            s: 0b1111,
            ms: 20.0,
            dv: 30.0,
            ..Default::default()
        };
        let suspect = Hist {
            t: 0b1111,
            s: 0b1111,
            q: 1,
            ms: 20.0,
            dv: 2.0,
            ..Default::default()
        };
        assert!(good.score() > jumpy.score() && jumpy.score() > flaky.score());
        assert!(good.score() > suspect.score());
        assert!(good.stable() && !jumpy.stable());
        assert!(Hist { ms: 4.0, dv: 8.0, ..good }.stable(), "延遲很低時抖動幾毫秒不算不穩");
    }

    #[test]
    fn hist_roundtrip_and_capped_at_2000_drops_unlisted_first() {
        let p = tmp("hist");
        let mut l = Learn::default();
        for i in 0..MAX_HIST + 50 {
            let mut h = Hist {
                e: HistState::Trial,
                ..Default::default()
            };
            h.record(20_000 + (i % 7) as u32, i % 3 != 0, false, Some(12.3 + i as f32 / 100.0));
            l.hist.insert(format!("https://dns{i}.example.net/dns-query"), h);
        }
        // 名單裡已經沒有的 50 筆先丟（即使它們比較新），再丟最舊的
        let unlisted = |k: &str| k.contains("dns20") && k.len() == "https://dns2000.example.net/dns-query".len();
        let n_unlisted = l.hist.keys().filter(|k| unlisted(k)).count();
        assert_eq!(n_unlisted, 50);
        assert_eq!(l.hist_cap(|k| !unlisted(k)), 50);
        assert_eq!(l.hist.len(), MAX_HIST);
        assert!(!l.hist.keys().any(|k| unlisted(k)));
        // 再塞 10 筆最舊的：丟的是它們
        for i in 0..10 {
            l.hist.insert(
                format!("old{i}"),
                Hist {
                    t: 1,
                    last: 5,
                    ..Default::default()
                },
            );
        }
        assert_eq!(l.hist_cap(|_| true), 10);
        assert!(!l.hist.keys().any(|k| k.starts_with("old")));
        l.day = 20_010;
        l.save(&p).unwrap();
        let back = Learn::load(&p);
        assert_eq!(back.hist.len(), MAX_HIST);
        let (k, h) = l.hist.iter().next().unwrap();
        let b = back.hist[k];
        assert_eq!((b.t, b.s, b.q, b.e, b.last), (h.t, h.s, h.q, HistState::Trial, h.last));
        assert!((b.ms - h.ms).abs() < 0.06);
        // 大小：原始放得進上限，壓縮後在 64 KB 以內（小 Flash、每日寫入額度）
        let raw = serde_json::to_vec(&l.to_json()).unwrap().len() as u64;
        assert!(raw < MAX_RAW * 3 / 4, "原始 {raw} bytes");
        let z = std::fs::metadata(zst_path(&p)).unwrap().len();
        assert!(z < 64 * 1024, "壓縮後 {z} bytes");
        // 格式不對的那一筆丟掉，其他照讀
        std::fs::write(
            &p,
            br#"{"v":1,"day":5,"hist":{"a":[3,1,0,12.5,1,2,5],"bad":{"t":1},"short":[1,1]}}"#,
        )
        .unwrap();
        let _ = std::fs::remove_file(zst_path(&p));
        let l = Learn::load(&p);
        assert_eq!(l.hist.len(), 1);
        assert_eq!(
            l.hist["a"],
            Hist {
                t: 3,
                s: 1,
                q: 0,
                ms: 12.5,
                dv: 1.0,
                e: HistState::Demoted,
                last: 5
            }
        );
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

    #[test]
    fn h3_skip_backoff_7_14_28_capped_30_with_jitter() {
        // 亂數 0～3 天、固定（同一個 id 同一天結果一樣）、合計不超過 30
        for n in 0..5 {
            for d in 20_000..20_050 {
                let k = h3_skip_days("h3://dns.example.com/dns-query", d, n);
                let base = 7 << n.min(H3_MAX_ROUND);
                assert!(
                    k >= base.min(H3_MAX_SKIP) && k <= (base + H3_JITTER).min(H3_MAX_SKIP),
                    "n={n} d={d} k={k}"
                );
                assert_eq!(k, h3_skip_days("h3://dns.example.com/dns-query", d, n));
            }
        }
        let spread: std::collections::HashSet<u32> = (0..64)
            .map(|i| h3_skip_days(&format!("h3://dns{i}.example.com/q"), 20_000, 0))
            .collect();
        assert!(spread.len() > 1, "不同的 id 不會全部同一天回來");
        assert!((20_000..20_100).all(|d| h3_skip_days("h3://x.example.net/q", d, 2) <= 30));

        let id = "h3://dns.example.com/dns-query";
        let mut l = Learn::default();
        let mut c = H3Change::default();
        // 同一天評測好幾次只算一天
        assert!(l.h3_record(id, 100, H3Seen::Fail, &mut c));
        assert!(!l.h3_record(id, 100, H3Seen::Fail, &mut c));
        assert!(l.h3_record(id, 101, H3Seen::Fail, &mut c));
        assert!(!l.h3_skipping(id, 102));
        assert_eq!(c.counted, 2);
        // 第 3 天開始跳過 7～10 天
        assert!(l.h3_record(id, 102, H3Seen::Fail, &mut c));
        assert_eq!(c.skipped, 1);
        let e = l.h3skip[id];
        assert_eq!((e.f, e.n), (3, 1));
        assert!((109..=112).contains(&e.until), "{e:?}");
        assert!(l.h3_skipping(id, 103) && l.h3_skipping(id, e.until - 1));
        assert!(!l.h3_skipping(id, e.until), "到期再測");
        // 到期再測：失敗 1 次就進下一輪（14～17 天），再來 28～30 天，之後一直 28～30 天
        let mut day = e.until;
        for want in [14u32, 28, 28, 28] {
            assert!(l.h3_record(id, day, H3Seen::Fail, &mut c));
            let e = l.h3skip[id];
            assert!(
                e.until - day >= want && e.until - day <= (want + 3).min(30),
                "{want}: {e:?} day={day}"
            );
            assert!(e.n <= H3_MAX_ROUND);
            day = e.until;
        }
        // 系統時間倒退（比檔案的日數舊）：不跳過、不記
        let mut l = Learn {
            day: 500,
            ..Default::default()
        };
        l.h3skip.insert(
            id.into(),
            H3Skip {
                f: 3,
                n: 1,
                until: 505,
                last: 498,
            },
        );
        assert!(!l.h3_skipping(id, 400));
        assert!(!l.h3_record(id, 400, H3Seen::Ok, &mut c));
        // 時間曾經跳到未來：until 離今天超過 30 天，不會卡住
        let mut far = Learn::default();
        far.h3skip.insert(
            id.into(),
            H3Skip {
                f: 3,
                n: 0,
                until: 9_999,
                last: 100,
            },
        );
        assert!(!far.h3_skipping(id, 200));
    }

    #[test]
    fn h3_success_clears() {
        let id = "h3://dns.example.net/dns-query";
        let mut l = Learn::default();
        let mut c = H3Change::default();
        for d in 0..3 {
            l.h3_record(id, 10 + d, H3Seen::Fail, &mut c);
        }
        assert!(l.h3_skipping(id, 13));
        let until = l.h3skip[id].until;
        // 不算的（https:// 自己也失敗、QUIC 可能整條被擋）：不改
        assert!(!l.h3_record(id, until, H3Seen::Neutral, &mut c));
        assert_eq!(l.h3skip[id].until, until);
        // 到期再測成功：整筆刪掉
        assert!(l.h3_record(id, until, H3Seen::Ok, &mut c));
        assert!(!l.h3skip.contains_key(id));
        assert_eq!(c.cleared, 1);
        // 還沒跳過、中間成功一天：重新算
        l.h3_record(id, 50, H3Seen::Fail, &mut c);
        l.h3_record(id, 51, H3Seen::Fail, &mut c);
        l.h3_record(id, 52, H3Seen::Ok, &mut c);
        l.h3_record(id, 53, H3Seen::Fail, &mut c);
        assert_eq!(l.h3skip[id].f, 1);
        assert!(!l.h3_skipping(id, 54));
        // 存檔再讀回來一樣
        let p = tmp("h3");
        l.save(&p).unwrap();
        assert_eq!(Learn::load(&p).h3skip, l.h3skip);
    }

    #[test]
    fn h3skip_capped_512() {
        let mut l = Learn::default();
        let mut c = H3Change::default();
        for i in 0..(MAX_H3_SKIP as u32 + 40) {
            l.h3_record(&format!("h3://dns{i}.example.com/q"), i, H3Seen::Fail, &mut c);
        }
        assert_eq!(l.h3skip.len(), MAX_H3_SKIP);
        assert!(!l.h3skip.contains_key("h3://dns0.example.com/q"), "先丟 last 最舊的");
        assert!(l.h3skip.contains_key(&format!("h3://dns{}.example.com/q", MAX_H3_SKIP + 39)));
        // 名單裡已經沒有的刪掉
        let n = l.h3_prune(|k| k.ends_with("1.example.com/q"));
        assert!(n > 0 && l.h3skip.keys().all(|k| k.ends_with("1.example.com/q")));
        // 讀檔時也套用上限
        let mut big = Map::new();
        for i in 0..600u32 {
            big.insert(format!("h3://x{i}.example.net/q"), json!({ "f": 1, "n": 9, "until": 0, "last": i }));
        }
        let p = tmp("h3cap");
        std::fs::write(&p, serde_json::to_vec(&json!({ "v": 1, "day": 1, "h3skip": big })).unwrap()).unwrap();
        let l = Learn::load(&p);
        assert_eq!(l.h3skip.len(), MAX_H3_SKIP);
        assert!(l.h3skip.values().all(|e| e.n <= H3_MAX_ROUND));
        assert!(!l.h3skip.contains_key("h3://x0.example.net/q"));
    }

    #[test]
    fn control_history_capped_and_shifted() {
        let mut l = Learn::default();
        let r = |c: char| vec![("tls://a.example.com".to_string(), c), ("192.0.2.9".to_string(), 'u')];
        assert!(l.control_record(100, &r('d')));
        assert_eq!(l.control["tls://a.example.com"], "d");
        // 同一天再跑一次：換掉今天那一格
        l.control_record(100, &r('p'));
        assert_eq!(l.control["tls://a.example.com"], "p");
        l.control_record(101, &r('d'));
        assert_eq!(l.control["tls://a.example.com"], "dp");
        // 跳過幾天沒跑：補 -
        l.control_record(104, &r('d'));
        assert_eq!(l.control["tls://a.example.com"], "d--dp");
        assert_eq!(l.control["192.0.2.9"], "u--uu");
        // 31 天後長度還是 30
        for d in 105..140 {
            l.control_record(d, &r('p'));
        }
        assert_eq!(l.control["tls://a.example.com"].len(), CONTROL_DAYS);
        assert!(l.control["tls://a.example.com"].chars().all(|c| c == 'p'));
        // 很久沒跑：全部是 -，還是 30 天
        l.control_record(1000, &r('d'));
        assert_eq!(l.control["tls://a.example.com"], format!("d{}", "-".repeat(29)));
        // 系統時間倒退：不改
        assert!(!l.control_record(999, &r('p')));
        assert_eq!(l.control_day, 1000);
        // 名單裡已經沒有的刪掉；上限 64
        let many: Vec<(String, char)> = (0..80).map(|i| (format!("192.0.2.{i}"), 'p')).collect();
        l.control_record(1001, &many);
        assert_eq!(l.control.len(), MAX_CONTROL);
        assert!(!l.control.contains_key("tls://a.example.com"));
        // 存檔再讀回來一樣；壞掉的字元丟掉
        let p = tmp("control");
        l.save(&p).unwrap();
        let back = Learn::load(&p);
        assert_eq!((back.control.clone(), back.control_day), (l.control.clone(), 1001));
        std::fs::write(&p, br#"{"v":1,"day":3,"control":{"a":"dXp-","b":"","c":5}}"#).unwrap();
        let _ = std::fs::remove_file(zst_path(&p));
        let back = Learn::load(&p);
        assert_eq!(back.control.len(), 1);
        assert_eq!(back.control["a"], "dp-");
    }

    #[test]
    fn control_regression_rules() {
        assert!(control_regress("pddd"));
        assert!(control_regress("pdpdpdp"));
        assert!(!control_regress("pdd"), "只有 2 天");
        assert!(!control_regress("dddd"), "今天判出");
        assert!(!control_regress("uddd"), "今天沒測到不算");
        assert!(!control_regress("p-------ddd"), "超過 7 天的不算");
        assert!(control_regress("pd-d-d"), "沒跑的天數跳過");
        // 整體：10 台，過去每天 8 台判出，今天只剩 2 台
        let past = |today: char, n_d: usize| -> Vec<String> {
            (0..10)
                .map(|i| format!("{}{}", if i < n_d { 'd' } else { today }, if i < 8 { "ddddddd" } else { "ppppppp" }))
                .collect()
        };
        let h = past('p', 2);
        let got = control_overall_drop(h.iter().map(String::as_str)).unwrap();
        assert!((got.0 - 0.2).abs() < 1e-9 && (got.1 - 0.8).abs() < 1e-9, "{got:?}");
        assert!(
            control_overall_drop(past('p', 5).iter().map(String::as_str)).is_none(),
            "少不到一半"
        );
        // 今天測到的不到 8 台：不判斷
        let few: Vec<String> = (0..10).map(|i| format!("{}ddddddd", if i < 7 { 'u' } else { 'p' })).collect();
        assert!(control_overall_drop(few.iter().map(String::as_str)).is_none());
        // 沒有過去的資料：不判斷
        let fresh: Vec<String> = (0..10).map(|_| "p".to_string()).collect();
        assert!(control_overall_drop(fresh.iter().map(String::as_str)).is_none());
    }
}
