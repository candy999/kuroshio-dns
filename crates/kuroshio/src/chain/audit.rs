//! 抽查上游黑潮給的 CDN 答案（3.4.2，規格 10 第 3.8 節「直系血親：繼承但查核」）
//!
//! 上游給的答案預設照用，但下游保有自己檢查的能力：抽樣連到上游給的 IP、用網域名稱做 TLS 握手並完整檢查憑證。
//! 憑證不符時，用自己的加密上游解析一次、對自己拿到的 IP 做同樣的檢查：自己的正常 → 記一次「可疑」。
//! 1 小時內 3 次可疑 → 解除串接（`audit-failed`），稍後重試。
//!
//! 上限：同時最多 1 個、每 30 秒最多 1 個、只抽 1/16；記憶體壓力不是 `Normal`、沒對時、沒有串接時不做。
//! 抽查不改答案、不排 CDN 驗證、不寫 CDN 網域資料庫。

use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;

/// 抽樣：每 16 筆可以抽查的答案抽 1 筆
pub const SAMPLE: u32 = 16;
/// 兩次抽查最少間隔（秒）
pub const MIN_GAP_SECS: u64 = 30;
/// 可疑幾次就解除串接
pub const SUSPICIOUS_LIMIT: usize = 3;
/// 可疑的累積期間（毫秒）
pub const WINDOW_MS: u64 = 3600 * 1000;
/// 串接中的機房抽查（3.5.0 E4）：搭答案抽查的名額，另外再限兩次之間的間隔（秒）與每天幾個；
/// `cdn.lite`（小機器減量）時放寬間隔、減少個數（減量，不是關掉）
pub const POP_GAP_SECS: u64 = 600;
pub const POP_DAY_MAX: u32 = 24;
pub const POP_GAP_SECS_LITE: u64 = 1800;
pub const POP_DAY_MAX_LITE: u32 = 8;

/// 一次抽查的結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// 上游給的 IP 憑證有效
    Valid,
    /// 連不上、逾時、自己的上游沒有答案：不判斷
    Unverified,
    /// 上游給的與自己拿到的都不符：網站本身的問題
    SiteInvalid,
    /// 上游給的不符、自己拿到的正常
    Suspicious,
}

#[derive(Default)]
struct State {
    sampled: u64,
    valid: u64,
    unverified: u64,
    site_invalid: u64,
    suspicious: u64,
    /// 累積期間內的可疑（毫秒時間）
    recent: VecDeque<u64>,
    last: Option<Value>,
    /// 因為抽查解除串接的次數
    releases: u64,
    /// 機房抽查（E4）：上一次的單調時鐘秒、今天（單調時鐘的日序）做了幾個、累計
    pop_last: Option<u64>,
    pop_day: u64,
    pop_today: u32,
    pop_probes: u64,
}

pub struct Audit {
    tick: AtomicU32,
    busy: AtomicBool,
    /// 上一次開始抽查（單調時鐘秒；0 = 還沒有）。32 位元：MIPS 沒有 64 位元原子操作
    last_start: AtomicU32,
    st: Mutex<State>,
}

/// 行程層級（跨重新載入；同 `chain::CURRENT`）
pub static AUDIT: Audit = Audit::new();

/// 一次抽查的名額：丟掉時一定還回去（工作 panic、被取消也一樣）
pub struct Slot(&'static Audit);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
    }
}

impl Audit {
    pub const fn new() -> Audit {
        Audit {
            tick: AtomicU32::new(0),
            busy: AtomicBool::new(false),
            last_start: AtomicU32::new(0),
            st: Mutex::new(State {
                sampled: 0,
                valid: 0,
                unverified: 0,
                site_invalid: 0,
                suspicious: 0,
                recent: VecDeque::new(),
                last: None,
                releases: 0,
                pop_last: None,
                pop_day: 0,
                pop_today: 0,
                pop_probes: 0,
            }),
        }
    }

    /// 這一筆要不要抽查（抽樣、間隔、同時一個）。要的話拿到名額；`now_s` 是單調時鐘秒
    pub fn claim(&'static self, now_s: u64) -> Option<Slot> {
        if self.tick.fetch_add(1, Ordering::Relaxed) % SAMPLE != 0 {
            return None;
        }
        let now_s = now_s.min(u32::MAX as u64) as u32;
        let last = self.last_start.load(Ordering::Relaxed);
        if last != 0 && (now_s as u64) < last as u64 + MIN_GAP_SECS {
            return None;
        }
        if self.busy.swap(true, Ordering::AcqRel) {
            return None;
        }
        self.last_start.store(now_s.max(1), Ordering::Relaxed);
        Some(Slot(self))
    }

    /// 記一次結果；回傳要不要解除串接（累積期間內可疑達到上限，同時清掉累積）
    pub fn record(&self, outcome: Outcome, name: &str, ip: &str, now_ms: u64) -> bool {
        let mut st = self.st.lock().unwrap();
        st.sampled += 1;
        match outcome {
            Outcome::Valid => st.valid += 1,
            Outcome::Unverified => st.unverified += 1,
            Outcome::SiteInvalid => st.site_invalid += 1,
            Outcome::Suspicious => {
                st.suspicious += 1;
                st.last = Some(json!({ "name": name, "ip": ip, "at": now_ms }));
                st.recent.push_back(now_ms);
            }
        }
        while st.recent.front().is_some_and(|&t| now_ms.saturating_sub(t) > WINDOW_MS) {
            st.recent.pop_front();
        }
        if st.recent.len() >= SUSPICIOUS_LIMIT {
            st.recent.clear();
            st.releases += 1;
            return true;
        }
        false
    }

    /// 機房抽查（3.5.0 E4）還有沒有名額：10 分鐘最多 1 個、一天最多 24 個（`lite`：30 分鐘 1 個、一天 8 個）。
    /// 只在拿著答案抽查的名額（[`Audit::claim`]，同時一個）時呼叫，所以「看名額 → 記一次」不會兩個同時
    pub fn pop_allowed(&self, now_s: u64, lite: bool) -> bool {
        let (gap, max) = if lite {
            (POP_GAP_SECS_LITE, POP_DAY_MAX_LITE)
        } else {
            (POP_GAP_SECS, POP_DAY_MAX)
        };
        let st = self.st.lock().unwrap();
        let today = if st.pop_day == now_s / 86_400 { st.pop_today } else { 0 };
        today < max && st.pop_last.map_or(true, |t| now_s >= t + gap)
    }

    /// 做了一次機房抽查
    pub fn pop_note(&self, now_s: u64) {
        let mut st = self.st.lock().unwrap();
        let day = now_s / 86_400;
        if st.pop_day != day {
            st.pop_day = day;
            st.pop_today = 0;
        }
        st.pop_today += 1;
        st.pop_probes += 1;
        st.pop_last = Some(now_s);
    }

    /// `/api/status` 的 `chain.audit`
    pub fn status_json(&self) -> Value {
        let st = self.st.lock().unwrap();
        json!({
            "sampled": st.sampled,
            "valid": st.valid,
            "unverified": st.unverified,
            "siteInvalid": st.site_invalid,
            "suspicious": st.suspicious,
            "recentSuspicious": st.recent.len(),
            "releases": st.releases,
            "last": st.last,
            // 3.5.0 E4：串接中的機房抽查（累計、今天）
            "popProbes": st.pop_probes,
            "popProbesToday": st.pop_today,
        })
    }
}

impl Default for Audit {
    fn default() -> Self {
        Audit::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_samples_spaces_and_is_single() {
        static A: Audit = Audit::new();
        // 第 1 筆就抽（tick 0），之後 15 筆不抽
        let s = A.claim(1000).expect("第一筆");
        assert!((0..15).all(|_| A.claim(1000).is_none()));
        // 下一個抽樣點，但還在 30 秒內：不抽；也不能跟進行中的同時
        assert!(A.claim(1010).is_none());
        drop(s);
        for _ in 0..15 {
            assert!(A.claim(1040).is_none());
        }
        assert!(A.claim(1040).is_some(), "隔 30 秒以上、名額還回來了");
    }

    #[test]
    fn three_suspicious_within_an_hour_releases_once() {
        let a = Audit::new();
        let h = WINDOW_MS;
        assert!(!a.record(Outcome::Suspicious, "a.example", "192.0.2.1", 1_000));
        assert!(!a.record(Outcome::Valid, "b.example", "192.0.2.2", 2_000));
        // 第一次可疑已經超過 1 小時：不算
        assert!(!a.record(Outcome::Suspicious, "c.example", "192.0.2.3", 1_000 + h + 10));
        assert!(!a.record(Outcome::Suspicious, "d.example", "192.0.2.4", 1_000 + h + 20));
        assert!(
            a.record(Outcome::Suspicious, "e.example", "192.0.2.5", 1_000 + h + 30),
            "1 小時內第 3 次"
        );
        // 解除後清掉累積：再一次可疑不會馬上又解除
        assert!(!a.record(Outcome::Suspicious, "f.example", "192.0.2.6", 1_000 + h + 40));
        let s = a.status_json();
        assert_eq!(
            (s["sampled"].as_u64(), s["suspicious"].as_u64(), s["releases"].as_u64()),
            (Some(6), Some(5), Some(1))
        );
        assert_eq!(s["last"]["name"], "f.example");
        assert!(!a.record(Outcome::SiteInvalid, "g.example", "192.0.2.7", 1_000 + h + 50));
        assert!(!a.record(Outcome::Unverified, "h.example", "192.0.2.8", 1_000 + h + 60));
        assert_eq!(a.status_json()["siteInvalid"], 1);
    }

    /// 3.5.0 E4：機房抽查搭答案抽查的名額，另外 10 分鐘 1 個、一天 24 個；cdn.lite 是 30 分鐘 1 個、一天 8 個
    #[test]
    fn chained_pop_probe_uses_audit_slot_and_is_capped() {
        let a = Audit::new();
        let t0 = 10 * 86_400;
        assert!(a.pop_allowed(t0, false));
        a.pop_note(t0);
        assert!(!a.pop_allowed(t0 + 599, false), "10 分鐘內不再一個");
        assert!(a.pop_allowed(t0 + 600, false));
        let mut t = t0;
        for _ in 1..POP_DAY_MAX {
            t += 600;
            assert!(a.pop_allowed(t, false));
            a.pop_note(t);
        }
        assert!(!a.pop_allowed(t + 600, false), "一天最多 24 個");
        assert_eq!(a.status_json()["popProbes"], 24);
        assert!(a.pop_allowed(t0 + 86_400, false), "隔天重新算");
        // 小機器減量
        let b = Audit::new();
        b.pop_note(t0);
        assert!(!b.pop_allowed(t0 + 600, true));
        assert!(b.pop_allowed(t0 + 1800, true));
        for k in 1..POP_DAY_MAX_LITE as u64 {
            b.pop_note(t0 + k * 1800);
        }
        assert!(!b.pop_allowed(t0 + 20 * 1800, true), "lite 一天 8 個");
        assert!(b.pop_allowed(t0 + 20 * 1800, false));
    }
}
