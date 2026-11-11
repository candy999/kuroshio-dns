//! 資料品質分數（規格 03 第 8.2 節，取代 v1 的違規次數）
//!
//! 每個好友、每種 kind 各自計分：本機驗證結果分成 ok / fail / invalid，只算最近 14 天。
//! 分數 = (ok + 1) / (ok + fail + invalid × 3 + 2)
//! 分數低於 minHitRate、而且至少試過 20 次 → 這種資料暫停採用，每 3 天放一小批重新試，好了就恢復。
//! 品質差不等於惡意：分數再低也不會封鎖。

use crate::util::DAY;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const WINDOW_DAYS: u32 = 14;
pub const MIN_TRIES: u32 = 20;
pub const RETRY_EVERY_MS: u64 = 3 * DAY;
/// 暫停期間每次重新試的筆數
pub const RETRY_BATCH: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Node,
    Site,
    Cross,
    Upstream,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::Node, Kind::Site, Kind::Cross, Kind::Upstream];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Node => "node",
            Kind::Site => "site",
            Kind::Cross => "cross",
            Kind::Upstream => "upstream",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// 本機驗證可用
    Ok,
    /// 本機驗證不可用
    Fail,
    /// 格式錯誤、私有 / 保留位址
    Invalid,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KindScore {
    /// 每天一筆：[日（Unix 天數）, ok, fail, invalid]
    #[serde(default)]
    pub days: Vec<[u32; 4]>,
    #[serde(default)]
    pub paused: bool,
    #[serde(default)]
    pub paused_at: u64,
    #[serde(default)]
    pub last_retry: u64,
}

fn day_of(ms: u64) -> u32 {
    (ms / DAY) as u32
}

impl KindScore {
    pub fn add(&mut self, o: Outcome, n: u32, now: u64) {
        if n == 0 {
            return;
        }
        let d = day_of(now);
        if self.days.last().map(|x| x[0]) != Some(d) {
            self.days.push([d, 0, 0, 0]);
        }
        let last = self.days.last_mut().unwrap();
        let i = match o {
            Outcome::Ok => 1,
            Outcome::Fail => 2,
            Outcome::Invalid => 3,
        };
        last[i] = last[i].saturating_add(n);
        self.prune(now);
    }

    pub fn prune(&mut self, now: u64) {
        let from = day_of(now).saturating_sub(WINDOW_DAYS - 1);
        self.days.retain(|x| x[0] >= from);
    }

    /// 最近 14 天的 (ok, fail, invalid)
    pub fn totals(&self, now: u64) -> (u32, u32, u32) {
        let from = day_of(now).saturating_sub(WINDOW_DAYS - 1);
        self.days.iter().filter(|x| x[0] >= from).fold((0u32, 0u32, 0u32), |a, x| {
            (a.0.saturating_add(x[1]), a.1.saturating_add(x[2]), a.2.saturating_add(x[3]))
        })
    }

    pub fn tries(&self, now: u64) -> u32 {
        let (o, f, i) = self.totals(now);
        o.saturating_add(f).saturating_add(i)
    }

    pub fn score(&self, now: u64) -> f64 {
        let (ok, fail, inv) = self.totals(now);
        (ok as f64 + 1.0) / (ok as f64 + fail as f64 + inv as f64 * 3.0 + 2.0)
    }

    /// 依門檻更新暫停狀態；回傳狀態有沒有改變
    pub fn evaluate(&mut self, min_hit_rate: f64, now: u64) -> bool {
        let low = min_hit_rate > 0.0 && self.tries(now) >= MIN_TRIES && self.score(now) < min_hit_rate;
        if low && !self.paused {
            self.paused = true;
            self.paused_at = now;
            self.last_retry = now;
            return true;
        }
        if !low && self.paused {
            self.paused = false;
            return true;
        }
        false
    }

    /// 這次可以採用幾筆：沒暫停 → 不限；暫停中每 3 天放一小批
    pub fn allowance(&mut self, now: u64) -> Option<usize> {
        if !self.paused {
            return None;
        }
        if now.saturating_sub(self.last_retry) >= RETRY_EVERY_MS {
            self.last_retry = now;
            return Some(RETRY_BATCH);
        }
        Some(0)
    }
}

/// 一個好友的四種分數
pub type Reputation = BTreeMap<String, KindScore>;

pub fn entry(r: &mut Reputation, k: Kind) -> &mut KindScore {
    r.entry(k.as_str().to_string()).or_default()
}

pub fn is_paused(r: &Reputation, k: Kind) -> bool {
    r.get(k.as_str()).map(|s| s.paused).unwrap_or(false)
}

pub fn score_of(r: &Reputation, k: Kind, now: u64) -> f64 {
    r.get(k.as_str()).map(|s| s.score(now)).unwrap_or(0.5)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formula_and_window() {
        let mut s = KindScore::default();
        let t0 = 100 * DAY;
        assert_eq!(s.score(t0), 0.5);
        s.add(Outcome::Ok, 8, t0);
        s.add(Outcome::Fail, 2, t0);
        s.add(Outcome::Invalid, 1, t0);
        // (8+1)/(8+2+3+2)
        assert!((s.score(t0) - 9.0 / 15.0).abs() < 1e-9);
        // 15 天後全部過期
        assert_eq!(s.totals(t0 + 15 * DAY), (0, 0, 0));
    }

    #[test]
    fn pause_retry_resume() {
        let mut s = KindScore::default();
        let t0 = 200 * DAY;
        s.add(Outcome::Fail, 19, t0);
        assert!(!s.evaluate(0.5, t0), "未滿 20 次不暫停");
        s.add(Outcome::Fail, 1, t0);
        assert!(s.evaluate(0.5, t0));
        assert!(s.paused);
        assert_eq!(s.allowance(t0 + DAY), Some(0));
        assert_eq!(s.allowance(t0 + 3 * DAY), Some(RETRY_BATCH));
        assert_eq!(s.allowance(t0 + 3 * DAY + 1), Some(0));
        s.add(Outcome::Ok, 60, t0 + 3 * DAY);
        assert!(s.evaluate(0.5, t0 + 3 * DAY));
        assert!(!s.paused);
        assert_eq!(s.allowance(t0 + 3 * DAY), None);
        // 0 = 不檢查
        let mut z = KindScore::default();
        z.add(Outcome::Invalid, 100, t0);
        assert!(!z.evaluate(0.0, t0));
    }
}
