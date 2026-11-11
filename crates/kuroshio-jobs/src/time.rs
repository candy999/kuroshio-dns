//! 時間：排程一律用台北時間（UTC+8，沒有日光節約，同 2.x 的 `taipeiParts`）。
//! 時鐘可以注入（`Clock`），測試不必等真的時間過去。

use std::sync::Mutex;

pub const SEC_MS: u64 = 1000;
pub const MIN_MS: u64 = 60 * SEC_MS;
pub const HOUR_MS: u64 = 60 * MIN_MS;
pub const DAY_MS: u64 = 24 * HOUR_MS;
/// 台北時間與 UTC 的差
pub const TPE_OFFSET_MS: u64 = 8 * HOUR_MS;

/// 牆上時鐘（Unix 毫秒）
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// 系統時鐘
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// 手動時鐘（測試用）。32 位元 MIPS 沒有 64 位元原子操作，所以用 Mutex。
#[derive(Debug, Default)]
pub struct ManualClock(Mutex<u64>);

impl ManualClock {
    pub fn new(ms: u64) -> ManualClock {
        ManualClock(Mutex::new(ms))
    }
    pub fn set(&self, ms: u64) {
        *self.0.lock().unwrap() = ms;
    }
    pub fn advance(&self, ms: u64) {
        *self.0.lock().unwrap() += ms;
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        *self.0.lock().unwrap()
    }
}

/// 台北時間的各欄位
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpeParts {
    pub y: i64,
    pub mo: u32,
    pub d: u32,
    pub h: u32,
    pub mi: u32,
    pub s: u32,
    pub ms: u32,
    /// 0 = 星期日
    pub weekday: u32,
}

/// 由 1970-01-01 起算的天數換成年月日（Howard Hinnant 的演算法）
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 年月日換成由 1970-01-01 起算的天數
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn parts_at(ms: u64, offset: u64) -> TpeParts {
    let t = ms + offset;
    let days = (t / DAY_MS) as i64;
    let rem = t % DAY_MS;
    let (y, mo, d) = civil_from_days(days);
    TpeParts {
        y,
        mo,
        d,
        h: (rem / HOUR_MS) as u32,
        mi: (rem % HOUR_MS / MIN_MS) as u32,
        s: (rem % MIN_MS / SEC_MS) as u32,
        ms: (rem % SEC_MS) as u32,
        weekday: ((days + 4).rem_euclid(7)) as u32,
    }
}

pub fn taipei_parts(ms: u64) -> TpeParts {
    parts_at(ms, TPE_OFFSET_MS)
}

/// 台北時間當天 00:00 的 Unix 毫秒
pub fn taipei_midnight(ms: u64) -> u64 {
    let t = ms + TPE_OFFSET_MS;
    (t / DAY_MS * DAY_MS).saturating_sub(TPE_OFFSET_MS)
}

/// YYYY-MM-DD（台北）
pub fn local_date_str(ms: u64) -> String {
    let p = taipei_parts(ms);
    format!("{:04}-{:02}-{:02}", p.y, p.mo, p.d)
}

/// HH:MM:SS（台北）
pub fn fmt_time(ms: u64) -> String {
    let p = taipei_parts(ms);
    format!("{:02}:{:02}:{:02}", p.h, p.mi, p.s)
}

/// YYYY-MM-DD HH:MM:SS（台北）
pub fn fmt_date_time(ms: u64) -> String {
    format!("{} {}", local_date_str(ms), fmt_time(ms))
}

/// 同 JavaScript 的 `Date.prototype.toISOString()`（UTC，含毫秒）
pub fn iso_string(ms: u64) -> String {
    let p = parts_at(ms, 0);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", p.y, p.mo, p.d, p.h, p.mi, p.s, p.ms)
}

/// `YYYY-MM-DD` 當成 UTC 午夜（同 JavaScript 的 `new Date('YYYY-MM-DD')`）
pub fn parse_date_utc(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let y: i64 = s[0..4].parse().ok()?;
    let m: u32 = s[5..7].parse().ok()?;
    let d: u32 = s[8..10].parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let days = days_from_civil(y, m, d);
    (days >= 0).then(|| days as u64 * DAY_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taipei_fields() {
        // 2025-11-09T16:30:00Z = 台北 2025-11-10 00:30，星期一
        let t = 1_762_705_800_000;
        assert_eq!(iso_string(t), "2025-11-09T16:30:00.000Z");
        let p = taipei_parts(t);
        assert_eq!((p.y, p.mo, p.d, p.h, p.mi), (2025, 11, 10, 0, 30));
        assert_eq!(p.weekday, 1);
        assert_eq!(local_date_str(t), "2025-11-10");
        assert_eq!(fmt_date_time(t), "2025-11-10 00:30:00");
        assert_eq!(taipei_midnight(t), t - 30 * MIN_MS);
        assert_eq!(parse_date_utc("1970-01-02"), Some(DAY_MS));
        assert_eq!(parse_date_utc("2025-11-10").map(local_date_str).as_deref(), Some("2025-11-10"));
        for days in [-1000i64, 0, 59, 365, 20_000, 30_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }
}
