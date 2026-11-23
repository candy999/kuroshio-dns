//! 新網域很多時的 CDN 驗證節流（3.5.0 F12，規格 11 第 6 節）：純邏輯，時間與 CPU 讀數由呼叫端給（測試可以注入）。
//!
//! - 每分鐘上限 `Rmax`（固定一分鐘一格，不留佇列：排不進的丟掉，下一次查詢再排）。
//! - 目前的速率 `r` 依 CPU 自己調：55% 以上減半、30% 以下（或量不到）加 `Rmax ÷ 10`、中間不動；永遠在 `[Rmin, Rmax]`，
//!   `Rmin = max(6, Rmax ÷ 8)`；記憶體壓力不是 Normal → `Rmin`。每 10 秒最多調一次。
//! - 名額的順序（不排隊，用「留給前面的」實作）：手動不受限但算進用量；第 2 類（重驗、問過 2 次以上）用全部名額；
//!   跨 CDN 探索用到四分之三（最後四分之一留給第 2 類）；只問過一次的新網域用到一半（另一半留給第 2 類），
//!   而且減量中根本不排（在 `apply()` 就拿掉）。
//! - 「減量中」：這一分鐘有排不進的、或 `r < Rmax` → 進入；連續 5 分鐘都沒有排不進的、而且 `r` 回到 `Rmax` → 離開。
//!
//! 全部在 `Cdn` 既有的 `bg` 鎖裡（`schedule()` 本來就拿），沒有新的鎖；時間戳（64 位元）也在鎖裡。

/// CPU 佔比到這裡以上：`r` 減半
pub const CPU_HIGH: u8 = 55;
/// CPU 佔比低於這裡：`r` 加 `Rmax ÷ 10`
pub const CPU_LOW: u8 = 30;
/// 兩次調整之間至少隔多久（主程式每 10 秒量一次；留一點誤差）
pub const ADJUST_GAP_MS: u64 = 9_000;
/// 連續幾分鐘都沒有排不進、而且 `r` 回到 `Rmax`，才離開減量中
pub const QUIET_MINUTES: u32 = 5;
/// `Rmin` 的絕對下限（每分鐘）
pub const RMIN_FLOOR: u32 = 6;

/// 一個工作屬於哪一類（名額的順序）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cat {
    /// 手動 `POST /api/cdn/verify`：不受名額限制，但算進用量
    Manual,
    /// 已經有驗證結果、到期重驗（含 F9 的確認與重驗）、問過 2 次以上的新網域：可以用全部名額
    Regular,
    /// 跨 CDN 探索：每次 1 個名額，用到四分之三
    Cross,
    /// 只問過 1 次的新網域：用到一半；減量中不排（在 `apply()` 就拿掉，不會走到這裡）
    FirstSeen,
}

/// 狀態轉換（呼叫端寫日誌）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    Enter,
    Leave,
}

#[derive(Debug, Clone)]
pub struct Pace {
    pub rmax: u32,
    pub rmin: u32,
    /// 目前的速率（每分鐘）
    pub rate: u32,
    /// 這一格是哪一分鐘（Unix 分鐘）、用了幾個
    minute: u32,
    used: u32,
    /// 上一格（剛好前一分鐘）用了幾個；不是剛好前一分鐘時是 0
    prev_used: u32,
    /// 最近一次「忙」（排不進、或 `r < Rmax`）在哪一分鐘
    last_busy: Option<u32>,
    pub paced: bool,
    /// 進入減量中的時間（毫秒）
    pub since: u64,
    last_adjust: u64,
    /// 主程式交進來的 CPU 佔比（None = 量不到或還沒交）
    pub cpu: Option<u8>,
    /// 名額用完沒排的累計
    pub capped: u32,
}

pub fn rmin_of(rmax: u32) -> u32 {
    (rmax / 8).max(RMIN_FLOOR).min(rmax.max(1))
}

fn minute_of(now: u64) -> u32 {
    (now / 60_000).min(u32::MAX as u64) as u32
}

impl Pace {
    pub fn new(rmax: u32) -> Pace {
        let rmax = rmax.max(1);
        Pace {
            rmax,
            rmin: rmin_of(rmax),
            rate: rmax,
            minute: 0,
            used: 0,
            prev_used: 0,
            last_busy: None,
            paced: false,
            since: 0,
            last_adjust: 0,
            cpu: None,
            capped: 0,
        }
    }

    /// 換到現在這一分鐘；看要不要離開減量中
    pub fn roll(&mut self, now: u64) -> Option<Transition> {
        let m = minute_of(now);
        if m != self.minute {
            self.prev_used = if m == self.minute.wrapping_add(1) { self.used } else { 0 };
            self.minute = m;
            self.used = 0;
        }
        if self.rate < self.rmax {
            self.last_busy = Some(m);
        }
        if self.paced && self.rate >= self.rmax && quiet(self.last_busy, m) {
            self.paced = false;
            self.since = 0;
            return Some(Transition::Leave);
        }
        None
    }

    fn busy(&mut self, now: u64) -> Option<Transition> {
        self.last_busy = Some(minute_of(now));
        if self.paced {
            return None;
        }
        self.paced = true;
        self.since = now;
        Some(Transition::Enter)
    }

    /// 這一分鐘還有沒有這一類的名額；有就用掉一個。回（排不排，狀態轉換）
    pub fn take(&mut self, cat: Cat, now: u64) -> (bool, Option<Transition>) {
        let t = self.roll(now);
        let r = self.rate;
        let limit = match cat {
            Cat::Manual => u32::MAX,
            Cat::Regular => r,
            Cat::Cross => (r * 3 / 4).max(1),
            Cat::FirstSeen => (r / 2).max(1),
        };
        if self.used < limit {
            self.used = self.used.saturating_add(1);
            return (true, t);
        }
        self.capped = self.capped.saturating_add(1);
        (false, self.busy(now).or(t))
    }

    /// 主程式每 10 秒交一次 CPU 佔比（`None` = 量不到：不依 CPU 降，低於 Rmax 時照「CPU 低」慢慢升回去）與記憶體壓力
    pub fn load(&mut self, pct: Option<u8>, memory_normal: bool, now: u64) -> Option<Transition> {
        self.cpu = pct;
        if self.last_adjust != 0 && now.saturating_sub(self.last_adjust) < ADJUST_GAP_MS {
            return self.roll(now);
        }
        self.last_adjust = now;
        if !memory_normal {
            self.rate = self.rmin;
        } else if let Some(p) = pct {
            if p >= CPU_HIGH {
                self.rate = (self.rate / 2).max(self.rmin);
            } else if p < CPU_LOW {
                self.rate = self.rate.saturating_add((self.rmax / 10).max(1)).min(self.rmax);
            }
        } else if self.rate < self.rmax {
            // 量不到 CPU：不依 CPU 降，但記憶體壓力解除之後要回得去 Rmax（跟 CPU 低的時候一樣慢慢升，不會卡在 Rmin）
            self.rate = self.rate.saturating_add((self.rmax / 10).max(1)).min(self.rmax);
        }
        let t = self.roll(now);
        if self.rate < self.rmax {
            return self.busy(now).or(t);
        }
        t
    }

    /// 上一分鐘（剛好前一分鐘）用了幾個、這一分鐘到現在用了幾個
    pub fn used(&self, now: u64) -> (u32, u32) {
        let m = minute_of(now);
        if m == self.minute {
            (self.prev_used, self.used)
        } else if m == self.minute.wrapping_add(1) {
            (self.used, 0)
        } else {
            (0, 0)
        }
    }

    /// 重新設定上限（設定沒變時不會呼叫；保留計數）
    pub fn set_rmax(&mut self, rmax: u32) {
        let rmax = rmax.max(1);
        self.rmax = rmax;
        self.rmin = rmin_of(rmax);
        self.rate = self.rate.clamp(self.rmin, self.rmax);
    }
}

/// `last_busy` 是不是已經過了 [`QUIET_MINUTES`] 分鐘（沒有紀錄算是）
fn quiet(last_busy: Option<u32>, m: u32) -> bool {
    match last_busy {
        None => true,
        Some(b) => m.saturating_sub(b) > QUIET_MINUTES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_800_000_000_000;
    const MIN: u64 = 60_000;

    #[test]
    fn rmin_is_eighth_but_at_least_6() {
        assert_eq!(rmin_of(60), 7);
        assert_eq!(rmin_of(30), 6);
        assert_eq!(rmin_of(480), 60);
        assert_eq!(rmin_of(6), 6);
        assert_eq!(rmin_of(3), 3, "不超過 Rmax");
    }

    #[test]
    fn categories_reserve_for_regular() {
        let mut p = Pace::new(60);
        let n = |p: &mut Pace, cat: Cat, k: usize| (0..k).filter(|_| p.take(cat, T0).0).count();
        assert_eq!(n(&mut p, Cat::FirstSeen, 100), 30, "只問過一次的最多一半");
        assert!(p.paced, "有排不進的：進入減量中");
        assert_eq!(n(&mut p, Cat::Cross, 100), 15, "跨 CDN 用到四分之三");
        assert_eq!(n(&mut p, Cat::Regular, 100), 15, "第 2 類用剩下的全部");
        assert_eq!(n(&mut p, Cat::Manual, 5), 5, "手動不受限");
        assert_eq!(p.used(T0), (0, 65), "手動算進用量");
        // 下一分鐘重算
        assert!(p.take(Cat::Regular, T0 + MIN).0);
        assert_eq!(p.used(T0 + MIN), (65, 1));
    }

    #[test]
    fn pace_halves_at_55_and_grows_by_tenth_below_30_and_holds_between() {
        let mut p = Pace::new(60);
        let mut t = T0;
        let mut step = |p: &mut Pace, pct: u8| {
            t += 10_000;
            p.load(Some(pct), true, t);
            p.rate
        };
        assert_eq!(step(&mut p, 55), 30, "55% 以上減半");
        assert_eq!(step(&mut p, 40), 30, "中間不動");
        assert_eq!(step(&mut p, 54), 30);
        assert_eq!(step(&mut p, 30), 30, "30% 不算低於 30%");
        assert_eq!(step(&mut p, 29), 36, "低於 30%：加 Rmax ÷ 10");
        assert_eq!(step(&mut p, 0), 42);
        // 每 10 秒最多調一次
        p.load(Some(99), true, t + 1_000);
        assert_eq!(p.rate, 42);
        assert_eq!(p.cpu, Some(99), "讀數照記");
    }

    #[test]
    fn pace_bounded_by_rmin_rmax() {
        let mut p = Pace::new(60);
        let mut t = T0;
        for _ in 0..20 {
            t += 10_000;
            p.load(Some(100), true, t);
            assert!(p.rate >= p.rmin);
        }
        assert_eq!(p.rate, p.rmin);
        for _ in 0..40 {
            t += 10_000;
            p.load(Some(1), true, t);
            assert!(p.rate <= p.rmax);
        }
        assert_eq!(p.rate, p.rmax);
        // 降得快、升得慢：60 → 7 只要 3 次；7 → 60 要 9 次（約 1.5 分鐘）
        let mut p = Pace::new(60);
        let mut n = 0;
        while p.rate > p.rmin {
            t += 10_000;
            p.load(Some(90), true, t);
            n += 1;
        }
        assert_eq!(n, 3);
        let mut n = 0;
        while p.rate < p.rmax {
            t += 10_000;
            p.load(Some(10), true, t);
            n += 1;
        }
        assert_eq!(n, 9);
    }

    #[test]
    fn pace_drops_to_rmin_under_memory_pressure() {
        let mut p = Pace::new(60);
        assert_eq!(p.load(Some(1), false, T0), Some(Transition::Enter));
        assert_eq!((p.rate, p.paced), (p.rmin, true), "記憶體壓力：Rmin，不停止驗證");
        // CPU 量不到也一樣
        let mut p = Pace::new(60);
        p.load(None, false, T0);
        assert_eq!(p.rate, p.rmin);
        // 壓力解除：照 CPU 慢慢升回來
        p.load(Some(10), true, T0 + 10_000);
        assert_eq!(p.rate, p.rmin + 6);
        // CPU 量不到也會回到 Rmax（不卡在 Rmin），然後 5 分鐘後離開減量中
        let mut p = Pace::new(60);
        p.load(None, false, T0);
        let mut t = T0;
        let mut left = false;
        for _ in 0..60 {
            t += 10_000;
            left |= p.load(None, true, t) == Some(Transition::Leave);
        }
        assert_eq!(p.rate, 60);
        assert!(left && !p.paced);
    }

    #[test]
    fn cpu_unreadable_keeps_rmax() {
        let mut p = Pace::new(60);
        for i in 1..30 {
            assert_eq!(p.load(None, true, T0 + i * 10_000), None);
        }
        assert_eq!((p.rate, p.paced, p.cpu), (60, false, None));
    }

    #[test]
    fn paced_enters_once_and_leaves_after_five_quiet_minutes() {
        let mut p = Pace::new(10);
        let mut enters = 0;
        let mut leaves = 0;
        let mut count = |t: Option<Transition>| match t {
            Some(Transition::Enter) => enters += 1,
            Some(Transition::Leave) => leaves += 1,
            None => {}
        };
        // 3 分鐘一直灌新網域：只進入一次（日誌一行）
        for m in 0..3 {
            for _ in 0..30 {
                count(p.take(Cat::FirstSeen, T0 + m * MIN).1);
            }
        }
        assert!(p.paced);
        // 停了之後：前 5 分鐘還在減量中
        for m in 3..=7 {
            count(p.roll(T0 + m * MIN));
            assert!(p.paced, "第 {m} 分鐘");
        }
        // 第 2 分鐘最後一次排不進；第 3～7 分鐘都沒有 → 第 8 分鐘離開（日誌一行）
        count(p.roll(T0 + 8 * MIN));
        assert!(!p.paced);
        count(p.roll(T0 + 9 * MIN));
        assert_eq!((enters, leaves), (1, 1));
        // 速率沒有回到 Rmax：不離開
        let mut p = Pace::new(60);
        let mut t = T0;
        p.load(Some(90), true, t);
        assert!(p.paced);
        for _ in 0..60 {
            t += 10_000;
            p.load(Some(40), true, t);
        }
        assert!(p.paced, "CPU 在中間，速率停在 30：還在減量中");
        // 降到 30% 以下：約 1 分鐘回到 Rmax，再 5 分鐘離開
        let mut left_at = None;
        for i in 0..60 {
            t += 10_000;
            if p.load(Some(10), true, t) == Some(Transition::Leave) {
                left_at = Some(i);
            }
        }
        let i = left_at.expect("壓力解除後自己離開");
        assert!((30..=48).contains(&i), "{i}");
    }

    #[test]
    fn no_backlog_after_load_stops() {
        // 沒有佇列：排不進的不記，下一分鐘不會湧出積壓的工作
        let mut p = Pace::new(10);
        let n = (0..100).filter(|_| p.take(Cat::Regular, T0).0).count();
        assert_eq!(n, 10);
        assert_eq!(p.capped, 90);
        assert_eq!(p.used(T0 + MIN), (10, 0), "下一分鐘從 0 開始，沒有東西自己跑出來");
    }
}
