//! 學到的永久黑名單（`state/blacklist.txt`）的整理（3.5.1，規格 11 的 A10.4）。
//!
//! 一行一台：`<id>  # <YYYY-MM-DD> <原因>`。原因裡有「憑證不符」的、手動加的、沒有日期的：永久（要手動刪）。
//! 原因裡有「網站無法驗證」的：列入之後 30～60 天（依 id 雜湊分散）自動重測一次，通過就移除。
//! 沒通過時照列入的標準判斷（3.5.1 第二版之後）：憑證不符的改成永久；「網站無法驗證」的可疑紀錄夠格列入
//! （30 天內不同的 3 天、2 個以上網域）才留著、從那天重新算，不夠格就移出、這次的失敗照一般規則記進可疑紀錄
//! （以前一天、一個網站逾時就又留 30～60 天，重測的門檻比列入的還低）。資格賽或連線失敗（什麼都沒看到）算今天沒測到：
//! 留著，30～60 天後再試（不移出：移出等於每天白測一台可能已經不在的伺服器）。
//! 3.5.0 以前的規則列入的（文字是「連續 N 天網站無法驗證」）那時候比較容易誤判，升級後就排重測。
//! 每次評測最多重測 [`RETEST_PER_RUN`] 台；名單裡已經沒有的、超過 [`BLACKLIST_MAX`] 筆的移除。
//!
//! 程式附帶的唯讀名單（`data/benchmark/blacklist.txt`）不動。

use crate::time::days_from_civil;
use std::collections::{HashMap, HashSet};

/// 「網站無法驗證」列入之後最少幾天才重測
pub const RETEST_MIN_DAYS: u32 = 30;
/// 再加 0～30 天（依 id 雜湊）：合計 30～60 天，同一天列入的不會同一天一起重測
pub const RETEST_SPREAD: u32 = 31;
/// 每次評測最多重測幾台
pub const RETEST_PER_RUN: usize = 16;
/// 學到的永久黑名單最多幾筆（超過時先丟最舊的「無法驗證」，再丟最舊的其他）
pub const BLACKLIST_MAX: usize = 512;
/// 名單裡已經沒有的，列入超過幾天才移除（好友提供的候選每天不一樣，不要今天移除、明天又重新累積）
pub const PRUNE_AFTER_DAYS: u32 = 30;

/// 檔頭（3.5.1）
pub const HEADER: &str = "# 永久黑名單：每日評測判定竄改的 DNS，之後不再測試\n\
# 憑證不符的是永久的；「網站無法驗證」的列入 30～60 天後自動重測一次，通過就移除。要恢復某台就刪掉那一行\n";
/// 3.5.0 以前的檔頭（整理時換成新的）
const OLD_HEADER: [&str; 2] = [
    "# 永久黑名單：每日評測判定「汙染」（解析到錯誤業者）的 DNS，之後不再測試",
    "# 要恢復某台就刪掉那一行",
];

/// 一行的種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// 「網站無法驗證」：會重測
    Unverified,
    /// 憑證不符、回封鎖位址、手動加的：永久
    Permanent,
}

/// 一行
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    /// 列入那天（台北的日數）；沒有日期是 None
    pub day: Option<u32>,
    pub kind: Kind,
    /// 3.5.0 以前的規則列入的「網站無法驗證」（升級後就排重測）
    pub old_rule: bool,
    /// 原本的一整行
    pub line: String,
}

/// `YYYY-MM-DD` → 日數
pub fn parse_day(s: &str) -> Option<u32> {
    let b = s.as_bytes();
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let y: i64 = s.get(0..4)?.parse().ok()?;
    let m: u32 = s.get(5..7)?.parse().ok()?;
    let d: u32 = s.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    u32::try_from(days_from_civil(y, m, d)).ok()
}

/// 拆一行；註解、空行是 None
pub fn parse_line(line: &str) -> Option<Entry> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
        return None;
    }
    let (id, note) = match t.split_once('#') {
        Some((a, b)) => (a.trim(), b.trim()),
        None => (t, ""),
    };
    if id.is_empty() {
        return None;
    }
    let unverified = note.contains("網站無法驗證") && !note.contains("憑證不符");
    Some(Entry {
        id: id.to_string(),
        day: parse_day(note),
        kind: if unverified { Kind::Unverified } else { Kind::Permanent },
        old_rule: unverified && note.contains("連續"),
        line: t.to_string(),
    })
}

/// 這一筆的重測日（列入那天 + 30～60 天）
pub fn retest_day(id: &str, day: u32) -> u32 {
    // FNV-1a：固定、跨平台一樣
    let mut h: u32 = 0x811c_9dc5;
    for b in id.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    day.saturating_add(RETEST_MIN_DAYS + h % RETEST_SPREAD)
}

/// 今天該重測的（最舊的先，最多 [`RETEST_PER_RUN`] 台）。`skip`：程式附帶的名單也有的（那份是唯讀的，重測也拿不掉）
pub fn due(entries: &[Entry], today: u32, skip: impl Fn(&str) -> bool) -> Vec<String> {
    let mut v: Vec<(u32, &str)> = entries
        .iter()
        .filter(|e| e.kind == Kind::Unverified && !skip(&e.id))
        .filter_map(|e| {
            let d = e.day?;
            // 3.5.0 以前的規則列入的：升級後就排（照樣受每次的上限限制）；日期在未來（時間曾經跳過去）的也排
            (e.old_rule || d > today || today >= retest_day(&e.id, d)).then_some((d, e.id.as_str()))
        })
        .collect();
    v.sort();
    let mut seen = HashSet::new();
    v.into_iter()
        .filter(|(_, id)| seen.insert(*id))
        .map(|(_, id)| id.to_string())
        .take(RETEST_PER_RUN)
        .collect()
}

/// 重測的結果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retest {
    /// 通過（沒有汙染、可疑）：移除
    Passed,
    /// 沒通過、而且照列入的標準夠格（憑證不符；或可疑紀錄 30 天內 3 天、2 個網域）：留著、從今天重新算（`reason` 寫進那一行）
    Failed(String),
    /// 沒通過，但照列入的標準不夠格（可疑紀錄不夠、別的經營者也回同一個位址）：移出永久黑名單，
    /// 這次的失敗照一般規則記進可疑紀錄（之後夠格再列入）
    Released(String),
    /// 今天沒測到（路徑檢查略過、不支援）：不動，下次再試
    Untested,
    /// 資格賽或連線失敗（沒有「網站無法驗證」或憑證的證據）：也算今天沒測到，留著；
    /// 那一行的日期改成今天，30～60 天後再試（不然每次評測都會再排一次，天天白測一台可能已經不在的伺服器）
    Unreachable(String),
}

/// 整理的結果（寫進 judge.log）
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tidy {
    pub passed: usize,
    /// 沒通過、「網站無法驗證」夠格：留著、從今天重新算
    pub failed: usize,
    /// 沒通過、憑證不符：改成永久
    pub failed_cert: usize,
    /// 沒通過但不夠格：移出
    pub released: usize,
    pub untested: usize,
    /// 今天沒測到裡面，資格賽或連線失敗的（留著、30～60 天後再試）
    pub unreachable: usize,
    pub pruned: usize,
    pub capped: usize,
}

impl Tidy {
    pub fn any(&self) -> bool {
        self.passed + self.failed + self.failed_cert + self.released + self.pruned + self.capped > 0
    }
}

/// 整理一份學到的永久黑名單（純函式）：套用重測結果、移除名單裡已經沒有而且夠舊的、同一台重複的、超過上限的。
/// `known`：今天名單裡有的 id（原始寫法與正規化後的都要放）。回傳（新的內容, 統計）
pub fn tidy(text: &str, results: &HashMap<String, Retest>, known: impl Fn(&str) -> bool, today: u32, today_str: &str) -> (String, Tidy) {
    let mut st = Tidy::default();
    let mut comments: Vec<String> = Vec::new();
    let mut entries: Vec<Entry> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for raw in text.strip_prefix('\u{feff}').unwrap_or(text).lines() {
        let line = raw.trim_end_matches('\r');
        let Some(mut e) = parse_line(line) else {
            let t = line.trim();
            if !t.is_empty() && !OLD_HEADER.contains(&t) && !HEADER.lines().any(|h| h == t) {
                comments.push(t.to_string());
            }
            continue;
        };
        if !seen.insert(e.id.clone()) {
            continue;
        }
        match results.get(&e.id) {
            Some(Retest::Passed) => {
                st.passed += 1;
                continue;
            }
            Some(Retest::Released(_)) => {
                st.released += 1;
                continue;
            }
            Some(Retest::Failed(why)) => {
                let first = first_listed(&e.line).unwrap_or_else(|| e.line_date().unwrap_or_default());
                // 重測時憑證不符：改成永久的那一種
                let what = if why.contains("憑證不符") {
                    "憑證不符"
                } else {
                    "網站無法驗證"
                };
                e.line = format!(
                    "{}  # {today_str} 重測：{what}（{}；第一次列入 {first}）",
                    e.id,
                    why.replace(['\n', '#'], " ")
                );
                e.day = Some(today);
                e.old_rule = false;
                if what == "憑證不符" {
                    e.kind = Kind::Permanent;
                    st.failed_cert += 1;
                } else {
                    st.failed += 1;
                }
            }
            Some(Retest::Untested) => st.untested += 1,
            Some(Retest::Unreachable(why)) => {
                st.untested += 1;
                st.unreachable += 1;
                let first = first_listed(&e.line).unwrap_or_else(|| e.line_date().unwrap_or_default());
                // 照樣是「網站無法驗證」的那一種（`parse_line()` 看這幾個字）：30～60 天後再重測
                e.line = format!(
                    "{}  # {today_str} 重測：連不上（{}），網站無法驗證的判斷下次再試（第一次列入 {first}）",
                    e.id,
                    why.replace(['\n', '#'], " ")
                );
                e.day = Some(today);
                e.old_rule = false;
            }
            None => {}
        }
        // 名單裡已經沒有的：列入夠久（或沒有日期）才移除
        if !known(&e.id) && e.day.is_none_or_old(today) {
            st.pruned += 1;
            continue;
        }
        entries.push(e);
    }
    // 超過上限：先丟最舊的「無法驗證」，再丟最舊的其他（沒有日期的當成最舊）
    if entries.len() > BLACKLIST_MAX {
        let over = entries.len() - BLACKLIST_MAX;
        let mut order: Vec<(bool, u32, usize)> = entries
            .iter()
            .enumerate()
            .map(|(i, e)| (e.kind == Kind::Permanent, e.day.unwrap_or(0), i))
            .collect();
        order.sort();
        let drop: HashSet<usize> = order.into_iter().take(over).map(|(_, _, i)| i).collect();
        st.capped = drop.len();
        entries = entries
            .into_iter()
            .enumerate()
            .filter(|(i, _)| !drop.contains(i))
            .map(|(_, e)| e)
            .collect();
    }
    let mut out = String::from(HEADER);
    for c in comments {
        out.push_str(&c);
        out.push('\n');
    }
    for e in entries {
        out.push_str(&e.line);
        out.push('\n');
    }
    (out, st)
}

/// 「第一次列入 YYYY-MM-DD」
fn first_listed(line: &str) -> Option<String> {
    let at = line.find("第一次列入 ")? + "第一次列入 ".len();
    let d = line.get(at..at + 10)?;
    parse_day(d).map(|_| d.to_string())
}

impl Entry {
    /// 註解裡的日期字串
    fn line_date(&self) -> Option<String> {
        let note = self.line.split_once('#')?.1.trim();
        let d = note.get(0..10)?;
        parse_day(d).map(|_| d.to_string())
    }
}

trait OldDay {
    fn is_none_or_old(&self, today: u32) -> bool;
}

impl OldDay for Option<u32> {
    /// 沒有日期、或列入超過 [`PRUNE_AFTER_DAYS`] 天
    fn is_none_or_old(&self, today: u32) -> bool {
        self.is_none_or(|d| today >= d.saturating_add(PRUNE_AFTER_DAYS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(s: &str) -> u32 {
        parse_day(s).unwrap()
    }

    #[test]
    fn lines_are_classified() {
        let e = parse_line("192.0.2.1  # 2026-11-15 汙染：www.example.com → X__AS64500_X（連續 3 天網站無法驗證）").unwrap();
        assert_eq!((e.kind, e.old_rule, e.day), (Kind::Unverified, true, Some(day("2026-11-15"))));
        let e = parse_line("192.0.2.2  # 2026-11-26 汙染：www.example.com → X（30 天內 3 天、2 個網域網站無法驗證）").unwrap();
        assert_eq!((e.kind, e.old_rule), (Kind::Unverified, false));
        let e = parse_line(
            "https://dns.example.com/dns-query  # 2026-11-14 汙染：www.example.com → X（憑證不符 ERR_TLS_CERT_ALTNAME_INVALID）",
        )
        .unwrap();
        assert_eq!(e.kind, Kind::Permanent);
        let e = parse_line("198.51.100.1").unwrap();
        assert_eq!((e.kind, e.day), (Kind::Permanent, None), "手動加的");
        assert!(parse_line("# 註解").is_none() && parse_line("   ").is_none());
    }

    #[test]
    fn retest_is_30_to_60_days_and_capped() {
        let d0 = day("2026-11-26");
        for i in 0..200 {
            let r = retest_day(&format!("192.0.2.{i}"), d0);
            assert!((d0 + 30..=d0 + 60).contains(&r), "{r}");
        }
        let mut entries: Vec<Entry> = (0..40)
            .map(|i| {
                parse_line(&format!(
                    "198.51.100.{i}  # 2026-11-26 汙染：a → b（30 天內 3 天、2 個網域網站無法驗證）"
                ))
                .unwrap()
            })
            .collect();
        assert!(due(&entries, d0 + 29, |_| false).is_empty(), "30 天內不重測");
        assert_eq!(due(&entries, d0 + 60, |_| false).len(), RETEST_PER_RUN, "每次最多 16 台");
        // 3.5.0 以前的規則列入的：升級後就排；程式附帶名單也有的不排；憑證不符的永遠不排
        entries.push(parse_line("192.0.2.9  # 2026-11-15 汙染：a → b（連續 3 天網站無法驗證）").unwrap());
        entries.push(parse_line("192.0.2.10  # 2026-11-15 汙染：a → b（連續 3 天網站無法驗證）").unwrap());
        entries.push(parse_line("192.0.2.11  # 2026-10-01 汙染：a → b（憑證不符 X）").unwrap());
        assert_eq!(due(&entries, d0, |id| id == "192.0.2.10"), vec!["192.0.2.9".to_string()]);
    }

    #[test]
    fn tidy_applies_results_prunes_and_caps() {
        let today = day("2026-12-30");
        let text = "\u{feff}# 永久黑名單：每日評測判定「汙染」（解析到錯誤業者）的 DNS，之後不再測試\n# 要恢復某台就刪掉那一行\n\
192.0.2.1  # 2026-11-15 汙染：a → b（連續 3 天網站無法驗證）\n\
192.0.2.2  # 2026-11-15 汙染：a → b（連續 3 天網站無法驗證）\n\
192.0.2.3  # 2026-11-15 汙染：a → b（連續 3 天網站無法驗證）\n\
192.0.2.4  # 2026-11-14 汙染：a → b（憑證不符 X）\n\
192.0.2.4  # 2026-11-20 重複的\n\
192.0.2.5  # 2026-11-14 汙染：a → b（憑證不符 X）\n\
192.0.2.6  # 2026-12-25 汙染：a → b（憑證不符 X）\n\
192.0.2.7  # 2026-11-15 汙染：a → b（連續 3 天網站無法驗證）\n\
192.0.2.8  # 2026-11-15 汙染：a → b（連續 3 天網站無法驗證）\n\
192.0.2.9  # 2026-11-15 汙染：a → b（連續 3 天網站無法驗證）\n\
# 使用者自己的註解\n\
198.51.100.9\n";
        let mut r = HashMap::new();
        r.insert("192.0.2.1".to_string(), Retest::Passed);
        r.insert("192.0.2.2".to_string(), Retest::Failed("可疑 a".into()));
        r.insert("192.0.2.3".to_string(), Retest::Untested);
        // 連不上：留著、日期改成今天（30～60 天後再試）
        r.insert("192.0.2.9".to_string(), Retest::Unreachable("資格賽失敗 (逾時)".into()));
        // 沒通過但不夠列入的標準：移出（3.5.1 第二版之後）；重測時憑證不符：改成永久
        r.insert("192.0.2.7".to_string(), Retest::Released("可疑 a".into()));
        r.insert("192.0.2.8".to_string(), Retest::Failed("汙染 a (判定為 b，憑證不符 X)".into()));
        // 192.0.2.5 不在名單、列入超過 30 天 → 移除；192.0.2.6 不在名單但才 5 天 → 留著；手動加的 198.51.100.9 在名單裡
        let known = |id: &str| id != "192.0.2.5" && id != "192.0.2.6";
        let (out, st) = tidy(text, &r, known, today, "2026-12-30");
        assert_eq!(
            st,
            Tidy {
                passed: 1,
                failed: 1,
                failed_cert: 1,
                released: 1,
                untested: 2,
                unreachable: 1,
                pruned: 1,
                capped: 0
            }
        );
        assert!(out.starts_with(HEADER), "{out}");
        assert!(!out.contains("解析到錯誤業者"), "舊檔頭換掉：{out}");
        assert!(!out.contains("192.0.2.1 "), "{out}");
        assert!(
            out.contains("192.0.2.2  # 2026-12-30 重測：網站無法驗證（可疑 a；第一次列入 2026-11-15）"),
            "{out}"
        );
        assert!(out.contains("192.0.2.3  # 2026-11-15"), "沒測到的不動：{out}");
        assert!(!out.contains("192.0.2.7 "), "不夠格的移出：{out}");
        assert!(
            out.contains("192.0.2.9  # 2026-12-30 重測：連不上（資格賽失敗 (逾時)），網站無法驗證的判斷下次再試（第一次列入 2026-11-15）"),
            "{out}"
        );
        let e9 = parse_line(out.lines().find(|l| l.starts_with("192.0.2.9 ")).unwrap()).unwrap();
        assert_eq!((e9.kind, e9.old_rule, e9.day), (Kind::Unverified, false, Some(today)));
        assert!(due(&[e9], today + 1, |_| false).is_empty(), "隔天不再排");
        assert!(
            out.contains("192.0.2.8  # 2026-12-30 重測：憑證不符（汙染 a (判定為 b，憑證不符 X)；第一次列入 2026-11-15）"),
            "{out}"
        );
        assert_eq!(
            parse_line(out.lines().find(|l| l.starts_with("192.0.2.8 ")).unwrap()).unwrap().kind,
            Kind::Permanent
        );
        assert_eq!(out.matches("192.0.2.4 ").count(), 1, "重複的只留第一筆：{out}");
        assert!(!out.contains("192.0.2.5") && out.contains("192.0.2.6"), "{out}");
        assert!(out.contains("# 使用者自己的註解\n") && out.contains("198.51.100.9\n"));
        // 再重測一次又失敗：第一次列入的日期不變
        let mut r = HashMap::new();
        r.insert("192.0.2.2".to_string(), Retest::Failed("可疑 b".into()));
        let (out2, _) = tidy(&out, &r, known, today + 40, "2027-02-08");
        assert!(
            out2.contains("192.0.2.2  # 2027-02-08 重測：網站無法驗證（可疑 b；第一次列入 2026-11-15）"),
            "{out2}"
        );
        // 重測失敗的那一行照樣是「無法驗證」，下次照樣會重測（不是 3.5.0 以前的規則了）
        let e = parse_line(out2.lines().find(|l| l.starts_with("192.0.2.2 ")).unwrap()).unwrap();
        assert_eq!((e.kind, e.old_rule, e.day), (Kind::Unverified, false, Some(today + 40)));
        // 上限：先丟最舊的「無法驗證」
        let mut big = String::new();
        for i in 0..(BLACKLIST_MAX + 2) {
            big.push_str(&format!(
                "10.0.{}.{}  # 2026-12-{:02} 汙染：a → b（30 天內 3 天、2 個網域網站無法驗證）\n",
                i / 250,
                i % 250,
                1 + i % 28
            ));
        }
        big.push_str("10.9.9.9  # 2026-01-01 汙染：a → b（憑證不符 X）\n");
        let (out3, st3) = tidy(&big, &HashMap::new(), |_| true, today, "2026-12-30");
        assert_eq!(st3.capped, 3);
        assert!(out3.contains("10.9.9.9"), "憑證不符的最後才丟");
        assert_eq!(out3.lines().filter(|l| !l.starts_with('#')).count(), BLACKLIST_MAX);
    }
}
