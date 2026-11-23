//! 分級評測（3.5.0，規格 11 的 A3）：決定「今天測誰」
//!
//! `benchmark.tiers`：
//! - `ab`：全部都測（3.4.4 以前的行為）。
//! - `a`：小機器的減量。A 級＋使用者自己加的每天測；B 級只測少數幾種：
//!   - **沿用**：昨天選上或列為候補的（不然探索到的 B 級今天選上、明天又不測，執行中的上游每天換）；
//!   - **補位**（多樣性保護）：今天要測的 A 級經營者不到 [`OPS_MIN`] 家、或某一種類型不到 [`TYPE_MIN`] 個時，
//!     從 B 級補，最多 [`B_FILL_MAX`] 個、同一個經營者最多 [`FILL_PER_OP`] 個；
//!   - **探索**：每天輪 [`B_EXPLORE_MAX`] 個，B 級才有機會累積歷史。
//! - `auto`：由主程式依實體記憶體換算（`benchjob.rs`）。
//!
//! 這裡只決定測不測：不測的 B 級不算淘汰、不記任何紀錄（跟路徑檢查略過一樣）；
//! 要測的一樣走完所有檢查（A 級不是信任等級）。選上游仍然只看今天的評測結果。
//!
//! 都是純函式：輸入是「路徑檢查、黑名單略過之後」今天實際可以測的候選（一般 DNS 被接走時，
//! A 級的 UDP 候選整批不在裡面，多樣性要用剩下的算）。

use super::tags::Tier;
use std::collections::{BTreeMap, HashSet};

/// 今天要測的 A 級至少要有幾家不同的經營者（不夠就從 B 級補）
pub const OPS_MIN: usize = 12;
/// 每一種會被選用的類型（`upstream.autoTypes`）至少要測幾個（名單裡本來就不到這麼多的，有幾個算幾個）
pub const TYPE_MIN: usize = 8;
/// 補位最多幾個
pub const B_FILL_MAX: usize = 32;
/// 補位時同一個經營者最多幾個
pub const FILL_PER_OP: usize = 2;
/// 每天探索幾個 B 級
pub const B_EXPLORE_MAX: usize = 40;
/// 沿用昨天選上／候補的 B 級最多幾個
pub const INCUMBENT_MAX: usize = 16;

/// 評測範圍
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A 級＋使用者的＋沿用＋補位＋探索
    A,
    /// 全部
    Ab,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::A => "a",
            Mode::Ab => "ab",
        }
    }

    /// 設定值：`a`／`ab`；`auto`、沒寫、看不懂都是 None（由呼叫者用換算好的值）
    pub fn parse(s: &str) -> Option<Mode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "a" => Some(Mode::A),
            "ab" | "all" => Some(Mode::Ab),
            _ => None,
        }
    }
}

/// `benchmark.tiers = auto` 的換算：實體記憶體小於這個值（MB）就只測 A 級。
/// 讀不到記憶體大小時照舊全部測
pub const AUTO_A_BELOW_MB: u64 = 256;

pub fn auto_mode(mem_total_mb: Option<u64>) -> Mode {
    match mem_total_mb {
        Some(mb) if mb < AUTO_A_BELOW_MB => Mode::A,
        _ => Mode::Ab,
    }
}

/// 一個候選（今天實際可以測的）
#[derive(Debug, Clone)]
pub struct Item<'a> {
    pub id: &'a str,
    /// 類型（`udp`、`doh`…）
    pub kind: &'a str,
    /// 實際分級（人工分級，加上 A4 依歷史的升降）
    pub tier: Tier,
    /// 經營者（名單的 `op=`，沒有就用主機的可註冊網域或 /16）
    pub op: String,
    /// 整理名單時量到的延遲：沒有歷史時的排序依據
    pub ms: Option<f32>,
    /// 一定要測、但不算進多樣性的：固定上游、對照組、執行時從未成功的
    pub always: bool,
    /// 昨天選上或列為候補
    pub incumbent: bool,
    /// 歷史分數（A4）：補位時高的先；沒有歷史是 None
    pub score: Option<f32>,
    /// 歷史很差（A4：倖存率低或有可疑紀錄）：不拿來補位，只在探索時輪到
    pub bad: bool,
}

/// 為什麼今天測（或不測）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// A 級、使用者的、固定上游、對照組
    Base,
    /// 昨天選上或候補的 B 級
    Incumbent,
    /// 多樣性補位
    Fill,
    /// 探索名額
    Explore,
    /// 今天不測
    Skip,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Plan {
    /// 跟輸入同樣的順序
    pub why: Vec<Why>,
    /// 補位的原因（寫進 judge.log）；不需要補位是空的
    pub fill_reason: String,
}

impl Plan {
    pub fn count(&self, w: Why) -> usize {
        self.why.iter().filter(|x| **x == w).count()
    }
    pub fn tested(&self, i: usize) -> bool {
        self.why.get(i).is_some_and(|w| *w != Why::Skip)
    }
}

/// FNV-1a（固定、跨平台一樣；不用另外的亂數來源，測試才穩）
pub fn fnv1a(b: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for x in b {
        h ^= *x as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn is_b(t: Tier) -> bool {
    matches!(t, Tier::B | Tier::Unknown)
}

/// 今天輪到探索的 B 級：全部 B 級依 id 的雜湊排成固定的順序，每 [`B_EXPLORE_MAX`] 個一組，
/// 第「日數 mod 組數」組就是今天的。同一天重跑是同一批（手動多跑幾次不會把 B 級全測完）；
/// 名單不變時每一組輪一次就全部測過一遍（1,300 個約 33 天）
pub fn explore_slice<'a>(b_ids: &[&'a str], day: u32) -> Vec<&'a str> {
    if b_ids.is_empty() {
        return Vec::new();
    }
    let mut v: Vec<(u32, &str)> = b_ids.iter().map(|id| (fnv1a(id.as_bytes()), *id)).collect();
    v.sort_unstable();
    v.dedup();
    let groups = v.len().div_ceil(B_EXPLORE_MAX);
    let g = day as usize % groups;
    v.into_iter()
        .skip(g * B_EXPLORE_MAX)
        .take(B_EXPLORE_MAX)
        .map(|(_, id)| id)
        .collect()
}

/// 決定今天測誰。`auto_types`：會被選用的類型（多樣性只看這些類型）
pub fn plan(items: &[Item], mode: Mode, day: u32, auto_types: &[String]) -> Plan {
    if mode == Mode::Ab {
        return Plan {
            why: vec![Why::Base; items.len()],
            fill_reason: String::new(),
        };
    }
    let usable = |it: &Item| auto_types.iter().any(|t| t == it.kind);
    let mut why: Vec<Why> = items
        .iter()
        .map(|it| if it.always || !is_b(it.tier) { Why::Base } else { Why::Skip })
        .collect();
    // 沿用：昨天選上或候補的 B 級
    let mut n = 0usize;
    for (i, it) in items.iter().enumerate() {
        if why[i] == Why::Skip && it.incumbent && n < INCUMBENT_MAX {
            why[i] = Why::Incumbent;
            n += 1;
        }
    }

    // 多樣性：今天要測的一般候選（只算會被選用的類型）有幾家經營者、每種類型幾個
    let mut ops: HashSet<&str> = HashSet::new();
    let mut have: BTreeMap<&str, usize> = BTreeMap::new();
    let mut avail: BTreeMap<&str, usize> = BTreeMap::new();
    let mut all_ops: HashSet<&str> = HashSet::new();
    for (i, it) in items.iter().enumerate() {
        if it.always || !usable(it) {
            continue;
        }
        *avail.entry(it.kind).or_default() += 1;
        all_ops.insert(it.op.as_str());
        if why[i] != Why::Skip {
            *have.entry(it.kind).or_default() += 1;
            ops.insert(it.op.as_str());
        }
    }
    let ops_target = OPS_MIN.min(all_ops.len());
    let mut need: BTreeMap<&str, usize> = BTreeMap::new();
    let mut reasons: Vec<String> = Vec::new();
    if ops.len() < ops_target {
        reasons.push(format!("經營者只有 {} 家（至少 {ops_target}）", ops.len()));
    }
    for (k, a) in &avail {
        let target = TYPE_MIN.min(*a);
        let h = have.get(k).copied().unwrap_or(0);
        if h < target {
            need.insert(k, target - h);
            reasons.push(format!("{k} 只有 {h} 個（至少 {target}）"));
        }
    }
    if !reasons.is_empty() {
        // 補位的順序：有歷史的依分數（高的先），沒有歷史的依整理名單時的延遲（小的先），再依 id（固定）
        let mut pool: Vec<usize> = (0..items.len())
            .filter(|&i| why[i] == Why::Skip && usable(&items[i]) && !items[i].bad)
            .collect();
        pool.sort_by(|&a, &b| {
            let (x, y) = (&items[a], &items[b]);
            let key = |v: Option<f32>| v.filter(|f| f.is_finite());
            match (key(x.score), key(y.score)) {
                (Some(p), Some(q)) if p != q => return q.partial_cmp(&p).unwrap_or(std::cmp::Ordering::Equal),
                (Some(_), None) => return std::cmp::Ordering::Less,
                (None, Some(_)) => return std::cmp::Ordering::Greater,
                _ => {}
            }
            match (key(x.ms), key(y.ms)) {
                (Some(p), Some(q)) if p != q => return p.partial_cmp(&q).unwrap_or(std::cmp::Ordering::Equal),
                (Some(_), None) => return std::cmp::Ordering::Less,
                (None, Some(_)) => return std::cmp::Ordering::Greater,
                _ => {}
            }
            x.id.cmp(y.id)
        });
        let mut per_op: BTreeMap<&str, usize> = BTreeMap::new();
        let mut filled = 0usize;
        for i in pool {
            if filled >= B_FILL_MAX || (ops.len() >= ops_target && need.values().all(|n| *n == 0)) {
                break;
            }
            let it = &items[i];
            let type_short = need.get(it.kind).copied().unwrap_or(0) > 0;
            let new_op = ops.len() < ops_target && !ops.contains(it.op.as_str());
            if !(type_short || new_op) {
                continue;
            }
            let c = per_op.entry(it.op.as_str()).or_default();
            if *c >= FILL_PER_OP {
                continue;
            }
            *c += 1;
            why[i] = Why::Fill;
            filled += 1;
            ops.insert(it.op.as_str());
            if let Some(n) = need.get_mut(it.kind) {
                *n = n.saturating_sub(1);
            }
        }
    }

    // 探索：今天輪到的那一組裡，還沒排進去的
    let b_ids: Vec<&str> = items.iter().filter(|it| !it.always && is_b(it.tier)).map(|it| it.id).collect();
    let today: HashSet<&str> = explore_slice(&b_ids, day).into_iter().collect();
    for (i, it) in items.iter().enumerate() {
        if why[i] == Why::Skip && today.contains(it.id) {
            why[i] = Why::Explore;
        }
    }
    Plan {
        why,
        fill_reason: reasons.join("、"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item<'a>(id: &'a str, kind: &'a str, tier: Tier, op: &str) -> Item<'a> {
        Item {
            id,
            kind,
            tier,
            op: op.to_string(),
            ms: None,
            always: false,
            incumbent: false,
            score: None,
            bad: false,
        }
    }

    fn types(t: &[&str]) -> Vec<String> {
        t.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn auto_follows_memory_and_parse() {
        assert_eq!(auto_mode(Some(128)), Mode::A);
        assert_eq!(auto_mode(Some(255)), Mode::A);
        assert_eq!(auto_mode(Some(256)), Mode::Ab);
        assert_eq!(auto_mode(Some(512)), Mode::Ab, "512 MB 的 D3 先照記憶體（待決 Q1）");
        assert_eq!(auto_mode(None), Mode::Ab, "讀不到就照舊全部測");
        assert_eq!(Mode::parse("a"), Some(Mode::A));
        assert_eq!(Mode::parse(" AB "), Some(Mode::Ab));
        assert_eq!(Mode::parse("auto"), None);
        assert_eq!(Mode::parse("x"), None);
    }

    #[test]
    fn ab_tests_everything() {
        let ids: Vec<String> = (0..100).map(|i| format!("192.0.2.{i}")).collect();
        let items: Vec<Item> = ids.iter().map(|id| item(id, "udp", Tier::B, "x")).collect();
        let p = plan(&items, Mode::Ab, 7, &types(&["udp"]));
        assert_eq!(p.count(Why::Base), 100);
        assert!(p.fill_reason.is_empty());
    }

    #[test]
    fn explore_slice_is_stable_within_a_day_and_rotates() {
        let ids: Vec<String> = (0..130).map(|i| format!("https://b{i}.example.net/dns-query")).collect();
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let d0 = explore_slice(&refs, 20_000);
        assert_eq!(d0.len(), B_EXPLORE_MAX);
        assert_eq!(d0, explore_slice(&refs, 20_000), "同一天重跑是同一批");
        // 輸入的順序不影響
        let mut rev = refs.clone();
        rev.reverse();
        assert_eq!(d0, explore_slice(&rev, 20_000));
        let d1 = explore_slice(&refs, 20_001);
        assert!(d0.iter().all(|x| !d1.contains(x)), "隔天是另一組");
        // 130 個分 4 組，4 天輪完，每個剛好一次
        let mut seen: Vec<&str> = (0..4).flat_map(|d| explore_slice(&refs, 20_000 + d)).collect();
        assert_eq!(seen.len(), 130);
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 130);
        assert!(explore_slice(&[], 1).is_empty());
        // 不到一組：每天都是全部
        assert_eq!(explore_slice(&refs[..5], 3).len(), 5);
    }

    #[test]
    fn tier_a_tests_only_a_user_fill_and_explore() {
        // A 級 20 家經營者、每種類型都夠：不補位
        let a: Vec<String> = (0..20).map(|i| format!("https://a{i}.example.com/dns-query")).collect();
        let b: Vec<String> = (0..100).map(|i| format!("https://b{i}.example.net/dns-query")).collect();
        let ops: Vec<String> = (0..20).map(|i| format!("op{i}")).collect();
        let mut items: Vec<Item> = a.iter().zip(&ops).map(|(id, op)| item(id, "doh", Tier::A, op)).collect();
        items.push(item("https://mine.example.com/dns-query", "doh", Tier::User, "mine"));
        let mut pinned = item("https://pinned.example.net/dns-query", "doh", Tier::B, "p");
        pinned.always = true;
        items.push(pinned);
        items.extend(b.iter().map(|id| item(id, "doh", Tier::B, "bop")));
        let mut unk = item("sdns://x", "dnscrypt", Tier::Unknown, "u");
        unk.incumbent = false;
        items.push(unk);
        // 101 個 B 級分 3 組，20_001 是第 0 組（滿 40 個）
        let p = plan(&items, Mode::A, 20_001, &types(&["doh"]));
        assert!(p.fill_reason.is_empty(), "{}", p.fill_reason);
        assert_eq!(p.count(Why::Base), 22, "A 級 20、使用者的 1、固定上游 1");
        assert_eq!(p.count(Why::Fill), 0);
        assert_eq!(p.count(Why::Explore), B_EXPLORE_MAX);
        assert_eq!(p.count(Why::Skip), 101 - B_EXPLORE_MAX);
        // 昨天選上的 B 級沿用（最多 16 個）
        for it in items.iter_mut().filter(|it| it.tier == Tier::B && !it.always).take(20) {
            it.incumbent = true;
        }
        let p = plan(&items, Mode::A, 20_000, &types(&["doh"]));
        assert_eq!(p.count(Why::Incumbent), INCUMBENT_MAX);
    }

    #[test]
    fn fill_when_operators_short_after_path_skip() {
        // 一般 DNS 整批被路徑檢查略過之後：A 級只剩 3 家經營者的 DoH
        let a: Vec<String> = (0..9).map(|i| format!("https://a{i}.example.com/dns-query")).collect();
        let b: Vec<String> = (0..200).map(|i| format!("https://b{i}.example.net/dns-query")).collect();
        let bops: Vec<String> = (0..200).map(|i| format!("bop{}", i / 5)).collect();
        let mut items: Vec<Item> = a
            .iter()
            .enumerate()
            .map(|(i, id)| item(id, "doh", Tier::A, ["x", "y", "z"][i % 3]))
            .collect();
        items.extend(b.iter().zip(&bops).enumerate().map(|(i, (id, op))| {
            let mut it = item(id, "doh", Tier::B, op);
            it.ms = Some(300.0 - i as f32);
            it
        }));
        let p = plan(&items, Mode::A, 20_000, &types(&["doh", "dot"]));
        assert!(p.fill_reason.contains("經營者只有 3 家"), "{}", p.fill_reason);
        let filled: Vec<&Item> = (0..items.len()).filter(|&i| p.why[i] == Why::Fill).map(|i| &items[i]).collect();
        // 3 家 → 12 家：補 9 家新的就夠（每家 1 個就達標），不超過上限
        assert_eq!(filled.len(), 9, "{:?}", filled.iter().map(|x| x.id).collect::<Vec<_>>());
        let mut per: BTreeMap<&str, usize> = BTreeMap::new();
        for f in &filled {
            *per.entry(f.op.as_str()).or_default() += 1;
        }
        assert!(per.values().all(|n| *n <= FILL_PER_OP));
        // 沒有歷史：依整理名單時的延遲，小的先（b199 最小）
        assert!(filled.iter().any(|f| f.id == "https://b199.example.net/dns-query"));
        // 有歷史分數的排在前面；歷史很差的不補
        items[9 + 3].score = Some(0.9);
        items[9 + 199].bad = true;
        let p = plan(&items, Mode::A, 20_000, &types(&["doh"]));
        assert_eq!(p.why[9 + 3], Why::Fill);
        assert_ne!(p.why[9 + 199], Why::Fill);
    }

    #[test]
    fn fill_is_capped_and_per_operator() {
        // 每種類型都缺很多：補位不超過 32 個、同一個經營者最多 2 個
        let b: Vec<String> = (0..300).map(|i| format!("tls://b{i}.example.net")).collect();
        let ops: Vec<String> = (0..300).map(|i| format!("op{}", i / 10)).collect();
        let kinds = ["doh", "dot", "doq", "doh3", "udp"];
        let items: Vec<Item> = b
            .iter()
            .zip(&ops)
            .enumerate()
            .map(|(i, (id, op))| item(id, kinds[i % 5], Tier::B, op))
            .collect();
        let p = plan(&items, Mode::A, 1, &types(&kinds));
        assert_eq!(p.count(Why::Fill), B_FILL_MAX);
        let mut per: BTreeMap<&str, usize> = BTreeMap::new();
        for i in (0..items.len()).filter(|&i| p.why[i] == Why::Fill) {
            *per.entry(items[i].op.as_str()).or_default() += 1;
        }
        assert!(per.values().all(|n| *n <= FILL_PER_OP), "{per:?}");
        assert!(p.count(Why::Explore) <= B_EXPLORE_MAX);
        // 名單裡某一種類型本來就只有 3 個：有幾個算幾個，不一直喊不夠
        let few: Vec<Item> = (0..3).map(|i| item(b[i].as_str(), "doq", Tier::A, ops[i * 10].as_str())).collect();
        let p = plan(&few, Mode::A, 1, &types(&["doq"]));
        assert!(p.fill_reason.is_empty(), "{}", p.fill_reason);
        // 不會被選用的類型不補位
        let off: Vec<Item> = (0..20).map(|i| item(b[i].as_str(), "dnscrypt", Tier::B, "s")).collect();
        let p = plan(&off, Mode::A, 1, &types(&["doh"]));
        assert_eq!(p.count(Why::Fill), 0);
    }
}
