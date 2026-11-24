//! 分級評測（3.5.0，規格 11 的 A3）：決定「今天測誰」
//!
//! `benchmark.tiers`：
//! - `ab`：全部都測（3.4.4 以前的行為）。
//! - `a`：**只用 A 級**（使用者自己選的）。只測、只選 A 級與使用者自己加的（另外固定上游、對照組照測）；
//!   人工分級是 B 級的一個都不測，連昨天選上的、依歷史升上來的也不用，所以也不會進 `selected`／候補。
//!   介意 B 級（經營者看不出來）的人用這個。A 級的多樣性不夠時只在 `judge.log` 寫明，不從 B 級補。
//! - `auto`：由主程式依實體記憶體換算（`benchjob.rs`）：大機器全部測；小機器是 [`Mode::Small`]——
//!   減量，不是只用 A 級。A 級＋使用者自己加的每天測；B 級只測少數幾種：
//!   - **沿用**：昨天選上或列為候補的（不然探索到的 B 級今天選上、明天又不測，執行中的上游每天換）；
//!   - **補位**（多樣性保護）：今天要測的 A 級經營者不到 [`OPS_MIN`] 家、或某一種類型不到 [`TYPE_MIN`] 個時，
//!     從 B 級補，最多 [`B_FILL_MAX`] 個、同一個經營者最多 [`FILL_PER_OP`] 個；
//!   - **探索**：每天輪 [`B_EXPLORE_MAX`] 個，B 級才有機會累積歷史。
//!
//! 這裡只決定測不測：不測的 B 級不算淘汰、不記任何紀錄（跟路徑檢查略過一樣）；
//! 要測的一樣走完所有檢查（A 級不是信任等級）。選上游仍然只看今天的評測結果（今天沒測的選不上）。
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
    /// 設定 `a`：只用 A 級（A 級＋使用者的；人工分級 B 級的一個都不測、不選）
    A,
    /// `auto` 在小機器的換算：A 級＋使用者的＋沿用＋補位＋探索（減量）
    Small,
    /// 全部
    Ab,
}

impl Mode {
    /// `upstreams.json` 的 `tiers.mode`：`a`（只測 A 級為主：設定 `a` 與小機器的 `auto`；
    /// 分得出來的是 `tiers.onlyA`）／`ab`
    pub fn name(self) -> &'static str {
        match self {
            Mode::A | Mode::Small => "a",
            Mode::Ab => "ab",
        }
    }

    /// 只用 A 級（設定 `a`）：B 級不測、不選
    pub fn only_a(self) -> bool {
        self == Mode::A
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

/// `benchmark.tiers = auto` 的換算：實體記憶體小於這個值（MB）就減量（[`Mode::Small`]）。
/// 讀不到記憶體大小時照舊全部測
pub const AUTO_A_BELOW_MB: u64 = 256;

pub fn auto_mode(mem_total_mb: Option<u64>) -> Mode {
    match mem_total_mb {
        Some(mb) if mb < AUTO_A_BELOW_MB => Mode::Small,
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
    /// （只用 A 級時，人工分級 B 級的從未成功也不測：見 [`Item::fixed`]）
    pub always: bool,
    /// 固定上游、對照組：不論哪一種模式都測（只用 A 級時也一樣；它們本來就不會被選成自動上游）
    pub fixed: bool,
    /// 昨天選上或列為候補
    pub incumbent: bool,
    /// 歷史分數（A4）：補位時高的先；沒有歷史是 None
    pub score: Option<f32>,
    /// 歷史很差（A4：倖存率低或有可疑紀錄）：不拿來補位
    pub bad: bool,
    /// 人工分級是 B 級（含沒標記的）：探索的分組用人工分級算，升降不會讓今天的那一組變動
    pub manual_b: bool,
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

/// 今天要測的一般候選（只算會被選用的類型）的多樣性
struct Diversity<'a> {
    /// 今天要測的有哪幾家經營者
    ops: HashSet<&'a str>,
    /// 經營者至少要幾家（今天能測的不到 [`OPS_MIN`] 家時有幾家算幾家）
    ops_target: usize,
    /// 每一種類型還差幾個
    need: BTreeMap<&'a str, usize>,
    /// 不夠的原因（寫進 judge.log）；夠了是空的
    reasons: Vec<String>,
}

fn diversity<'a>(items: &'a [Item], why: &[Why], auto_types: &[String]) -> Diversity<'a> {
    let usable = |it: &Item| auto_types.iter().any(|t| t == it.kind);
    let mut ops: HashSet<&str> = HashSet::new();
    let mut have: BTreeMap<&str, usize> = BTreeMap::new();
    let mut avail: BTreeMap<&str, usize> = BTreeMap::new();
    let mut all_ops: HashSet<&str> = HashSet::new();
    for (i, it) in items.iter().enumerate() {
        if it.always || it.fixed || !usable(it) {
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
    Diversity {
        ops,
        ops_target,
        need,
        reasons,
    }
}

/// 決定今天測誰。`auto_types`：會被選用的類型（多樣性只看這些類型）
pub fn plan(items: &[Item], mode: Mode, day: u32, auto_types: &[String]) -> Plan {
    match mode {
        Mode::Ab => {
            return Plan {
                why: vec![Why::Base; items.len()],
                fill_reason: String::new(),
            }
        }
        Mode::A => {
            // 只用 A 級：人工分級 B 級的（含依歷史升上來的、昨天選上的、從未成功的）一個都不測；
            // 依歷史降級的 A 級照小機器的規則今天不測。多樣性不夠只寫原因，不從 B 級補
            let why: Vec<Why> = items
                .iter()
                .map(|it| {
                    if it.fixed || (!it.manual_b && (it.always || !is_b(it.tier))) {
                        Why::Base
                    } else {
                        Why::Skip
                    }
                })
                .collect();
            let d = diversity(items, &why, auto_types);
            return Plan {
                why,
                fill_reason: d.reasons.join("、"),
            };
        }
        Mode::Small => {}
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

    let Diversity {
        mut ops,
        ops_target,
        mut need,
        reasons,
    } = diversity(items, &why, auto_types);
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
    let b_ids: Vec<&str> = items.iter().filter(|it| !it.always && it.manual_b).map(|it| it.id).collect();
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

// ---------------- 依評測歷史的升降（A4） ----------------
//
// 人工分級是起點；這台自己近 30 天的評測歷史（學習檔的 `hist`）決定「實際分級」：
//
// - **降級** A → B：測到 7 天以上，倖存率低於 50% 或有 2 天以上的汙染／可疑紀錄。只測 A 級的機器降下去之後就不測
//   （也不拿來補位、不排進探索）；歷史滾出 30 天（測到不滿 7 天）就照人工分級重新測，還是不行就再降——
//   一台壞掉的 A 級 30 天最多測 7 次左右。全部都測的機器照樣每天測，倖存率回到 80% 以上而且沒有可疑紀錄就恢復。
// - **試用** B：今天測到（探索、補位、沿用）而且倖存、30 天內沒有失敗過、沒有可疑紀錄 → 先每天測，
//   最多 [`TRIAL_MAX`] 個、每天最多新增 [`TRIAL_NEW_PER_DAY`] 個（今天延遲低的先）。試用中失敗 2 天或有可疑紀錄就結束。
//   沒有這一步的話，只測 A 級的機器 B 級一個月才輪到一次，永遠累積不到 10 天的歷史。
// - **升級** B → A：測到 10 天以上、倖存率 90% 以上、沒有可疑紀錄、延遲穩定，最多 [`PROMOTE_MAX`] 個（歷史分數高的先）。
//   升上來之後倖存率掉到 75% 以下或有可疑紀錄才降回去。
// - 升與降的門檻不一樣（90%／75%、50%／80%）：中間地帶維持原狀，不會每天來回。
// - 只影響「測不測」，不影響「選不選」；固定上游、對照組、使用者自己加的不參與。

use super::learn::{Hist, HistState};

/// 降級至少要測到幾天
pub const DEMOTE_MIN_DAYS: u32 = 7;
/// 倖存率低於這個值就降級
pub const DEMOTE_BELOW: f32 = 0.5;
/// 汙染／可疑紀錄幾天以上就降級
pub const DEMOTE_SUSPECT_DAYS: u32 = 2;
/// 降級之後倖存率回到這個值以上（而且沒有可疑紀錄）才恢復
pub const RESTORE_AT: f32 = 0.8;
/// 升級至少要測到幾天
pub const PROMOTE_MIN_DAYS: u32 = 10;
/// 升級要的倖存率
pub const PROMOTE_AT: f32 = 0.9;
/// 升上來之後倖存率低於這個值才降回去
pub const UNPROMOTE_BELOW: f32 = 0.75;
/// 升上來的最多幾個
pub const PROMOTE_MAX: usize = 64;
/// 試用中的最多幾個
pub const TRIAL_MAX: usize = 24;
/// 每天最多新增幾個試用
pub const TRIAL_NEW_PER_DAY: usize = 8;
/// 試用中失敗幾天就結束
pub const TRIAL_FAIL_DAYS: u32 = 2;

/// 歷史很差（降級的條件；B 級也用它決定「不拿來補位」）
pub fn history_bad(h: &Hist) -> bool {
    h.tested() >= DEMOTE_MIN_DAYS && (h.rate() < DEMOTE_BELOW || h.suspect() >= DEMOTE_SUSPECT_DAYS)
}

/// 實際分級：人工分級加上歷史的升降。`h` 是學習檔裡的那一筆（還沒換算到今天）；沒有歷史就是人工分級
pub fn effective_tier(manual: Tier, h: Option<&Hist>, today: u32) -> Tier {
    let Some(h) = h else { return manual };
    let aged = h.aged(today);
    match manual {
        // 降級的歷史滾出 30 天（測到不滿 7 天）就照人工分級重來
        Tier::A if h.e == HistState::Demoted && aged.tested() >= DEMOTE_MIN_DAYS => Tier::B,
        Tier::B | Tier::Unknown if matches!(h.e, HistState::Promoted | HistState::Trial) && aged.tested() > 0 => Tier::A,
        t => t,
    }
}

/// 保險絲：被降級的 A 級超過今天 A 級的三分之一時，多半是這條線路的問題（換線路、某一種協定時好時壞），
/// 今天不採用降級（全部照人工分級測）
pub fn demotion_fuse(manual_a: usize, demoted: usize) -> bool {
    demoted * 3 > manual_a
}

/// 一個候選今天的評測結果（只有今天真的測到、而且評測成功時才有）
#[derive(Debug, Clone)]
pub struct Tested {
    pub id: String,
    /// 人工分級（A／B／Unknown；使用者的不參與）
    pub manual: Tier,
    /// 倖存到最後
    pub survived: bool,
    /// 被判汙染／可疑
    pub suspect: bool,
    /// 今天的平均延遲
    pub ms: Option<f32>,
    /// 可以試用：類型會被選用、不是執行時從未成功的
    pub trial_ok: bool,
}

/// 今天的升降（寫進 judge.log）
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Changes {
    pub promoted: Vec<String>,
    pub unpromoted: Vec<String>,
    pub demoted: Vec<String>,
    pub restored: Vec<String>,
    pub trial_in: Vec<String>,
    pub trial_out: Vec<String>,
}

impl Changes {
    pub fn any(&self) -> bool {
        [
            &self.promoted,
            &self.unpromoted,
            &self.demoted,
            &self.restored,
            &self.trial_in,
            &self.trial_out,
        ]
        .iter()
        .any(|v| !v.is_empty())
    }
}

/// 評測成功之後更新歷史與升降狀態。`listed`：這個 id 還在不在名單裡（不在的刪掉）
pub fn update_history(
    hist: &mut std::collections::BTreeMap<String, Hist>,
    tested: &[Tested],
    today: u32,
    listed: impl Fn(&str) -> bool,
) -> Changes {
    let mut ch = Changes::default();
    // 名單裡沒有的、30 天內都沒測到的：不用記了（試用／升級中但一直測不到的也放掉，不佔名額）
    // （系統時間倒退、比那一筆舊的不動）
    hist.retain(|k, h| listed(k) && (today < h.last || h.aged(today).tested() > 0));
    let mut promote: Vec<(f32, &str)> = Vec::new();
    let mut trial: Vec<(f32, &str)> = Vec::new();
    for t in tested {
        let h = hist.entry(t.id.clone()).or_default();
        if !h.record(today, t.survived, t.suspect, t.ms) {
            continue;
        }
        let (n, rate, q) = (h.tested(), h.rate(), h.suspect());
        match t.manual {
            Tier::A => match h.e {
                HistState::Demoted => {
                    if n < DEMOTE_MIN_DAYS {
                        h.e = HistState::Normal;
                    } else if rate >= RESTORE_AT && q == 0 {
                        h.e = HistState::Normal;
                        ch.restored.push(t.id.clone());
                    }
                }
                _ => {
                    h.e = HistState::Normal;
                    if history_bad(h) {
                        h.e = HistState::Demoted;
                        ch.demoted.push(t.id.clone());
                    }
                }
            },
            Tier::B | Tier::Unknown => {
                let good = n >= PROMOTE_MIN_DAYS && rate >= PROMOTE_AT && q == 0 && h.stable();
                match h.e {
                    HistState::Promoted => {
                        if rate < UNPROMOTE_BELOW || q > 0 {
                            h.e = HistState::Normal;
                            ch.unpromoted.push(t.id.clone());
                        }
                    }
                    HistState::Trial => {
                        if n - h.survived() >= TRIAL_FAIL_DAYS || q > 0 || (n >= PROMOTE_MIN_DAYS && !good) {
                            h.e = HistState::Normal;
                            ch.trial_out.push(t.id.clone());
                        } else if good {
                            promote.push((h.score().unwrap_or(0.0), &t.id));
                        }
                    }
                    _ => {
                        h.e = HistState::Normal;
                        if good {
                            promote.push((h.score().unwrap_or(0.0), &t.id));
                        } else if t.trial_ok && t.survived && n == h.survived() && q == 0 {
                            trial.push((t.ms.filter(|x| x.is_finite()).unwrap_or(f32::MAX), &t.id));
                        }
                    }
                }
            }
            Tier::User => h.e = HistState::Normal,
        }
    }
    // 升級：分數高的先，總數不超過上限；試用期滿但名額滿了的回到一般 B 級
    promote.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal).then(a.1.cmp(b.1)));
    let mut n_promoted = hist.values().filter(|h| h.e == HistState::Promoted).count();
    for (_, id) in promote {
        let Some(h) = hist.get_mut(id) else { continue };
        if n_promoted < PROMOTE_MAX {
            h.e = HistState::Promoted;
            n_promoted += 1;
            ch.promoted.push(id.to_string());
        } else if h.e == HistState::Trial {
            h.e = HistState::Normal;
            ch.trial_out.push(id.to_string());
        }
    }
    // 試用：今天延遲低的先
    trial.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal).then(a.1.cmp(b.1)));
    let n_trial = hist.values().filter(|h| h.e == HistState::Trial).count();
    let room = TRIAL_MAX.saturating_sub(n_trial).min(TRIAL_NEW_PER_DAY);
    for (_, id) in trial.into_iter().take(room) {
        if let Some(h) = hist.get_mut(id) {
            h.e = HistState::Trial;
            ch.trial_in.push(id.to_string());
        }
    }
    ch
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
            fixed: false,
            incumbent: false,
            score: None,
            bad: false,
            manual_b: is_b(tier),
        }
    }

    fn types(t: &[&str]) -> Vec<String> {
        t.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn auto_follows_memory_and_parse() {
        assert_eq!(auto_mode(Some(128)), Mode::Small, "小機器是減量，不是只用 A 級");
        assert_eq!(auto_mode(Some(255)), Mode::Small);
        assert_eq!(auto_mode(Some(256)), Mode::Ab);
        assert_eq!(auto_mode(Some(512)), Mode::Ab, "512 MB 的 D3 先照記憶體（待決 Q1）");
        assert_eq!(auto_mode(None), Mode::Ab, "讀不到就照舊全部測");
        assert_eq!(Mode::parse("a"), Some(Mode::A), "設定 a＝只用 A 級");
        assert!(Mode::A.only_a() && !Mode::Small.only_a() && !Mode::Ab.only_a());
        assert_eq!((Mode::A.name(), Mode::Small.name()), ("a", "a"));
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
    fn tier_a_uses_only_a_no_incumbent_fill_or_explore() {
        // 設定 a＝只用 A 級：A 級只有 3 家經營者（多樣性不夠）、B 級有昨天選上的、依歷史升上來的、從未成功的
        let a: Vec<String> = (0..9).map(|i| format!("https://a{i}.example.com/dns-query")).collect();
        let b: Vec<String> = (0..100).map(|i| format!("https://b{i}.example.net/dns-query")).collect();
        let mut items: Vec<Item> = a
            .iter()
            .enumerate()
            .map(|(i, id)| item(id, "doh", Tier::A, ["x", "y", "z"][i % 3]))
            .collect();
        items.push(item("https://mine.example.com/dns-query", "doh", Tier::User, "mine"));
        let mut pinned = item("https://pinned.example.net/dns-query", "doh", Tier::B, "p");
        (pinned.always, pinned.fixed) = (true, true);
        items.push(pinned);
        let mut control = item("https://control.example.net/dns-query", "doh", Tier::Unknown, "c");
        (control.always, control.fixed) = (true, true);
        items.push(control);
        items.extend(b.iter().map(|id| item(id, "doh", Tier::B, "bop")));
        let nb = items.len() - 100;
        items[nb].incumbent = true; // 昨天選上的 B 級
        items[nb + 1].tier = Tier::A; // 依歷史升上來的 B 級（實際分級 A、人工分級 B）
        items[nb + 2].always = true; // 執行時從未成功的 B 級
        let mut demoted = item("https://demoted.example.com/dns-query", "doh", Tier::B, "d");
        demoted.manual_b = false; // 依歷史降級的 A 級
        items.push(demoted);
        for day in [20_000, 20_001, 20_002] {
            let p = plan(&items, Mode::A, day, &types(&["doh"]));
            assert_eq!(p.count(Why::Base), 12, "A 級 9、使用者的 1、固定上游 1、對照組 1");
            assert_eq!((p.count(Why::Incumbent), p.count(Why::Fill), p.count(Why::Explore)), (0, 0, 0));
            assert!((nb..items.len()).all(|i| p.why[i] == Why::Skip), "B 級一個都不測");
            assert!(p.fill_reason.contains("經營者只有 4 家"), "多樣性不夠照樣寫原因：{}", p.fill_reason);
        }
        // 同一份候選在小機器的 auto：沿用、補位、探索照舊
        let p = plan(&items, Mode::Small, 20_000, &types(&["doh"]));
        assert_eq!(p.why[nb], Why::Incumbent);
        assert_eq!(p.why[nb + 1], Why::Base);
        assert!(p.count(Why::Fill) > 0 && p.count(Why::Explore) > 0);
    }

    #[test]
    fn small_tests_only_a_user_fill_and_explore() {
        // A 級 20 家經營者、每種類型都夠：不補位
        let a: Vec<String> = (0..20).map(|i| format!("https://a{i}.example.com/dns-query")).collect();
        let b: Vec<String> = (0..100).map(|i| format!("https://b{i}.example.net/dns-query")).collect();
        let ops: Vec<String> = (0..20).map(|i| format!("op{i}")).collect();
        let mut items: Vec<Item> = a.iter().zip(&ops).map(|(id, op)| item(id, "doh", Tier::A, op)).collect();
        items.push(item("https://mine.example.com/dns-query", "doh", Tier::User, "mine"));
        let mut pinned = item("https://pinned.example.net/dns-query", "doh", Tier::B, "p");
        pinned.always = true;
        pinned.fixed = true;
        items.push(pinned);
        items.extend(b.iter().map(|id| item(id, "doh", Tier::B, "bop")));
        let mut unk = item("sdns://x", "dnscrypt", Tier::Unknown, "u");
        unk.incumbent = false;
        items.push(unk);
        // 101 個 B 級分 3 組，20_001 是第 0 組（滿 40 個）
        let p = plan(&items, Mode::Small, 20_001, &types(&["doh"]));
        assert!(p.fill_reason.is_empty(), "{}", p.fill_reason);
        assert_eq!(p.count(Why::Base), 22, "A 級 20、使用者的 1、固定上游 1");
        assert_eq!(p.count(Why::Fill), 0);
        assert_eq!(p.count(Why::Explore), B_EXPLORE_MAX);
        assert_eq!(p.count(Why::Skip), 101 - B_EXPLORE_MAX);
        // 昨天選上的 B 級沿用（最多 16 個）
        for it in items.iter_mut().filter(|it| it.tier == Tier::B && !it.always).take(20) {
            it.incumbent = true;
        }
        let p = plan(&items, Mode::Small, 20_000, &types(&["doh"]));
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
        let p = plan(&items, Mode::Small, 20_000, &types(&["doh", "dot"]));
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
        let p = plan(&items, Mode::Small, 20_000, &types(&["doh"]));
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
        let p = plan(&items, Mode::Small, 1, &types(&kinds));
        assert_eq!(p.count(Why::Fill), B_FILL_MAX);
        let mut per: BTreeMap<&str, usize> = BTreeMap::new();
        for i in (0..items.len()).filter(|&i| p.why[i] == Why::Fill) {
            *per.entry(items[i].op.as_str()).or_default() += 1;
        }
        assert!(per.values().all(|n| *n <= FILL_PER_OP), "{per:?}");
        assert!(p.count(Why::Explore) <= B_EXPLORE_MAX);
        // 名單裡某一種類型本來就只有 3 個：有幾個算幾個，不一直喊不夠
        let few: Vec<Item> = (0..3).map(|i| item(b[i].as_str(), "doq", Tier::A, ops[i * 10].as_str())).collect();
        let p = plan(&few, Mode::Small, 1, &types(&["doq"]));
        assert!(p.fill_reason.is_empty(), "{}", p.fill_reason);
        // 不會被選用的類型不補位
        let off: Vec<Item> = (0..20).map(|i| item(b[i].as_str(), "dnscrypt", Tier::B, "s")).collect();
        let p = plan(&off, Mode::Small, 1, &types(&["doh"]));
        assert_eq!(p.count(Why::Fill), 0);
    }

    // ---------------- A4 ----------------

    use std::collections::BTreeMap as Map;

    fn t(id: &str, manual: Tier, survived: bool) -> Tested {
        Tested {
            id: id.to_string(),
            manual,
            survived,
            suspect: false,
            ms: survived.then_some(20.0),
            trial_ok: true,
        }
    }

    /// 連續幾天、每天同一個結果
    fn days(hist: &mut Map<String, Hist>, from: u32, n: u32, x: &Tested) -> Changes {
        let mut last = Changes::default();
        for d in from..from + n {
            last = update_history(hist, std::slice::from_ref(x), d, |_| true);
        }
        last
    }

    #[test]
    fn demote_needs_seven_days_and_low_survival() {
        let mut h = Map::new();
        let bad = t("a", Tier::A, false);
        // 6 天都失敗：還不降
        assert!(days(&mut h, 100, 6, &bad).demoted.is_empty());
        assert_eq!(effective_tier(Tier::A, h.get("a"), 106), Tier::A);
        // 第 7 天：降級
        assert_eq!(days(&mut h, 106, 1, &bad).demoted, ["a"]);
        assert_eq!(h["a"].e, HistState::Demoted);
        assert_eq!(effective_tier(Tier::A, h.get("a"), 107), Tier::B);
        // 倖存率剛好 50% 不降（低於才降）
        let mut h = Map::new();
        for d in 0..10 {
            update_history(&mut h, &[t("a", Tier::A, d % 2 == 0)], 100 + d, |_| true);
        }
        assert_eq!(h["a"].e, HistState::Normal);
        // 汙染／可疑 2 天：倖存率再高也降
        let mut h = Map::new();
        days(&mut h, 100, 8, &t("a", Tier::A, true));
        let mut sus = t("a", Tier::A, false);
        sus.suspect = true;
        assert!(days(&mut h, 108, 1, &sus).demoted.is_empty(), "1 天還不降");
        assert_eq!(days(&mut h, 109, 1, &sus).demoted, ["a"]);
        // 使用者自己加的、沒有歷史的：照人工分級
        assert_eq!(effective_tier(Tier::User, h.get("a"), 110), Tier::User);
        assert_eq!(effective_tier(Tier::A, None, 110), Tier::A);
        assert_eq!(effective_tier(Tier::B, None, 110), Tier::B);
    }

    #[test]
    fn demoted_recovers_by_evidence_or_by_expiry() {
        let mut h = Map::new();
        let (bad, good) = (t("a", Tier::A, false), t("a", Tier::A, true));
        days(&mut h, 100, 7, &bad);
        assert_eq!(h["a"].e, HistState::Demoted);
        // 全部都測的機器：每天還是測得到。倖存率回到 80% 以上才恢復（50%～80% 維持降級，不來回）
        let mut restored_at = None;
        for d in 107..160 {
            let ch = update_history(&mut h, std::slice::from_ref(&good), d, |_| true);
            if d == 107 + 6 {
                assert_eq!(h["a"].e, HistState::Demoted, "倖存率 50%：還是降級");
            }
            if !ch.restored.is_empty() {
                restored_at = Some(d);
                break;
            }
        }
        // 7 天失敗 + n 天成功，n/(n+7) >= 0.8 → n = 28；那時最舊的失敗已經滾出 30 天，實際更早
        let d = restored_at.expect("會恢復");
        assert!(h["a"].rate() >= RESTORE_AT, "{:?}", h["a"]);
        assert!(d > 107 + 6);
        // 只測 A 級的機器：降級後不測。歷史滾出 30 天（測到不滿 7 天）就照人工分級重來
        let mut h = Map::new();
        days(&mut h, 100, 7, &bad);
        assert_eq!(effective_tier(Tier::A, h.get("a"), 107), Tier::B);
        assert_eq!(effective_tier(Tier::A, h.get("a"), 129), Tier::B, "第 100 天還在 30 天內");
        assert_eq!(effective_tier(Tier::A, h.get("a"), 130), Tier::A, "最舊的一天滾出去：重新測");
        // 重新測還是失敗：又滿 7 天 → 維持降級（一個壞掉的 A 級 30 天最多測 7 次左右）
        update_history(&mut h, std::slice::from_ref(&bad), 130, |_| true);
        assert_eq!(h["a"].e, HistState::Demoted);
        assert_eq!(effective_tier(Tier::A, h.get("a"), 131), Tier::A, "第 101 天也滾出去了");
        // 修好了：之後每次重測都倖存，倖存率夠了就恢復
        let mut d = 131;
        while h["a"].e == HistState::Demoted && d < 200 {
            if effective_tier(Tier::A, h.get("a"), d) == Tier::A {
                update_history(&mut h, std::slice::from_ref(&good), d, |_| true);
            }
            d += 1;
        }
        assert_eq!(h["a"].e, HistState::Normal);
        assert!(d < 140, "{d}");
    }

    #[test]
    fn promote_needs_ten_days_clean_and_stable() {
        let mut h = Map::new();
        let good = t("b", Tier::B, true);
        // 第 1 天倖存、沒有失敗過：開始試用（每天測）
        assert_eq!(days(&mut h, 100, 1, &good).trial_in, ["b"]);
        assert_eq!(effective_tier(Tier::B, h.get("b"), 101), Tier::A);
        // 9 天還不升
        assert!(days(&mut h, 101, 8, &good).promoted.is_empty());
        assert_eq!(h["b"].e, HistState::Trial);
        // 第 10 天：升級
        assert_eq!(days(&mut h, 109, 1, &good).promoted, ["b"]);
        assert_eq!(effective_tier(Tier::Unknown, h.get("b"), 110), Tier::A);
        // 延遲不穩的：試用期滿不升，回到一般 B 級
        let mut h = Map::new();
        for d in 0..10u32 {
            let mut x = t("j", Tier::B, true);
            x.ms = Some(if d % 2 == 0 { 20.0 } else { 220.0 });
            let ch = update_history(&mut h, &[x], 100 + d, |_| true);
            assert!(ch.promoted.is_empty());
            if d == 9 {
                assert_eq!(ch.trial_out, ["j"]);
            }
        }
        assert_eq!(h["j"].e, HistState::Normal);
        assert!(!h["j"].stable());
        // 有可疑紀錄的：不升、試用馬上結束
        let mut h = Map::new();
        days(&mut h, 100, 3, &t("q", Tier::B, true));
        let mut sus = t("q", Tier::B, false);
        sus.suspect = true;
        assert_eq!(days(&mut h, 103, 1, &sus).trial_out, ["q"]);
        // 30 天內失敗過、有可疑紀錄的不再試用（要等紀錄滾出去）
        assert!(days(&mut h, 104, 5, &t("q", Tier::B, true)).trial_in.is_empty());
        assert_eq!(effective_tier(Tier::B, h.get("q"), 110), Tier::B);
        // 試用中失敗 1 天還留著，2 天就結束
        let mut h = Map::new();
        days(&mut h, 100, 3, &t("f", Tier::B, true));
        assert!(days(&mut h, 103, 1, &t("f", Tier::B, false)).trial_out.is_empty());
        assert_eq!(days(&mut h, 104, 1, &t("f", Tier::B, false)).trial_out, ["f"]);
        // 類型不會被選用、執行時從未成功的：不試用
        let mut no = t("n", Tier::B, true);
        no.trial_ok = false;
        assert!(days(&mut Map::new(), 100, 3, &no).trial_in.is_empty());
    }

    #[test]
    fn middle_band_keeps_tier() {
        // 升上來的：倖存率掉到 75%～90% 之間不降回去，低於 75% 才降
        let mut h = Map::new();
        days(&mut h, 100, 20, &t("b", Tier::B, true));
        assert_eq!(h["b"].e, HistState::Promoted);
        let fail = t("b", Tier::B, false);
        // 20 天成功之後失敗 5 天：20/25 = 80%
        assert!(days(&mut h, 120, 5, &fail).unpromoted.is_empty());
        assert_eq!(h["b"].e, HistState::Promoted);
        assert!(h["b"].rate() < PROMOTE_AT && h["b"].rate() >= UNPROMOTE_BELOW);
        // 再失敗 2 天：20/27 = 74% → 降回去
        assert!(days(&mut h, 125, 1, &fail).unpromoted.is_empty());
        assert_eq!(days(&mut h, 126, 1, &fail).unpromoted, ["b"]);
        // 回到 B 級之後不會馬上又升：倖存率在 75%～90% 之間維持 B 級
        let ch = days(&mut h, 127, 2, &t("b", Tier::B, true));
        assert!(ch.promoted.is_empty() && ch.trial_in.is_empty());
        assert_eq!(effective_tier(Tier::B, h.get("b"), 129), Tier::B);
        // A 級：倖存率 50%～90% 維持 A 級
        let mut h = Map::new();
        for d in 0..20 {
            let ch = update_history(&mut h, &[t("a", Tier::A, d % 3 != 0)], 100 + d, |_| true);
            assert!(!ch.any(), "{ch:?}");
        }
        assert_eq!(h["a"].e, HistState::Normal);
    }

    #[test]
    fn promoted_capped_at_64_and_trial_capped() {
        let ids: Vec<String> = (0..100).map(|i| format!("https://b{i:03}.example.net/dns-query")).collect();
        let mut h = Map::new();
        let mut seen_trial_max = 0usize;
        for d in 0..60u32 {
            let all: Vec<Tested> = ids
                .iter()
                .enumerate()
                .map(|(i, id)| {
                    let mut x = t(id, Tier::B, true);
                    x.ms = Some(10.0 + i as f32);
                    x
                })
                .collect();
            let ch = update_history(&mut h, &all, 100 + d, |_| true);
            assert!(ch.trial_in.len() <= TRIAL_NEW_PER_DAY, "{}", ch.trial_in.len());
            if d == 0 {
                // 今天延遲低的先試用
                assert_eq!(ch.trial_in, ids[..TRIAL_NEW_PER_DAY]);
            }
            let trial = h.values().filter(|x| x.e == HistState::Trial).count();
            seen_trial_max = seen_trial_max.max(trial);
            assert!(trial <= TRIAL_MAX);
            assert!(h.values().filter(|x| x.e == HistState::Promoted).count() <= PROMOTE_MAX);
        }
        assert_eq!(seen_trial_max, TRIAL_MAX);
        assert_eq!(h.values().filter(|x| x.e == HistState::Promoted).count(), PROMOTE_MAX);
        // 名額滿了：其他的回到一般 B 級，不會卡在試用
        assert_eq!(h.values().filter(|x| x.e == HistState::Trial).count(), 0);
    }

    #[test]
    fn path_skipped_not_counted_and_unlisted_dropped() {
        let mut h = Map::new();
        days(&mut h, 100, 8, &t("a", Tier::A, true));
        let before = h["a"];
        // 今天沒測到（路徑檢查略過、沒輪到）：那一筆不動，不算失敗
        let ch = update_history(&mut h, &[t("other", Tier::A, true)], 108, |_| true);
        assert!(!ch.any());
        assert_eq!(h["a"], before);
        assert_eq!(h["a"].aged(108).rate(), 1.0);
        // 30 天都沒測到：整筆忘掉；名單裡沒有的也刪掉
        update_history(&mut h, &[], 140, |_| true);
        assert!(h.is_empty());
        days(&mut h, 200, 3, &t("gone", Tier::B, true));
        update_history(&mut h, &[], 203, |k| k != "gone");
        assert!(h.is_empty());
        // 系統時間倒退：不動
        days(&mut h, 300, 3, &t("a", Tier::A, false));
        let before = h.clone();
        update_history(&mut h, &[t("a", Tier::A, true)], 250, |_| true);
        assert_eq!(h, before);
    }

    #[test]
    fn demotion_fuse_trips_above_a_third() {
        assert!(!demotion_fuse(90, 30));
        assert!(demotion_fuse(90, 31));
        assert!(demotion_fuse(2, 1));
        assert!(!demotion_fuse(100, 0));
    }
}
