//! 評測結算（同 2.x `jobs/dns-benchmark.js` 的 Phase 2 / 3）：獨有 IP、覆蓋率貪婪選擇、
//! 每個 ASN 留最快的一台、選出執行期上游，以及 5 份 CSV 報表。全部是純函式，方便對照 2.x 的結果。
//!
//! 覆蓋項目是「網域 | IP」：這裡編成 u64（高 32 位元是網域編號、低 32 位元是 IPv4），
//! 比 2.x 的字串省很多記憶體。

use super::rules::extract_asn_number;
use crate::util::to_fixed;
use std::collections::{HashMap, HashSet};

/// 一台倖存的上游（Phase 1 結束後）
#[derive(Debug, Clone, Default)]
pub struct Scored {
    pub id: String,
    /// udp / tcp / dot / doh / doh3 / doq / dnscrypt
    pub kind: String,
    pub owner: String,
    pub pinned: bool,
    /// 延遲統計（毫秒）；沒有成功紀錄時 avg = 9999、min = max = 0（同 2.x）
    pub avg: f64,
    pub min: f64,
    pub max: f64,
    pub count: usize,
    /// 網域編號 → 解析到的 IPv4（不重複）
    pub history: Vec<(u32, Vec<u32>)>,
    pub ext: Ext,
    /// 所在地（規格 10 的 6.1）："TW"（在台灣網段）、ip-api 的國別碼，或 ""（都沒有）
    pub region: String,
    /// 鄰近（台灣、日本、香港、新加坡且延遲合理，或延遲本身就夠低）：`coverage_region = near` 時優先挑
    pub near: bool,
    /// `region` 的依據（3.5.0 B9）：`"tw-net"`（位址在台灣網段，可信）或 `"registered"`（ip-api 的國別是 IP 的註冊地，
    /// 任播的公共 DNS 在東京的節點也會標成別國）。只影響顯示
    pub region_source: &'static str,
    /// 名單的分級（3.5.0）："A"／"B"／"user"；只輸出，不影響選擇
    pub tier: &'static str,
    /// 名單標記的經營者（3.5.0）
    pub op: String,
    /// 今天不選（3.5.0 A7：執行時上線以來從未成功）：照測、照算覆蓋，只是不選、也不當候補
    pub excluded: bool,
    /// 台灣率（3.5.0 B5）：答案裡有台灣網段 IP 的網域數 ÷「至少有一台倖存者回過台灣 IP 的網域」數；
    /// 分母不到 [`TW_RATE_MIN_DOMAINS`] 或沒有台灣網段資料時是 None。只在「覆蓋」差不多時當決勝條件
    pub tw_rate: Option<f32>,
    /// 名單標記的 `ecs=1`（3.5.0 B5）：會帶 ECS。只輸出
    pub ecs: bool,
    /// 昨天選上的（3.5.1 M3）：2＝同一台（正規化後的 id 相同）、1＝同一個經營者的別的寫法、0＝不是。
    /// 跟今天最好的差在 [`STICKY_RATIO`] 以內就留昨天那台（不要天天換）
    pub incumbent: u8,
}

/// 昨天選上的上游，延遲或新增覆蓋跟今天最好的差在這個比例以內就留昨天那台（3.5.1 M3：15%）
pub const STICKY_RATIO: f64 = 0.15;

/// 台灣率的分母（至少有一台倖存者回過台灣 IP 的網域）少於這個數就不算（樣本太少）
pub const TW_RATE_MIN_DOMAINS: usize = 10;
/// 「覆蓋」階段：新增覆蓋差在這個比例以內才看台灣率（10%）
pub const TW_TIE_RATIO: f64 = 0.9;

/// 算每台的台灣率（3.5.0 B5）。分母排除在台灣根本沒有節點的網站（沒有任何一台回過台灣 IP 的網域），
/// 分母不到 [`TW_RATE_MIN_DOMAINS`] 時全部是 None。`is_tw`：這個 IPv4 在不在台灣網段。回傳分母
pub fn tw_rates(servers: &mut [Scored], is_tw: impl Fn(u32) -> bool) -> usize {
    let mut tw_domains: HashSet<u32> = HashSet::new();
    let per: Vec<usize> = servers
        .iter()
        .map(|s| {
            let mut n = 0;
            for (d, ips) in &s.history {
                if ips.iter().any(|ip| is_tw(*ip)) {
                    tw_domains.insert(*d);
                    n += 1;
                }
            }
            n
        })
        .collect();
    let denom = tw_domains.len();
    for (s, n) in servers.iter_mut().zip(per) {
        s.tw_rate = (denom >= TW_RATE_MIN_DOMAINS).then(|| n as f32 / denom as f32);
    }
    denom
}

/// 鄰近的四地
pub const NEAR_REGIONS: [&str; 4] = ["TW", "JP", "HK", "SG"];

/// 判斷上游在哪裡、算不算鄰近（規格 10 的 6.1，純函式）：
/// - `region` = "TW"（位址在台灣網段）、否則 ip-api 的國別碼、都沒有就是 ""
/// - `near` = `region` 在鄰近四地而且 `min ≤ near_max_ms × 2`，或 `min ≤ near_max_ms`（不管國別，涵蓋任播與查不到國別的）
///
/// `min == 0` 是沒有成功紀錄，一律不算鄰近
pub fn classify_region(in_tw: bool, cc: &str, min_ms: f64, near_max_ms: f64) -> (String, bool) {
    // 註：`region` 不改值（串接的下游、auto_shared() 都在讀）；依據另外放在 `region_source`（見 [`region_source`]）
    let region = if in_tw { "TW".to_string() } else { cc.trim().to_ascii_uppercase() };
    let near = min_ms > 0.0 && (min_ms <= near_max_ms || (NEAR_REGIONS.contains(&region.as_str()) && min_ms <= near_max_ms * 2.0));
    (region, near)
}

/// `region` 的依據（3.5.0 B9）：位址在台灣網段是 `"tw-net"`，其他（ip-api 的國別、或查不到）是 `"registered"`
pub fn region_source(in_tw: bool) -> &'static str {
    if in_tw {
        "tw-net"
    } else {
        "registered"
    }
}

/// 2.x 的 `ext`
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Ext {
    pub total_resolved: usize,
    pub exclusive_count: usize,
    pub exclusive_ratio_self: f64,
    pub exclusive_ratio_global: f64,
    pub success_rate: f64,
}

pub fn item(domain: u32, ip: u32) -> u64 {
    ((domain as u64) << 32) | ip as u64
}

impl Scored {
    pub fn items(&self) -> impl Iterator<Item = u64> + '_ {
        self.history.iter().flat_map(|(d, ips)| ips.iter().map(move |ip| item(*d, *ip)))
    }
    pub fn item_count(&self) -> usize {
        self.history.iter().map(|(_, ips)| ips.len()).sum()
    }
}

/// 獨有 IP、成功率（同 2.x `extendedMetrics`）。`total_domains` 是有計分的網域數。
pub fn extended_metrics(servers: &mut [Scored], total_domains: usize) {
    // IP → 解析到它的上游（只需要知道是不是只有一台）
    let mut own: HashMap<u32, (usize, bool)> = HashMap::new();
    for (i, s) in servers.iter().enumerate() {
        for (_, ips) in &s.history {
            for ip in ips {
                let e = own.entry(*ip).or_insert((i, false));
                if e.0 != i {
                    e.1 = true;
                }
            }
        }
    }
    let universe = own.len();
    for s in servers.iter_mut() {
        let mut all = HashSet::new();
        let mut excl = 0;
        for (_, ips) in &s.history {
            for ip in ips {
                all.insert(*ip);
                if !own[ip].1 {
                    excl += 1;
                }
            }
        }
        let n = all.len();
        s.ext = Ext {
            total_resolved: n,
            exclusive_count: excl,
            exclusive_ratio_self: if n > 0 { excl as f64 / n as f64 } else { 0.0 },
            exclusive_ratio_global: if universe > 0 { excl as f64 / universe as f64 } else { 0.0 },
            success_rate: if total_domains > 0 {
                s.count as f64 / total_domains as f64
            } else {
                0.0
            },
        };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// 新增覆蓋最多的先（一樣多取快的）
    Coverage,
    /// 最快的先（一樣快取新增多的）
    Latency,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// `servers` 裡的位置
    pub idx: usize,
    pub newly: usize,
    /// 加入後的總覆蓋數
    pub total: usize,
}

fn stable_sort_by_avg(list: &mut [usize], servers: &[&Scored]) {
    list.sort_by(|a, b| servers[*a].avg.partial_cmp(&servers[*b].avg).unwrap_or(std::cmp::Ordering::Equal));
}

/// 貪婪選擇（同 2.x `greedy`）：回傳（選擇順序, 剩下的依延遲排序）
pub fn greedy(servers: &[&Scored], total: usize, strategy: Strategy, pre: &HashSet<u64>) -> (Vec<Step>, Vec<usize>) {
    greedy_inner(servers, total, strategy, pre, false).0
}

/// `tw_tie`（3.5.0 B5，只用在選上游的「覆蓋」階段）：每一步新增覆蓋差在 10% 以內的候選裡，
/// 台灣率比原本選到的高就改選它（台灣率高的有好幾台時，照原本的規則：新增多的、再快的）。
/// 台灣率是 None（沒有台灣網段資料、樣本太少）時跟原本一模一樣；報表（`greedy_csv`）不用
///
/// `tw_tie` 也同時打開「留昨天選上的」（3.5.1 M3）：台灣率決定之後，選到的不是昨天選上的，而新增覆蓋差在
/// [`STICKY_RATIO`] 以內、台灣率不比它低的候選裡有昨天選上的，就改選昨天那台（同一台優先、再來同一個經營者、再來新增多的、再快的）。
/// 第二個回傳值是因為這樣改選的步驟（`result` 的位置）
fn greedy_inner(
    servers: &[&Scored],
    total: usize,
    strategy: Strategy,
    pre: &HashSet<u64>,
    tw_tie: bool,
) -> ((Vec<Step>, Vec<usize>), Vec<usize>) {
    let mut covered = pre.clone();
    let mut result = Vec::new();
    let mut kept_steps = Vec::new();
    let mut cands: Vec<usize> = (0..servers.len()).collect();
    let mut news: Vec<(usize, usize)> = Vec::new(); // (cands 位置, 新增數)
    while covered.len() < total {
        let mut best: Option<(usize, usize)> = None; // (cands 位置, 新增數)
        news.clear();
        for (pos, &i) in cands.iter().enumerate() {
            let s = servers[i];
            let nw = s.items().filter(|k| !covered.contains(k)).count();
            if nw == 0 {
                continue;
            }
            if tw_tie {
                news.push((pos, nw));
            }
            let Some((bp, bn)) = best else {
                best = Some((pos, nw));
                continue;
            };
            let b = servers[cands[bp]];
            let better = match strategy {
                Strategy::Coverage => nw > bn || (nw == bn && s.avg < b.avg),
                Strategy::Latency => s.avg < b.avg || (s.avg == b.avg && nw > bn),
            };
            if better {
                best = Some((pos, nw));
            }
        }
        let Some((mut bp, mut bn)) = best else { break };
        if tw_tie && strategy == Strategy::Coverage {
            // 新增覆蓋差在 10% 以內的（含原本選到的）裡，台灣率最高的比原本選到的高 → 在那幾台裡照原本的規則挑
            if let Some(base) = servers[cands[bp]].tw_rate {
                let close = |nw: usize| nw as f64 >= bn as f64 * TW_TIE_RATIO;
                let top = news
                    .iter()
                    .filter(|(_, nw)| close(*nw))
                    .filter_map(|(pos, _)| servers[cands[*pos]].tw_rate)
                    .fold(base, f32::max);
                if top > base {
                    let mut pick: Option<(usize, usize)> = None;
                    for &(pos, nw) in news
                        .iter()
                        .filter(|(pos, nw)| close(*nw) && servers[cands[*pos]].tw_rate == Some(top))
                    {
                        let better = match pick {
                            None => true,
                            Some((pp, pn)) => nw > pn || (nw == pn && servers[cands[pos]].avg < servers[cands[pp]].avg),
                        };
                        if better {
                            pick = Some((pos, nw));
                        }
                    }
                    if let Some(p) = pick {
                        (bp, bn) = p;
                    }
                }
            }
            // 留昨天選上的（M3）
            if servers[cands[bp]].incumbent == 0 {
                let chosen_tw = servers[cands[bp]].tw_rate;
                let close = |nw: usize| nw as f64 >= bn as f64 * (1.0 - STICKY_RATIO);
                let mut pick: Option<(usize, usize)> = None;
                // 台灣率不比選到的低（任一邊沒有台灣率就不比）：台灣節點是黑潮的本質，穩定不能拿它來換
                let tw_ok = |s: &Scored| match (s.tw_rate, chosen_tw) {
                    (Some(a), Some(b)) => a >= b,
                    _ => true,
                };
                for &(pos, nw) in news.iter().filter(|(pos, nw)| {
                    let s = servers[cands[*pos]];
                    s.incumbent > 0 && close(*nw) && tw_ok(s)
                }) {
                    let s = servers[cands[pos]];
                    let better = match pick {
                        None => true,
                        Some((pp, pn)) => {
                            let p = servers[cands[pp]];
                            (s.incumbent, nw) > (p.incumbent, pn) || ((s.incumbent, nw) == (p.incumbent, pn) && s.avg < p.avg)
                        }
                    };
                    if better {
                        pick = Some((pos, nw));
                    }
                }
                if let Some(p) = pick {
                    (bp, bn) = p;
                    kept_steps.push(result.len());
                }
            }
        }
        let idx = cands.remove(bp);
        covered.extend(servers[idx].items());
        result.push(Step {
            idx,
            newly: bn,
            total: covered.len(),
        });
    }
    stable_sort_by_avg(&mut cands, servers);
    ((result, cands), kept_steps)
}

/// 每個 ASN（沒有 AS 號碼就用整個 owner 字串）留最快的一台，依第一次出現的順序
pub fn best_per_asn(servers: &[&Scored]) -> Vec<usize> {
    let mut order: Vec<String> = Vec::new();
    let mut best: HashMap<String, usize> = HashMap::new();
    for (i, s) in servers.iter().enumerate() {
        let k = extract_asn_number(&s.owner).unwrap_or(&s.owner).to_string();
        match best.get(&k) {
            None => {
                order.push(k.clone());
                best.insert(k, i);
            }
            Some(&b) if s.avg < servers[b].avg => {
                best.insert(k, i);
            }
            Some(_) => {}
        }
    }
    order.iter().map(|k| best[k]).collect()
}

/// 選上游的參數（`upstream.*` 與 `benchmark.*`，0 / 缺少時用 2.x 的預設）
#[derive(Debug, Clone)]
pub struct SelectOpts {
    pub auto_types: Vec<String>,
    pub max_n: usize,
    pub max_avg: f64,
    pub coverage_target: f64,
    pub min_auto: usize,
    /// `benchmark.coverageRegion = near`：「覆蓋」階段先在鄰近的候選裡挑（規格 10 的 6.2）。
    /// `false`（`any`）跟 3.3.7 一模一樣。`Default` 是 `false`（舊的行為）；設定的預設 `near` 由 `select_opts()` 帶入
    pub near_first: bool,
}

impl Default for SelectOpts {
    fn default() -> SelectOpts {
        SelectOpts {
            auto_types: vec!["udp".into(), "doh".into(), "dot".into()],
            max_n: 5,
            max_avg: 250.0,
            coverage_target: 0.97,
            min_auto: 3,
            near_first: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pick {
    /// `finals` 裡的位置
    pub idx: usize,
    pub newly: usize,
    /// 最快 / 覆蓋 / 備援
    pub why: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub selected: Vec<Pick>,
    pub covered: usize,
    /// 因為「昨天選上的」而留下的（3.5.1 M3；`finals` 的位置）：寫進 judge.log
    pub kept: Vec<usize>,
}

/// 能不能被選來用（固定上游另外算；3.5.0 起「今天不選」的也不行）
fn eligible(s: &Scored, o: &SelectOpts) -> bool {
    !s.pinned && !s.excluded && o.auto_types.contains(&s.kind) && s.avg <= o.max_avg && s.ext.success_rate >= 0.9
}

/// 候補最多幾台（3.5.0 A7）
pub const SPARES: usize = 3;

/// 候補（3.5.0 A7）：跟 [`select`] 一樣合格（每個 ASN 最快的一台、類型、延遲、成功率）、但沒選上的，依速度取前 `n` 台。
/// 執行時可用的自動上游不夠時依序補上
pub fn spares(finals: &[&Scored], asn_best: &[usize], sel: &Selection, o: &SelectOpts, n: usize) -> Vec<usize> {
    let mut v: Vec<usize> = asn_best
        .iter()
        .copied()
        .filter(|&i| eligible(finals[i], o) && !sel.selected.iter().any(|p| p.idx == i))
        .collect();
    v.sort_by(|a, b| finals[*a].avg.partial_cmp(&finals[*b].avg).unwrap_or(std::cmp::Ordering::Equal));
    v.truncate(n);
    v
}

/// Phase 3：選出執行期上游。`finals` 依延遲排序，`asn_best` 是 `best_per_asn(finals)`。
/// 先取最快的一台，再依「新增覆蓋最多」貪婪挑選，直到台數上限或覆蓋率達標；不足 minAuto 台時依速度補備援。
pub fn select(finals: &[&Scored], asn_best: &[usize], total: usize, o: &SelectOpts) -> Selection {
    let mut covered: HashSet<u64> = finals.iter().filter(|s| s.pinned).flat_map(|s| s.items()).collect();
    let eligible: Vec<usize> = asn_best.iter().copied().filter(|&i| eligible(finals[i], o)).collect();
    let mut by_speed = eligible.clone();
    by_speed.sort_by(|a, b| finals[*a].avg.partial_cmp(&finals[*b].avg).unwrap_or(std::cmp::Ordering::Equal));
    let mut selected = Vec::new();
    let mut kept = Vec::new();
    if let Some(&best) = by_speed.first() {
        // 留昨天選上的（M3）：延遲在今天最快的 15% 以內（同一台優先、再來同一個經營者的別的寫法、再快的）
        let fastest = by_speed
            .iter()
            .copied()
            .filter(|&i| finals[i].incumbent > 0 && finals[i].avg <= finals[best].avg * (1.0 + STICKY_RATIO))
            .min_by(|&a, &b| {
                finals[b]
                    .incumbent
                    .cmp(&finals[a].incumbent)
                    .then(finals[a].avg.partial_cmp(&finals[b].avg).unwrap_or(std::cmp::Ordering::Equal))
            })
            .unwrap_or(best);
        if fastest != best {
            kept.push(fastest);
        }
        let nw: Vec<u64> = finals[fastest].items().filter(|k| !covered.contains(k)).collect();
        let newly = nw.len();
        covered.extend(nw);
        selected.push(Pick {
            idx: fastest,
            newly,
            why: "最快",
        });
        let rest: Vec<usize> = eligible.iter().copied().filter(|&i| i != fastest).collect();
        // 覆蓋：`near_first` 時分兩輪（先鄰近的、再其餘的），第二輪從第一輪結束時的覆蓋接著算；
        // 兩輪共用台數上限與覆蓋率的停止條件。否則一輪、不分遠近（3.3.7）
        let rounds: Vec<Vec<usize>> = if o.near_first {
            let (near, far): (Vec<usize>, Vec<usize>) = rest.iter().partition(|&&i| finals[i].near);
            vec![near, far]
        } else {
            vec![rest]
        };
        let done = |n: usize, c: usize| n >= o.max_n || c as f64 >= total as f64 * o.coverage_target;
        'rounds: for round in rounds {
            if done(selected.len(), covered.len()) {
                break;
            }
            let refs: Vec<&Scored> = round.iter().map(|&i| finals[i]).collect();
            let ((steps, _), kept_steps) = greedy_inner(&refs, total, Strategy::Coverage, &covered, true);
            for (n, st) in steps.into_iter().enumerate() {
                if done(selected.len(), covered.len()) {
                    break 'rounds;
                }
                let idx = round[st.idx];
                if kept_steps.contains(&n) {
                    kept.push(idx);
                }
                covered.extend(finals[idx].items());
                selected.push(Pick {
                    idx,
                    newly: st.newly,
                    why: "覆蓋",
                });
            }
        }
    }
    for &i in &by_speed {
        if selected.len() >= o.min_auto.min(o.max_n) {
            break;
        }
        if !selected.iter().any(|p| p.idx == i) {
            selected.push(Pick {
                idx: i,
                newly: 0,
                why: "備援",
            });
        }
    }
    Selection {
        selected,
        covered: covered.len(),
        kept,
    }
}

// ---------------- CSV 報表（格式同 2.x，開頭有 BOM 方便 Excel 開） ----------------

fn pct(x: f64, d: usize) -> String {
    format!("{}%", to_fixed(x * 100.0, d))
}

/// dns_coverage_optimization.csv / dns_latency_optimization.csv（以及 ASN 版）
pub fn greedy_csv(servers: &[&Scored], total: usize, strategy: Strategy) -> String {
    let (result, rest) = greedy(servers, total, strategy, &HashSet::new());
    let mut csv = String::from("\u{feff}Step,DNS_Server,DNS_Owner,Type,Avg_Latency,New_IPs,Total_Coverage_Count,Coverage_Percent,Details,Total_Resolved_IPs,Exclusive_IPs,Exclusive_Rate_Self,Success_Rate\n");
    for (i, r) in result.iter().enumerate() {
        let s = servers[r.idx];
        let e = &s.ext;
        csv.push_str(&format!(
            "{},{},\"{}\",{},{},{},{},{},貢獻 {} 個新節點,{},{},{},{}\n",
            i + 1,
            s.id,
            s.owner,
            s.kind,
            to_fixed(s.avg, 2),
            r.newly,
            r.total,
            pct(r.total as f64 / total as f64, 2),
            r.newly,
            e.total_resolved,
            e.exclusive_count,
            pct(e.exclusive_ratio_self, 2),
            pct(e.success_rate, 1)
        ));
    }
    for &i in &rest {
        let s = servers[i];
        let e = &s.ext;
        csv.push_str(&format!(
            "-,{},\"{}\",{},{},0,{},100.00%,冗餘/備用節點,{},{},{},{}\n",
            s.id,
            s.owner,
            s.kind,
            to_fixed(s.avg, 2),
            total,
            e.total_resolved,
            e.exclusive_count,
            pct(e.exclusive_ratio_self, 2),
            pct(e.success_rate, 1)
        ));
    }
    csv
}

/// final_dns_smart.csv（`finals` 依延遲排序）。3.4.0 在最後加 `Region`、`Near` 兩欄、3.5.0 再加 `Tier`、`TW_Rate`（舊的欄位順序不變）
pub fn final_csv(finals: &[&Scored]) -> String {
    let mut csv = String::from("\u{feff}Rank,DNS_Server,Type,DNS_Owner,Min,Max,Avg,Count,Success_Rate,Total_IPs,Unique_IPs,Unique_Ratio_Self,Unique_Ratio_Global,Pinned,Region,Near,Tier,TW_Rate\n");
    for (i, s) in finals.iter().enumerate() {
        let e = &s.ext;
        csv.push_str(&format!(
            "{},{},{},\"{}\",{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            i + 1,
            s.id,
            s.kind,
            s.owner,
            to_fixed(s.min, 2),
            to_fixed(s.max, 2),
            to_fixed(s.avg, 2),
            s.count,
            pct(e.success_rate, 1),
            e.total_resolved,
            e.exclusive_count,
            pct(e.exclusive_ratio_self, 2),
            pct(e.exclusive_ratio_global, 4),
            if s.pinned { "Y" } else { "" },
            s.region,
            if s.near { "Y" } else { "" },
            s.tier,
            s.tw_rate.map(|r| pct(r as f64, 1)).unwrap_or_default()
        ));
    }
    csv
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srv(id: &str, owner: &str, avg: f64, items: &[(u32, u32)]) -> Scored {
        let mut history: Vec<(u32, Vec<u32>)> = Vec::new();
        for (d, ip) in items {
            match history.iter_mut().find(|(x, _)| x == d) {
                Some((_, v)) => v.push(*ip),
                None => history.push((*d, vec![*ip])),
            }
        }
        Scored {
            id: id.into(),
            kind: "udp".into(),
            owner: owner.into(),
            avg,
            count: 10,
            history,
            ..Default::default()
        }
    }

    #[test]
    fn greedy_and_select() {
        let mut v = vec![
            srv("a", "A__AS1", 10.0, &[(0, 1), (1, 2)]),
            srv("b", "B__AS2", 20.0, &[(0, 1), (1, 3), (2, 4), (2, 5)]),
            srv("c", "C__AS3", 30.0, &[(0, 6)]),
            srv("d", "D__AS2", 25.0, &[(0, 7)]), // 跟 b 同 ASN、比較慢 → 被 best_per_asn 濾掉
        ];
        extended_metrics(&mut v, 10);
        let refs: Vec<&Scored> = v.iter().collect();
        let (steps, rest) = greedy(&refs, 7, Strategy::Coverage, &HashSet::new());
        assert_eq!(
            steps.iter().map(|s| (s.idx, s.newly)).collect::<Vec<_>>(),
            vec![(1, 4), (0, 1), (3, 1), (2, 1)]
        );
        assert!(rest.is_empty());
        let (steps, _) = greedy(&refs, 7, Strategy::Latency, &HashSet::new());
        assert_eq!(steps.iter().map(|s| s.idx).collect::<Vec<_>>(), vec![0, 1, 3, 2]);
        assert_eq!(best_per_asn(&refs), vec![0, 1, 2]);
        let sel = select(&refs, &best_per_asn(&refs), 7, &SelectOpts::default());
        assert_eq!(
            sel.selected.iter().map(|p| (p.idx, p.newly, p.why)).collect::<Vec<_>>(),
            vec![(0, 2, "最快"), (1, 3, "覆蓋"), (2, 1, "覆蓋")]
        );
        assert_eq!(sel.covered, 6);
        assert!(greedy_csv(&refs, 7, Strategy::Coverage).contains("1,b,\"B__AS2\",udp,20.00,4,4,57.14%,貢獻 4 個新節點"));
    }

    fn near(mut s: Scored, n: bool) -> Scored {
        s.near = n;
        s
    }

    fn picks(sel: &Selection) -> Vec<(usize, usize, &'static str)> {
        sel.selected.iter().map(|p| (p.idx, p.newly, p.why)).collect()
    }

    #[test]
    fn classify_region_rules() {
        assert_eq!(classify_region(true, "", 8.0, 60.0), ("TW".to_string(), true));
        assert_eq!(
            classify_region(true, "US", 100.0, 60.0),
            ("TW".to_string(), true),
            "台灣網段優先於國別"
        );
        assert_eq!(classify_region(false, "JP", 45.0, 60.0), ("JP".to_string(), true));
        assert_eq!(
            classify_region(false, "JP", 110.0, 60.0),
            ("JP".to_string(), true),
            "鄰近四地放寬到 2 倍"
        );
        assert_eq!(classify_region(false, "JP", 130.0, 60.0), ("JP".to_string(), false), "超過 2 倍");
        assert_eq!(classify_region(false, "AU", 4.0, 60.0), ("AU".to_string(), true), "任播靠延遲");
        assert_eq!(classify_region(false, "US", 90.0, 60.0), ("US".to_string(), false));
        assert_eq!(classify_region(false, "", 80.0, 60.0), (String::new(), false));
        assert_eq!(classify_region(false, "", 30.0, 60.0), (String::new(), true));
        assert_eq!(classify_region(false, "sg", 70.0, 60.0), ("SG".to_string(), true));
        assert_eq!(classify_region(false, "JP", 0.0, 60.0), ("JP".to_string(), false), "沒有成功紀錄");
        assert_eq!(classify_region(true, "", 0.0, 60.0), ("TW".to_string(), false));
    }

    #[test]
    fn near_candidates_picked_before_far() {
        // 覆蓋量相同、一近一遠 → 近的（遠的比較快也一樣）
        let mut v = vec![
            near(srv("f", "F__AS1", 5.0, &[(0, 1)]), true),
            near(srv("far", "X__AS2", 10.0, &[(1, 2), (1, 3)]), false),
            near(srv("nr", "Y__AS3", 30.0, &[(2, 4), (2, 5)]), true),
        ];
        extended_metrics(&mut v, 10);
        let refs: Vec<&Scored> = v.iter().collect();
        let asn = best_per_asn(&refs);
        let o = SelectOpts {
            max_n: 2,
            near_first: true,
            ..Default::default()
        };
        assert_eq!(picks(&select(&refs, &asn, 5, &o)), vec![(0, 1, "最快"), (2, 2, "覆蓋")]);
        let any = SelectOpts {
            near_first: false,
            ..o.clone()
        };
        assert_eq!(
            picks(&select(&refs, &asn, 5, &any)),
            vec![(0, 1, "最快"), (1, 2, "覆蓋")],
            "any 照舊：一樣多取快的"
        );

        // 遠的覆蓋量較大，但近的也有新增 → 先近的
        let mut v = vec![
            near(srv("f", "F__AS1", 5.0, &[(0, 1)]), true),
            near(srv("far", "X__AS2", 10.0, &[(1, 2), (1, 3), (1, 6), (1, 7)]), false),
            near(srv("nr", "Y__AS3", 30.0, &[(2, 4)]), true),
        ];
        extended_metrics(&mut v, 10);
        let refs: Vec<&Scored> = v.iter().collect();
        let asn = best_per_asn(&refs);
        assert_eq!(picks(&select(&refs, &asn, 7, &o)), vec![(0, 1, "最快"), (2, 1, "覆蓋")]);
        assert_eq!(picks(&select(&refs, &asn, 7, &any)), vec![(0, 1, "最快"), (1, 4, "覆蓋")]);
    }

    #[test]
    fn far_used_when_near_cannot_reach_target() {
        let mut v = vec![
            near(srv("f", "F__AS1", 5.0, &[(0, 1)]), true),
            near(srv("n1", "A__AS2", 20.0, &[(1, 2)]), true),
            near(srv("far1", "B__AS3", 10.0, &[(2, 3), (2, 4), (2, 5)]), false),
            near(srv("n2", "C__AS4", 25.0, &[(0, 1)]), true), // 跟最快的一樣，沒有新增
            near(srv("far2", "D__AS5", 15.0, &[(3, 6)]), false),
        ];
        extended_metrics(&mut v, 10);
        let refs: Vec<&Scored> = v.iter().collect();
        let asn = best_per_asn(&refs);
        let o = SelectOpts {
            max_n: 5,
            near_first: true,
            ..Default::default()
        };
        let sel = select(&refs, &asn, 6, &o);
        assert_eq!(
            picks(&sel),
            vec![(0, 1, "最快"), (1, 1, "覆蓋"), (2, 3, "覆蓋"), (4, 1, "覆蓋")],
            "近的用完還沒達標 → 補遠的（遠的之間照舊依新增量）"
        );
        assert_eq!(sel.covered, 6);
        // 名額用完就不補
        let o3 = SelectOpts { max_n: 2, ..o.clone() };
        assert_eq!(picks(&select(&refs, &asn, 6, &o3)), vec![(0, 1, "最快"), (1, 1, "覆蓋")]);
        // 近的就達標 → 不用遠的做「覆蓋」（不足 minAuto 台時照舊依速度補「備援」）
        let ot = SelectOpts {
            coverage_target: 0.3,
            ..o.clone()
        };
        assert_eq!(
            picks(&select(&refs, &asn, 6, &ot)),
            vec![(0, 1, "最快"), (1, 1, "覆蓋"), (2, 0, "備援")]
        );
        // 一台近的都沒有 → 跟 any 一樣
        let all_far: Vec<Scored> = v.iter().cloned().map(|s| near(s, false)).collect();
        let refs2: Vec<&Scored> = all_far.iter().collect();
        let any = SelectOpts {
            near_first: false,
            ..o.clone()
        };
        assert_eq!(select(&refs2, &asn, 6, &o), select(&refs2, &asn, 6, &any));
    }

    /// 3.3.7 的 `select()`（原封不動）：`near_first = false` 的結果要跟它逐項相同
    fn select_337(finals: &[&Scored], asn_best: &[usize], total: usize, o: &SelectOpts) -> Selection {
        let mut covered: HashSet<u64> = finals.iter().filter(|s| s.pinned).flat_map(|s| s.items()).collect();
        let eligible: Vec<usize> = asn_best
            .iter()
            .copied()
            .filter(|&i| {
                let s = finals[i];
                !s.pinned && o.auto_types.contains(&s.kind) && s.avg <= o.max_avg && s.ext.success_rate >= 0.9
            })
            .collect();
        let mut by_speed = eligible.clone();
        by_speed.sort_by(|a, b| finals[*a].avg.partial_cmp(&finals[*b].avg).unwrap_or(std::cmp::Ordering::Equal));
        let mut selected = Vec::new();
        if let Some(&fastest) = by_speed.first() {
            let nw: Vec<u64> = finals[fastest].items().filter(|k| !covered.contains(k)).collect();
            let newly = nw.len();
            covered.extend(nw);
            selected.push(Pick {
                idx: fastest,
                newly,
                why: "最快",
            });
            let rest: Vec<usize> = eligible.iter().copied().filter(|&i| i != fastest).collect();
            let rest_refs: Vec<&Scored> = rest.iter().map(|&i| finals[i]).collect();
            let (steps, _) = greedy(&rest_refs, total, Strategy::Coverage, &covered);
            for st in steps {
                if selected.len() >= o.max_n || covered.len() as f64 >= total as f64 * o.coverage_target {
                    break;
                }
                let idx = rest[st.idx];
                covered.extend(finals[idx].items());
                selected.push(Pick {
                    idx,
                    newly: st.newly,
                    why: "覆蓋",
                });
            }
        }
        for &i in &by_speed {
            if selected.len() >= o.min_auto.min(o.max_n) {
                break;
            }
            if !selected.iter().any(|p| p.idx == i) {
                selected.push(Pick {
                    idx: i,
                    newly: 0,
                    why: "備援",
                });
            }
        }
        Selection {
            selected,
            covered: covered.len(),
            kept: Vec::new(),
        }
    }

    #[test]
    fn any_matches_previous_selection() {
        // 既有測試的預期值固定下來（near 標記不影響 any）
        let mut v = vec![
            near(srv("a", "A__AS1", 10.0, &[(0, 1), (1, 2)]), false),
            near(srv("b", "B__AS2", 20.0, &[(0, 1), (1, 3), (2, 4), (2, 5)]), true),
            near(srv("c", "C__AS3", 30.0, &[(0, 6)]), false),
            near(srv("d", "D__AS2", 25.0, &[(0, 7)]), true),
        ];
        extended_metrics(&mut v, 10);
        let refs: Vec<&Scored> = v.iter().collect();
        let asn = best_per_asn(&refs);
        let sel = select(&refs, &asn, 7, &SelectOpts::default());
        assert_eq!(picks(&sel), vec![(0, 2, "最快"), (1, 3, "覆蓋"), (2, 1, "覆蓋")]);
        assert_eq!(sel.covered, 6);
        assert_eq!(sel, select_337(&refs, &asn, 7, &SelectOpts::default()));

        // 亂數產生的多組輸入：any 跟 3.3.7 逐項相同
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut rnd = |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for round in 0..300 {
            let n = 2 + rnd(12) as usize;
            let mut v: Vec<Scored> = (0..n)
                .map(|i| {
                    let items: Vec<(u32, u32)> = (0..rnd(8)).map(|_| (rnd(4) as u32, rnd(10) as u32)).collect();
                    let mut s = srv(&format!("s{i}"), &format!("O{}__AS{}", i, rnd(6)), (rnd(30) * 10) as f64, &items);
                    s.pinned = rnd(10) == 0;
                    s.near = rnd(2) == 0;
                    s.count = 8 + rnd(3) as usize;
                    s
                })
                .collect();
            extended_metrics(&mut v, 10);
            v.sort_by(|a, b| a.avg.partial_cmp(&b.avg).unwrap());
            let refs: Vec<&Scored> = v.iter().collect();
            let asn = best_per_asn(&refs);
            let o = SelectOpts {
                max_n: 1 + rnd(5) as usize,
                min_auto: rnd(5) as usize,
                coverage_target: [0.5, 0.8, 0.97, 1.0][rnd(4) as usize],
                max_avg: 250.0,
                ..Default::default()
            };
            let total = 40;
            assert_eq!(select(&refs, &asn, total, &o), select_337(&refs, &asn, total, &o), "第 {round} 組");
        }
    }

    #[test]
    fn final_csv_region_columns() {
        let mut s = srv("a", "A__AS1", 10.0, &[(0, 1)]);
        s.region = "JP".into();
        s.near = true;
        s.tier = "A";
        let csv = final_csv(&[&s]);
        let mut lines = csv.lines();
        assert!(lines.next().unwrap().ends_with(",Pinned,Region,Near,Tier,TW_Rate"));
        assert!(lines.next().unwrap().ends_with(",,JP,Y,A,"));
        s.tw_rate = Some(0.625);
        assert!(final_csv(&[&s]).lines().nth(1).unwrap().ends_with(",,JP,Y,A,62.5%"));
    }

    /// 網域 d 的答案：`tw` 為真時是台灣網段（>= 1000），否則不是
    fn ans(d: u32, tw: bool) -> (u32, u32) {
        (d, if tw { 1000 + d } else { d + 1 })
    }

    #[test]
    fn tw_rate_denominator_excludes_sites_without_tw_nodes() {
        // 12 個網域有台灣節點（a 全部回台灣、b 一半）；另外 6 個網域在台灣根本沒有節點（誰都沒回過台灣 IP）
        let a: Vec<(u32, u32)> = (0..12).map(|d| ans(d, true)).chain((20..26).map(|d| ans(d, false))).collect();
        let b: Vec<(u32, u32)> = (0..12).map(|d| ans(d, d % 2 == 0)).chain((20..26).map(|d| ans(d, false))).collect();
        let c: Vec<(u32, u32)> = (20..26).map(|d| ans(d, false)).collect();
        let mut v = vec![
            srv("a", "A__AS1", 10.0, &a),
            srv("b", "B__AS2", 10.0, &b),
            srv("c", "C__AS3", 10.0, &c),
        ];
        tw_rates(&mut v, |ip| ip >= 1000);
        assert_eq!(v[0].tw_rate, Some(1.0), "分母是 12，不是 18");
        assert_eq!(v[1].tw_rate, Some(0.5));
        assert_eq!(v[2].tw_rate, Some(0.0));
    }

    #[test]
    fn tw_rate_none_when_few_domains() {
        let a: Vec<(u32, u32)> = (0..9).map(|d| ans(d, true)).chain((20..40).map(|d| ans(d, false))).collect();
        let mut v = vec![srv("a", "A__AS1", 10.0, &a)];
        tw_rates(&mut v, |ip| ip >= 1000);
        assert_eq!(v[0].tw_rate, None, "分母只有 9 個網域");
        // 沒有台灣網段資料：一律 None
        tw_rates(&mut v, |_| false);
        assert_eq!(v[0].tw_rate, None);
    }

    fn with_tw(mut s: Scored, r: Option<f32>) -> Scored {
        s.tw_rate = r;
        s
    }

    #[test]
    fn tie_break_prefers_higher_tw_rate_only_within_ten_percent() {
        let items = |base: u32, n: u32| -> Vec<(u32, u32)> { (0..n).map(|k| (1, base + k)).collect() };
        let mk = |x_tw: f32, y_n: u32| {
            let mut v = vec![
                with_tw(srv("f", "F__AS1", 1.0, &[(0, 1)]), Some(0.1)),
                with_tw(srv("x", "X__AS2", 10.0, &items(100, 10)), Some(x_tw)),
                with_tw(srv("y", "Y__AS3", 20.0, &items(200, y_n)), Some(0.8)),
                with_tw(srv("z", "Z__AS4", 5.0, &items(300, 8)), Some(0.9)),
            ];
            extended_metrics(&mut v, 10);
            v
        };
        let o = SelectOpts {
            max_n: 2,
            ..Default::default()
        };
        let run = |v: &Vec<Scored>| {
            let refs: Vec<&Scored> = v.iter().collect();
            picks(&select(&refs, &best_per_asn(&refs), 100, &o))
        };
        // y 新增 9、x 新增 10：差在 10% 以內 → 台灣率高的 y；z 新增 8（差超過 10%）台灣率再高也不選
        assert_eq!(run(&mk(0.2, 9)), vec![(0, 1, "最快"), (2, 9, "覆蓋")]);
        // y 只有 8：差超過 10% → 照舊選新增最多的 x
        assert_eq!(run(&mk(0.2, 8)), vec![(0, 1, "最快"), (1, 10, "覆蓋")]);
        // x 的台灣率本來就最高 → 照舊
        assert_eq!(run(&mk(0.95, 9)), vec![(0, 1, "最快"), (1, 10, "覆蓋")]);
        // 報表的貪婪（greedy_csv）不看台灣率
        let v = mk(0.2, 9);
        let refs: Vec<&Scored> = v.iter().collect();
        let (steps, _) = greedy(&refs[1..], 100, Strategy::Coverage, &HashSet::new());
        assert_eq!(steps[0].idx, 0, "x");
    }

    #[test]
    fn no_tw_data_matches_previous_selection() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for round in 0..300 {
            let n = 2 + rnd(12) as usize;
            let mut v: Vec<Scored> = (0..n)
                .map(|i| {
                    let items: Vec<(u32, u32)> = (0..rnd(12)).map(|_| (rnd(4) as u32, rnd(16) as u32)).collect();
                    let mut s = srv(&format!("s{i}"), &format!("O{i}__AS{i}"), (rnd(30) * 10) as f64, &items);
                    s.count = 9 + rnd(2) as usize;
                    s
                })
                .collect();
            extended_metrics(&mut v, 10);
            v.sort_by(|a, b| a.avg.partial_cmp(&b.avg).unwrap());
            let refs: Vec<&Scored> = v.iter().collect();
            let asn = best_per_asn(&refs);
            let o = SelectOpts {
                max_n: 1 + rnd(5) as usize,
                min_auto: rnd(5) as usize,
                ..Default::default()
            };
            let want = select_337(&refs, &asn, 60, &o);
            // 沒有台灣網段資料（None）、或每台一樣：跟 3.3.7 逐項相同
            assert_eq!(select(&refs, &asn, 60, &o), want, "第 {round} 組（None）");
            let same: Vec<Scored> = v.iter().cloned().map(|s| with_tw(s, Some(0.5))).collect();
            let refs2: Vec<&Scored> = same.iter().collect();
            assert_eq!(select(&refs2, &asn, 60, &o), want, "第 {round} 組（一樣的台灣率）");
        }
    }
}

#[cfg(test)]
mod sticky_tests {
    use super::*;

    fn srv(id: &str, asn: u32, avg: f64, items: std::ops::Range<u32>, incumbent: u8) -> Scored {
        Scored {
            id: id.into(),
            kind: "doh".into(),
            owner: format!("X{asn}__AS{asn}_X"),
            avg,
            count: 10,
            history: vec![(0, items.collect())],
            incumbent,
            ..Default::default()
        }
    }

    fn opts(max_n: usize) -> SelectOpts {
        SelectOpts {
            auto_types: vec!["doh".into()],
            max_n,
            min_auto: 1,
            coverage_target: 1.0,
            ..Default::default()
        }
    }

    fn run(v: &mut [Scored], max_n: usize) -> (Vec<String>, Vec<String>) {
        extended_metrics(v, 1);
        v.sort_by(|a, b| a.avg.partial_cmp(&b.avg).unwrap());
        let refs: Vec<&Scored> = v.iter().collect();
        let asn = best_per_asn(&refs);
        let s = select(&refs, &asn, 1000, &opts(max_n));
        (
            s.selected.iter().map(|p| refs[p.idx].id.clone()).collect(),
            s.kept.iter().map(|&i| refs[i].id.clone()).collect(),
        )
    }

    /// 3.5.1（M3）：「最快」昨天選上的延遲在今天最快的 15% 以內就留昨天那台；同一台優先於同一個經營者的別的寫法
    #[test]
    fn fastest_keeps_yesterday_within_15_percent() {
        let mut v = vec![srv("new", 1, 3.2, 0..5, 0), srv("old", 2, 3.6, 5..10, 2)];
        assert_eq!(run(&mut v, 1), (vec!["old".to_string()], vec!["old".to_string()]));
        let mut v = vec![srv("new", 1, 3.2, 0..5, 0), srv("old", 2, 3.8, 5..10, 2)];
        assert_eq!(run(&mut v, 1).0, vec!["new"], "差超過 15%：換");
        let mut v = vec![
            srv("new", 1, 3.2, 0..5, 0),
            srv("same-op", 2, 3.3, 5..10, 1),
            srv("old", 3, 3.5, 10..15, 2),
        ];
        assert_eq!(run(&mut v, 1).0, vec!["old"], "同一台優先");
        // 沒有昨天的資料：跟以前一樣
        let mut v = vec![srv("new", 1, 3.2, 0..5, 0), srv("old", 2, 3.6, 5..10, 0)];
        assert_eq!(run(&mut v, 1), (vec!["new".to_string()], vec![]));
    }

    /// 「覆蓋」：新增覆蓋在今天最多的 85% 以上的昨天選上的就留它；差太多、台灣率比較低的照換
    #[test]
    fn coverage_keeps_yesterday_within_15_percent() {
        let base = || srv("fast", 9, 1.0, 0..1, 0);
        let mut v = vec![base(), srv("more", 1, 50.0, 100..200, 0), srv("old", 2, 60.0, 300..390, 2)];
        let (sel, kept) = run(&mut v, 2);
        assert_eq!(sel, vec!["fast", "old"]);
        assert_eq!(kept, vec!["old"]);
        let mut v = vec![base(), srv("more", 1, 50.0, 100..200, 0), srv("old", 2, 60.0, 300..380, 2)];
        assert_eq!(run(&mut v, 2).0, vec!["fast", "more"], "新增覆蓋少超過 15%：換");
        let mut v = vec![base(), srv("more", 1, 50.0, 100..200, 0), srv("old", 2, 60.0, 300..390, 2)];
        v[1].tw_rate = Some(0.5);
        v[2].tw_rate = Some(0.4);
        assert_eq!(run(&mut v, 2).0, vec!["fast", "more"], "台灣率比較低的不留");
    }
}
