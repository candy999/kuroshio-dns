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
    let mut covered = pre.clone();
    let mut result = Vec::new();
    let mut cands: Vec<usize> = (0..servers.len()).collect();
    while covered.len() < total {
        let mut best: Option<(usize, usize)> = None; // (cands 位置, 新增數)
        for (pos, &i) in cands.iter().enumerate() {
            let s = servers[i];
            let nw = s.items().filter(|k| !covered.contains(k)).count();
            if nw == 0 {
                continue;
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
        let Some((bp, bn)) = best else { break };
        let idx = cands.remove(bp);
        covered.extend(servers[idx].items());
        result.push(Step {
            idx,
            newly: bn,
            total: covered.len(),
        });
    }
    stable_sort_by_avg(&mut cands, servers);
    (result, cands)
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
}

impl Default for SelectOpts {
    fn default() -> SelectOpts {
        SelectOpts {
            auto_types: vec!["udp".into(), "doh".into(), "dot".into()],
            max_n: 5,
            max_avg: 250.0,
            coverage_target: 0.97,
            min_auto: 3,
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
}

/// Phase 3：選出執行期上游。`finals` 依延遲排序，`asn_best` 是 `best_per_asn(finals)`。
/// 先取最快的一台，再依「新增覆蓋最多」貪婪挑選，直到台數上限或覆蓋率達標；不足 minAuto 台時依速度補備援。
pub fn select(finals: &[&Scored], asn_best: &[usize], total: usize, o: &SelectOpts) -> Selection {
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

/// final_dns_smart.csv（`finals` 依延遲排序）
pub fn final_csv(finals: &[&Scored]) -> String {
    let mut csv = String::from("\u{feff}Rank,DNS_Server,Type,DNS_Owner,Min,Max,Avg,Count,Success_Rate,Total_IPs,Unique_IPs,Unique_Ratio_Self,Unique_Ratio_Global,Pinned\n");
    for (i, s) in finals.iter().enumerate() {
        let e = &s.ext;
        csv.push_str(&format!(
            "{},{},{},\"{}\",{},{},{},{},{},{},{},{},{},{}\n",
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
            if s.pinned { "Y" } else { "" }
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
}
