//! CDNtest Step3 + Step4（對齊 2.x `jobs/cdn-pool.js`）：從 TW 網段與實際流量收集的候選 IP 中，
//! 依「丟包 → 下載速度 → 延遲」選出台灣節點池；同時嘗試建立 IPv6 台灣節點池。
//! 沒有台灣 POP 的 CDN（Fastly）改找品質最好的鄰近節點（`build_nearest`）。
//!
//! 結果直接換掉記憶體裡的節點池（`Pools::replace`），pools.json 由外層的快照寫入。

use super::{v4_lines, JobCtx, Rng};
use crate::cdn::Cdn;
use crate::health::map_limit;
use crate::pools::{qscore, weighted_qscore, PoolNode};
use crate::providers::{self, is_tw_pop, Provider};
use crate::util::{self, intern, now_ms, Num};
use anyhow::Result;
use indexmap::{IndexMap, IndexSet};
use kuroshio_net::probe::HttpsOpts;
use kuroshio_proto::message::rtype;
use serde_json::{json, Map, Value};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProviderPool {
    pub provider: String,
    pub v4: Vec<IpAddr>,
    pub v6: Vec<IpAddr>,
    /// 沒找到新節點、保留舊的
    pub kept_old: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    pub v6_ok: bool,
    pub providers: Vec<ProviderPool>,
}

/// 連 n 次 TCP 443：（掉包率，平均延遲）
async fn measure(cdn: &Cdn, ip: IpAddr, n: u32) -> (f64, f64) {
    let (mut ok, mut sum) = (0u32, 0.0);
    for _ in 0..n {
        let r = cdn.net().tcp_ping(ip, Duration::from_millis(1000), 1).await;
        if r.ok {
            ok += 1;
            sum += r.ms;
        }
    }
    ((n - ok) as f64 / n as f64, if ok > 0 { sum / ok as f64 } else { f64::INFINITY })
}

async fn has_ipv6(cdn: &Cdn) -> bool {
    for ip in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
        if cdn.net().tcp_ping(ip.parse().unwrap(), Duration::from_millis(1500), 1).await.ok {
            return true;
        }
    }
    false
}

/// 帶各個台灣子網路查詢，收集所有 IP
async fn ecs_resolve(cdn: &Cdn, name: &str, qtype: u16, subnets: &[String]) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for s in subnets {
        for ip in cdn.resolve_with_ecs(name, qtype, Some(s)).await {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

fn p24(ip: IpAddr) -> Option<u32> {
    util::prefix24(ip)
}

/// 一家 CDN 目前的節點池與 pools.json 裡的其他欄位
struct Prev {
    v4: Vec<PoolNode>,
    v6: Vec<PoolNode>,
    rest: Map<String, Value>,
}

fn prev_of(cdn: &Cdn, name: &str) -> Prev {
    let st = cdn.state();
    match st.pools.p.get(name) {
        Some(d) => Prev {
            v4: d.pool4.clone(),
            v6: d.pool6.clone(),
            rest: d.rest.clone(),
        },
        None => Prev {
            v4: vec![],
            v6: vec![],
            rest: Map::new(),
        },
    }
}

#[derive(Debug, Clone)]
struct Scored {
    ip: IpAddr,
    pop: String,
    ms: f64,
    jitter: f64,
    loss: f64,
    speed: Option<f64>,
    score: f64,
}

impl Scored {
    fn node(&self) -> PoolNode {
        let mut n = PoolNode::new(self.ip);
        n.ms = Num::V(self.ms);
        n.jitter = Num::V(self.jitter);
        n.loss = Num::V(self.loss);
        n.speed = Num::opt(self.speed);
        n
    }
}

/// 沒有台灣 POP 的 CDN（Fastly）：掃過官方所有 /24，找出各鄰近 POP（香港 / 東京 / 大阪 / 新加坡…），
/// 每個 POP 挑最好的幾個網段，用「延遲 + 抖動 + 掉包 + 下載速度」評分，留前幾個 POP 當主力與備援。
/// 回傳（節點池，每個 POP 的所有網段）
async fn build_nearest(ctx: &JobCtx, prov: &'static Provider, prev: &Prev, rng: &mut Rng) -> (Vec<PoolNode>, IndexMap<String, Vec<u32>>) {
    let cdn = ctx.cdn.clone();
    let jc = ctx.jobs_cfg();
    let name = prov.name;
    let max_lat = cdn.cfg.provider(name).and_then(|p| p.max_latency_ms).unwrap_or(150.0);
    // 1. 候選：官方範圍每個 /24 抽一個 IP ＋ 實際流量看到的 IP ＋ 舊節點池
    let mut cand: IndexMap<u32, IpAddr> = IndexMap::new();
    for cidr in v4_lines(cdn.paths.read_cdn_text(&format!("ranges/{name}-ipv4.txt"))) {
        let (base, bits) = cidr.split_once('/').unwrap_or((&cidr, "32"));
        let (Ok(b), Ok(bits)) = (base.parse::<Ipv4Addr>(), bits.parse::<u32>()) else {
            continue;
        };
        let start = u32::from(b) as u64;
        let count = (1u64 << (32 - bits.min(24))) / 256;
        for i in 0..count {
            let s = start + i * 256;
            if s + 255 > u32::MAX as u64 {
                break;
            }
            cand.insert((s >> 8) as u32, IpAddr::V4(Ipv4Addr::from((s + 10 + rng.below(200)) as u32)));
        }
    }
    for ip in cdn.state().db.harvest_of(name, false) {
        if let Some(p) = p24(ip) {
            cand.insert(p, ip);
        }
    }
    for x in &prev.v4 {
        if let Some(p) = p24(x.ip) {
            cand.insert(p, x.ip);
        }
    }
    info!("{} 官方沒有台灣 POP：掃描 {} 個 /24，找品質最好的鄰近節點", prov.label, cand.len());

    // 2. 粗篩延遲（3 次）
    let c2 = cdn.clone();
    let lat = map_limit(cand.values().copied().collect(), jc.latency_concurrency, move |ip| {
        let c = c2.clone();
        async move { (ip, measure(&c, ip, 3).await) }
    })
    .await;
    let mut ok: Vec<(IpAddr, f64)> = lat
        .into_iter()
        .flatten()
        .filter(|(_, (l, m))| *l < 1.0 && *m <= max_lat)
        .map(|(ip, (_, m))| (ip, m))
        .collect();
    ok.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    info!("粗篩：{} 個 /24 可連線且 ≤ {max_lat}ms", ok.len());

    // 3. 判定 POP：先用 HTTP 80 埠＋Host；80 埠被擋就改用 HTTPS，IP 換成探測網站自己的最後一段
    let (host, path) = prov.probe.unwrap_or(("", "/"));
    let last_of = |ips: Vec<IpAddr>| ips.into_iter().find(|i| i.is_ipv4()).and_then(util::last_octet);
    let octet = last_of(cdn.net().resolve_host(host).await);
    let c3 = cdn.clone();
    ok.truncate(jc.nearest_probe_top);
    let with_pop = map_limit(ok, jc.probe_concurrency, move |(ip, ms): (IpAddr, f64)| {
        let c = c3.clone();
        async move {
            let mut r = c.net().http_probe(ip, host, path, Duration::from_millis(3000)).await;
            if !(r.ok && !prov.pop(&r.headers, &r.body).is_empty()) {
                if let (Some(o), Some(p)) = (octet, p24(ip)) {
                    let opts = HttpsOpts {
                        timeout: Duration::from_millis(3000),
                        ..Default::default()
                    };
                    r = c.net().https_probe(util::ip_of(p, o), host, path, opts).await;
                }
            }
            let pop: String = if r.ok {
                prov.pop(&r.headers, &r.body).chars().take(3).collect()
            } else {
                String::new()
            };
            (ip, ms, pop)
        }
    })
    .await;
    let mut by_pop: IndexMap<String, Vec<(IpAddr, f64)>> = IndexMap::new();
    let mut prefixes: IndexMap<String, Vec<u32>> = IndexMap::new();
    for (ip, ms, pop) in with_pop.into_iter().flatten().filter(|x| !x.2.is_empty()) {
        let a = by_pop.entry(pop.clone()).or_default();
        if a.len() < 4 {
            a.push((ip, ms));
        }
        if let Some(p) = p24(ip) {
            prefixes.entry(pop).or_default().push(p);
        }
    }
    let mut dist: Vec<(&String, usize)> = prefixes.iter().map(|(k, v)| (k, v.len())).collect();
    dist.sort_by_key(|x| std::cmp::Reverse(x.1));
    info!(
        "POP 分布：{}",
        dist.iter().map(|(k, n)| format!("{k} {n}")).collect::<Vec<_>>().join("、")
    );

    // 4. 品質：每個 POP 最好的 4 個網段，各連 10 次（中位數延遲、抖動、掉包）
    let mut pops: Vec<(String, Vec<(IpAddr, f64)>)> = by_pop.into_iter().collect();
    pops.sort_by(|a, b| a.1[0].1.partial_cmp(&b.1[0].1).unwrap_or(std::cmp::Ordering::Equal));
    pops.truncate(jc.nearest_pops);
    let mut scored: Vec<Scored> = Vec::new();
    for (pop, list) in &pops {
        for (ip, _) in list {
            let q = cdn
                .net()
                .quality(*ip, 10, Duration::from_millis(1500), Duration::from_millis(80))
                .await;
            scored.push(Scored {
                ip: *ip,
                pop: pop.clone(),
                ms: q.ms,
                jitter: q.jitter,
                loss: q.loss,
                speed: None,
                score: f64::INFINITY,
            });
        }
    }

    // 5. 下載速度：前 5 個 POP 各測最好的 2 個網段
    // HTTP 網址直接用候選 IP；HTTPS 網址要換成該網站自己的最後一段（憑證才對）
    if let Some(url) = prov.speed_url {
        let plain = url.starts_with("http:");
        let s_octet = if plain {
            None
        } else {
            let h = url.split("://").nth(1).and_then(|r| r.split(['/', ':', '?']).next()).unwrap_or("");
            if h == host {
                octet
            } else {
                last_of(cdn.net().resolve_host(h).await)
            }
        };
        if plain || s_octet.is_some() {
            let qs = |x: &Scored| qscore(&x.node());
            let pop_score = |pop: &str, sc: &[Scored]| sc.iter().filter(|x| x.pop == pop).map(qs).fold(f64::INFINITY, f64::min);
            let mut top: Vec<String> = Vec::new();
            for x in &scored {
                if !top.contains(&x.pop) {
                    top.push(x.pop.clone());
                }
            }
            top.sort_by(|a, b| {
                pop_score(a, &scored)
                    .partial_cmp(&pop_score(b, &scored))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            top.truncate(5);
            for pop in top {
                let mut idx: Vec<usize> = (0..scored.len()).filter(|&i| scored[i].pop == pop).collect();
                idx.sort_by(|&a, &b| qs(&scored[a]).partial_cmp(&qs(&scored[b])).unwrap_or(std::cmp::Ordering::Equal));
                for i in idx.into_iter().take(2) {
                    let target = if plain {
                        scored[i].ip
                    } else {
                        util::ip_of(p24(scored[i].ip).unwrap(), s_octet.unwrap())
                    };
                    scored[i].speed = Some(cdn.net().download_speed(target, url, jc.speed_seconds * 1000).await);
                }
            }
        }
    }
    for x in scored.iter_mut() {
        x.score = qscore(&x.node());
    }

    // 6. 報表：每個 POP 最好的一個
    let mut summary: Vec<Scored> = Vec::new();
    for x in &scored {
        match summary.iter_mut().find(|s| s.pop == x.pop) {
            Some(s) if x.score < s.score => *s = x.clone(),
            Some(_) => {}
            None => summary.push(x.clone()),
        }
    }
    summary.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal));
    for b in &summary {
        info!(
            "{:<5}  {:>6}ms {:>5.1}ms {:>4}%  {}  {}",
            b.pop,
            if b.ms.is_finite() { format!("{:.1}", b.ms) } else { "—".into() },
            b.jitter,
            (b.loss * 100.0).round(),
            b.speed.map(|s| format!("{s} MB/s")).unwrap_or_else(|| "—".into()),
            if b.score.is_finite() {
                format!("{:.1}", b.score)
            } else {
                "—".into()
            }
        );
    }

    // 7. 節點池：分數最好的幾個 POP，各留最好的 3 個網段（有些憑證組只放在特定 POP）
    let keep: Vec<String> = summary
        .iter()
        .filter(|b| b.score.is_finite())
        .take(jc.nearest_keep_pops)
        .map(|b| b.pop.clone())
        .collect();
    let mut pool: Vec<Scored> = Vec::new();
    for pop in &keep {
        let mut l: Vec<Scored> = scored.iter().filter(|x| &x.pop == pop && x.score.is_finite()).cloned().collect();
        l.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal));
        pool.extend(l.into_iter().take(3));
    }
    pool.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal));
    if keep.is_empty() {
        info!("沒有找到可用的鄰近節點");
    } else {
        info!(
            "主力 {}{}",
            keep[0],
            if keep.len() > 1 {
                format!("，備援 {}", keep[1..].join(" / "))
            } else {
                String::new()
            }
        );
    }
    let nodes = pool
        .iter()
        .map(|x| {
            let mut n = PoolNode::new(x.ip);
            n.pop = Some(intern(&x.pop));
            n.ms = Num::V(util::round(x.ms, 2));
            n.jitter = Num::V(util::round(x.jitter, 2));
            n.loss = Num::V(util::round(x.loss, 2));
            n.speed = match x.speed {
                Some(s) if s != 0.0 => Num::V(s),
                _ => Num::Null,
            };
            n.score = Num::V(util::round(x.score, 1));
            n
        })
        .collect();
    (nodes, prefixes)
}

/// 尖峰時段的量測沿用舊節點池同一個 IP 的紀錄（規格 06 第 3.2 節），分數重新加權
fn carry_peak(nodes: &mut [PoolNode], prev: &[PoolNode], w: f64, rescore: bool) {
    let now = now_ms();
    for n in nodes.iter_mut() {
        let Some(p) = prev.iter().find(|p| p.ip == n.ip && p.peak_fresh(now)) else {
            continue;
        };
        n.peak_ms = p.peak_ms;
        n.peak_jitter = p.peak_jitter;
        n.peak_loss = p.peak_loss;
        n.peak_at = p.peak_at;
        if rescore {
            n.score = Num::V(util::round(weighted_qscore(n, w, now), 1));
        }
    }
}

/// 執行：建好的節點池直接換進記憶體
pub async fn run(ctx: &JobCtx) -> Result<Report> {
    let cdn = ctx.cdn.clone();
    let jc = ctx.jobs_cfg();
    let pool_size = jc.pool_size.max(1);
    let subnets = cdn.ecs_subnets();
    let v6ok = has_ipv6(&cdn).await;
    info!(
        "本機 IPv6 連線：{}",
        if v6ok {
            "可用"
        } else {
            "不可用（只建立 IPv4 節點池，CDN 的 AAAA 依設定丟棄）"
        }
    );
    let mut rng = Rng::new();
    let mut report = Report {
        v6_ok: v6ok,
        ..Default::default()
    };
    let w = cdn.cfg.peak_weight;

    for prov in providers::PROVIDERS {
        let name = prov.name;
        if !ctx.wants(name) || !prov.alias {
            continue;
        }
        let pc = cdn.cfg.provider(name).cloned().unwrap();
        let max_lat = pc.max_latency_ms.unwrap_or(prov.max_latency_ms);
        let prev = prev_of(&cdn, name);
        info!("========== {} ==========", prov.label);
        let updated = util::iso(now_ms());

        if prov.nearest {
            let (mut pool4, built_prefixes) = build_nearest(ctx, prov, &prev, &mut rng).await;
            let mut rest = prev.rest.clone();
            rest.insert("updatedAt".into(), json!(updated));
            rest.insert("tw48".into(), json!([]));
            if !built_prefixes.is_empty() {
                let pf: Map<String, Value> = built_prefixes
                    .iter()
                    .map(|(k, v)| (k.clone(), json!(v.iter().map(|p| util::prefix24_str(*p)).collect::<Vec<_>>())))
                    .collect();
                rest.insert("prefixes".into(), Value::Object(pf));
            } else if !rest.contains_key("prefixes") {
                rest.insert("prefixes".into(), json!({}));
            }
            let kept = pool4.is_empty();
            if kept {
                info!("保留舊的節點池");
                pool4 = prev.v4.clone();
            } else {
                carry_peak(&mut pool4, &prev.v4, w, true);
            }
            info!(
                "節點池：IPv4 {} 個網段 → {}",
                pool4.len(),
                pool4
                    .iter()
                    .map(|x| format!("{}({})", x.ip, x.pop_str()))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            report.providers.push(ProviderPool {
                provider: name.to_string(),
                v4: pool4.iter().map(|x| x.ip).collect(),
                v6: vec![],
                kept_old: kept,
            });
            cdn.with_state(|st| st.pools.replace(name, pool4, vec![], rest));
            continue;
        }

        // ---------- 收集 IPv4 候選 ----------
        let mut cand: IndexSet<IpAddr> = IndexSet::new();
        let mut tw24 = v4_lines(cdn.paths.read_cdn_text(&format!("scan/{name}-ipv4-TW.txt")));
        rng.shuffle(&mut tw24);
        let limit = jc.candidates_per_provider;
        for c in tw24.iter().take(limit.div_ceil(2)) {
            let Some(base) = c.split('/').next().and_then(|b| b.parse::<Ipv4Addr>().ok()) else {
                continue;
            };
            let b = u32::from(base);
            cand.insert(IpAddr::V4(Ipv4Addr::from(b.wrapping_add(1 + rng.below(126) as u32))));
            cand.insert(IpAddr::V4(Ipv4Addr::from(b.wrapping_add(128 + rng.below(126) as u32))));
        }
        for x in &prev.v4 {
            cand.insert(x.ip);
        }
        for s in &pc.seed_v4 {
            if let Some(ip) = util::parse_ip(s) {
                cand.insert(ip);
            }
        }
        let harvest4 = cdn.state().db.harvest_of(name, false);
        for ip in &harvest4 {
            cand.insert(*ip);
        }
        for h in prov.seed_hosts {
            for ip in ecs_resolve(&cdn, h, rtype::A, &subnets).await.into_iter().filter(|i| i.is_ipv4()) {
                cand.insert(ip);
            }
        }
        info!(
            "IPv4 候選 {} 個（TW 網段 {}、實際流量收集 {}）",
            cand.len(),
            tw24.len(),
            harvest4.len()
        );

        // ---------- 階段 A：延遲 / 丟包 ----------
        let c = cdn.clone();
        let lat = map_limit(cand.into_iter().collect(), jc.latency_concurrency, move |ip| {
            let c = c.clone();
            async move { (ip, measure(&c, ip, 4).await) }
        })
        .await;
        let mut good: Vec<(IpAddr, f64)> = lat
            .into_iter()
            .flatten()
            .filter(|(_, (l, m))| *l == 0.0 && *m <= max_lat)
            .map(|(ip, (_, m))| (ip, m))
            .collect();
        good.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        info!("階段 A 延遲：{} 個 0% 丟包且 ≤ {max_lat}ms", good.len());

        // ---------- 階段 B：確認是台灣 POP ----------
        let (host, path) = prov.probe.unwrap_or(("", "/"));
        good.truncate(120);
        let c = cdn.clone();
        let checked = map_limit(good, jc.probe_concurrency, move |(ip, ms): (IpAddr, f64)| {
            let c = c.clone();
            async move {
                let r = c.net().http_probe(ip, host, path, Duration::from_millis(3000)).await;
                (ip, ms, if r.ok { prov.pop(&r.headers, &r.body) } else { String::new() })
            }
        })
        .await;
        let mut seen24 = std::collections::HashSet::new();
        // 每個 /24 只留最快的一個，提高多樣性
        let mut good: Vec<Scored> = checked
            .into_iter()
            .flatten()
            .filter(|x| is_tw_pop(&x.2))
            .filter(|x| seen24.insert(p24(x.0)))
            .map(|(ip, ms, pop)| Scored {
                ip,
                pop,
                ms,
                jitter: 0.0,
                loss: 0.0,
                speed: None,
                score: 0.0,
            })
            .collect();
        let mut pops_seen: Vec<&str> = Vec::new();
        for x in &good {
            if !pops_seen.contains(&x.pop.as_str()) {
                pops_seen.push(&x.pop);
            }
        }
        info!("階段 B POP：{} 個確認在台灣（{}）", good.len(), pops_seen.join(", "));

        // ---------- 階段 C：下載測速 ----------
        if let Some(url) = prov.speed_url {
            for x in good.iter_mut().take(jc.speed_top) {
                x.speed = Some(cdn.net().download_speed(x.ip, url, jc.speed_seconds * 1000).await);
                info!(
                    "  測速 {:<16} {}  {:.1}ms  {} MB/s",
                    x.ip.to_string(),
                    x.pop,
                    x.ms,
                    x.speed.unwrap_or(0.0)
                );
            }
        }
        // 階段 A 同時測很多個，本機會塞車、延遲偏高：決選名單用低並行重新量一次
        let finalists: Vec<IpAddr> = good.iter().take(pool_size * 2).map(|x| x.ip).collect();
        let c = cdn.clone();
        let rq = map_limit(finalists, 4, move |ip| {
            let c = c.clone();
            async move {
                (
                    ip,
                    c.net().quality(ip, 5, Duration::from_millis(1500), Duration::from_millis(50)).await,
                )
            }
        })
        .await;
        for (ip, q) in rq.into_iter().flatten() {
            if q.ms.is_finite() {
                if let Some(x) = good.iter_mut().find(|x| x.ip == ip) {
                    x.ms = q.ms;
                    x.loss = q.loss;
                }
            }
        }
        // 排序：丟包 → 速度 → 延遲
        good.sort_by(|a, b| {
            a.loss
                .partial_cmp(&b.loss)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(
                    b.speed
                        .unwrap_or(0.0)
                        .partial_cmp(&a.speed.unwrap_or(0.0))
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
                .then(a.ms.partial_cmp(&b.ms).unwrap_or(std::cmp::Ordering::Equal))
        });
        let mut pool4: Vec<PoolNode> = good
            .iter()
            .take(pool_size)
            .map(|x| {
                let mut n = PoolNode::new(x.ip);
                n.ms = Num::V(util::round(x.ms, 2));
                n.speed = match x.speed {
                    Some(s) if s != 0.0 => Num::V(s),
                    _ => Num::Null,
                };
                n.pop = Some(intern(&x.pop));
                n
            })
            .collect();
        let kept = pool4.is_empty();
        if kept {
            info!("沒有找到可用的台灣 IPv4 節點，保留舊的節點池");
            pool4 = prev.v4.clone();
        } else {
            carry_peak(&mut pool4, &prev.v4, w, false);
        }

        // ---------- IPv6：收集 → 判定 POP → 建池（台灣節點永久保存，失效才移除） ----------
        let mut pool6 = prev.v6.clone();
        let mut tw48: Vec<String> = prev
            .rest
            .get("tw48")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let permanent = cdn.state().v6.list(name);
        if v6ok {
            let mut c6: IndexSet<IpAddr> = cdn.state().db.harvest_of(name, true).into_iter().collect();
            c6.extend(prev.v6.iter().map(|x| x.ip));
            c6.extend(pc.seed_v6.iter().filter_map(|s| util::parse_ip(s)));
            for h in prov.seed_hosts {
                c6.extend(
                    ecs_resolve(&cdn, h, rtype::AAAA, &subnets)
                        .await
                        .into_iter()
                        .filter(|i| i.is_ipv6()),
                );
            }
            // 一般候選每個 /48 最多測 3 個；永久紀錄的節點每個都要測
            let mut per48: IndexMap<u128, Vec<IpAddr>> = IndexMap::new();
            for ip in c6 {
                let Some(k) = util::v6_48(ip) else { continue };
                let a = per48.entry(k).or_default();
                if a.len() < 3 {
                    a.push(ip);
                }
            }
            let mut list: IndexSet<IpAddr> = permanent.iter().map(|x| x.ip).collect();
            list.extend(per48.values().flatten().copied());
            info!(
                "IPv6 候選 {} 個（永久紀錄 {}、{} 個 /48）",
                list.len(),
                permanent.len(),
                per48.len()
            );
            let c = cdn.clone();
            let r6 = map_limit(list.into_iter().collect(), jc.probe_concurrency, move |ip| {
                let c = c.clone();
                async move {
                    let r = c.net().http_probe(ip, host, path, Duration::from_millis(3000)).await;
                    let pop = if r.ok { prov.pop(&r.headers, &r.body) } else { String::new() };
                    if !r.ok || pop.is_empty() {
                        return (ip, "dead", pop, f64::INFINITY);
                    }
                    if !is_tw_pop(&pop) {
                        return (ip, "nottw", pop, f64::INFINITY);
                    }
                    let (loss, ms) = measure(&c, ip, 4).await;
                    if loss == 0.0 {
                        (ip, "tw", pop, ms)
                    } else {
                        (ip, "dead", pop, ms)
                    }
                }
            })
            .await;
            let r6: Vec<_> = r6.into_iter().flatten().collect();
            let net_ok = r6.iter().any(|x| x.1 != "dead");
            let (mut added, mut removed) = (0, 0);
            cdn.with_state(|st| {
                for (ip, s, pop, ms) in &r6 {
                    match *s {
                        "tw" => {
                            if st.v6.mark_ok(name, *ip, pop, Some(*ms)) {
                                added += 1;
                                info!("  ★ 新的台灣 IPv6 節點 {ip} ({pop} {ms:.1}ms)，已永久保存");
                            }
                        }
                        "nottw" => {
                            if st.v6.mark_not_tw(name, *ip) {
                                removed += 1;
                                info!("  移除 {ip}：POP 變成 {pop}");
                            }
                        }
                        _ => {
                            if net_ok && st.v6.mark_dead(name, *ip) {
                                removed += 1;
                                info!("  移除 {ip}：連續 {} 次失效", crate::v6store::FAIL_LIMIT);
                            }
                        }
                    }
                }
            });
            let mut tw6: Vec<&(IpAddr, &str, String, f64)> = r6.iter().filter(|x| x.1 == "tw").collect();
            tw6.sort_by(|a, b| a.3.partial_cmp(&b.3).unwrap_or(std::cmp::Ordering::Equal));
            let mut seen = std::collections::HashSet::new();
            let uniq: Vec<_> = tw6.iter().filter(|x| seen.insert(util::v6_48(x.0))).collect();
            for x in &tw6 {
                let k = util::subnet_key(x.0);
                if !tw48.contains(&k) {
                    tw48.push(k);
                }
            }
            if !uniq.is_empty() {
                pool6 = uniq
                    .iter()
                    .take(pool_size)
                    .map(|x| {
                        let mut n = PoolNode::new(x.0);
                        n.ms = Num::V(util::round(x.3, 2));
                        n.pop = Some(intern(&x.2));
                        n
                    })
                    .collect();
            } else if !net_ok {
                info!("IPv6 探測全部無回應，疑似本機網路問題，保留舊節點池與永久紀錄");
            }
            let mut abroad: Vec<&str> = Vec::new();
            for x in r6.iter().filter(|x| x.1 == "nottw") {
                if !abroad.contains(&x.2.as_str()) && abroad.len() < 10 {
                    abroad.push(&x.2);
                }
            }
            info!(
                "IPv6 台灣節點：本次確認 {} 個（新增永久 {added}、移除 {removed}，永久紀錄共 {}）；其他 POP：{}",
                tw6.len(),
                cdn.state().v6.count(name),
                if abroad.is_empty() { "無".to_string() } else { abroad.join(", ") }
            );
        } else if !permanent.is_empty() {
            info!("本機目前沒有 IPv6，無法檢查；保留 {} 個永久紀錄的台灣 v6 節點", permanent.len());
        }
        // 永久保存的台灣 v6 節點一律併入（同 2.x 載入節點池時的處理）
        for k in cdn.state().v6.list(name) {
            if !pool6.iter().any(|x| x.ip == k.ip) {
                let mut n = PoolNode::new(k.ip);
                n.ms = k.node.ms;
                n.pop = k.node.pop.as_deref().map(intern);
                n.permanent = Some(true);
                pool6.push(n);
            }
        }
        pool6.sort_by(|a, b| a.ms.or(999.0).partial_cmp(&b.ms.or(999.0)).unwrap_or(std::cmp::Ordering::Equal));

        info!(
            "節點池：IPv4 {} 個 → {}",
            pool4.len(),
            pool4.iter().map(|x| x.ip.to_string()).collect::<Vec<_>>().join(", ")
        );
        if !pool6.is_empty() {
            info!("節點池：IPv6 {} 個", pool6.len());
        }
        let mut rest = prev.rest.clone();
        rest.insert("updatedAt".into(), json!(updated));
        rest.insert("tw48".into(), json!(tw48));
        report.providers.push(ProviderPool {
            provider: name.to_string(),
            v4: pool4.iter().map(|x| x.ip).collect(),
            v6: pool6.iter().map(|x| x.ip).collect(),
            kept_old: kept,
        });
        cdn.with_state(|st| st.pools.replace(name, pool4, pool6, rest));
    }
    Ok(report)
}

/// 方便外層用：節點池工作的 `Arc<Cdn>` 版本
pub async fn run_for(cfg: Value, cdn: Arc<Cdn>, only: Option<String>) -> Result<Report> {
    let ctx = JobCtx { cfg, cdn, only };
    run(&ctx).await
}
