//! 節點池的網路檢查（對齊 2.x `pools.js` 的 `healthCheck` / `qualityCheck` / `tryV6`）

use crate::cdn::Cdn;
use crate::pools::{self, node_score, weighted_ms, weighted_qscore, Bad};
use crate::providers::{self, is_tw_pop};
use crate::util::{self, now_ms, Num};
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// 有上限的並行執行（結果依輸入順序；任務失敗的位置是 None）
pub async fn map_limit<T, R, F, Fut>(items: Vec<T>, limit: usize, f: F) -> Vec<Option<R>>
where
    T: Send + 'static,
    R: Send + 'static,
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
{
    let n = items.len();
    let f = Arc::new(f);
    let sem = Arc::new(tokio::sync::Semaphore::new(limit.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for (i, it) in items.into_iter().enumerate() {
        let f = f.clone();
        let sem = sem.clone();
        set.spawn(async move {
            let _p = sem.acquire_owned().await;
            (i, f(it).await)
        });
    }
    let mut out: Vec<Option<R>> = (0..n).map(|_| None).collect();
    while let Some(r) = set.join_next().await {
        if let Ok((i, v)) = r {
            out[i] = Some(v);
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HStatus {
    Tw,
    NotTw,
    Dead,
}

struct HResult {
    ip: IpAddr,
    status: HStatus,
    pop: String,
    ms: f64,
    reason: String,
}

impl Cdn {
    /// 定時健檢：確認池內 IP 仍是台灣 POP、仍可連線，並依延遲重新排序。回傳是否有變動
    pub async fn health_check(self: &Arc<Self>) -> bool {
        let mut changed = false;
        let names: Vec<&'static str> = self.state().pools.p.keys().copied().collect();
        for name in names {
            let Some(prov) = providers::get(name) else { continue };
            let Some((host, path)) = prov.probe else { continue };
            let nearest = prov.nearest;
            for family in [4u8, 6] {
                let list: Vec<(IpAddr, String)> = {
                    let st = self.state();
                    let Some(d) = st.pools.p.get(name) else { continue };
                    d.pool(family).iter().map(|x| (x.ip, x.pop_str().to_string())).collect()
                };
                if list.is_empty() || (family == 6 && self.net.v6_usable() == Some(false)) {
                    continue;
                }
                let net = self.net.clone();
                let results = map_limit(list, 16, move |(ip, old_pop): (IpAddr, String)| {
                    let net = net.clone();
                    async move {
                        let r = net.http_probe(ip, host, path, Duration::from_millis(3000)).await;
                        let pop = if r.ok { prov.pop(&r.headers, &r.body) } else { String::new() };
                        let lat = net.tcp_ping(ip, Duration::from_millis(1500), 2).await;
                        let p3 = |s: &str| s.chars().take(3).collect::<String>();
                        let same_near = nearest && !pop.is_empty() && !old_pop.is_empty() && p3(&pop) == p3(&old_pop);
                        let status = if r.ok && lat.ok && (is_tw_pop(&pop) || same_near) {
                            HStatus::Tw
                        } else if r.ok && !pop.is_empty() {
                            HStatus::NotTw
                        } else {
                            HStatus::Dead
                        };
                        let reason = if r.ok {
                            format!("POP={}", if pop.is_empty() { "?" } else { &pop })
                        } else {
                            r.error.clone().unwrap_or_else(|| "DEAD".into())
                        };
                        HResult {
                            ip,
                            status,
                            pop,
                            ms: lat.ms,
                            reason,
                        }
                    }
                })
                .await;
                let results: Vec<HResult> = results.into_iter().flatten().collect();
                let now = now_ms();
                let peak = self.cfg.is_peak(now);
                let w = self.cfg.peak_weight;
                let min_pool = self.cfg.min_pool;
                let v6_ok = self.net.v6_usable() == Some(true);
                changed |= self.with_state(|st| {
                    let st = &mut *st;
                    let mut changed = false;
                    let Some(d) = st.pools.p.get_mut(name) else { return false };
                    for r in &results {
                        let Some(x) = d.pool_mut(family).iter_mut().find(|x| x.ip == r.ip) else {
                            continue;
                        };
                        if r.status == HStatus::Tw {
                            x.pop = Some(util::intern(&r.pop));
                            x.ms = Num::V(util::round(r.ms, 2));
                            x.checked_at = Some(now);
                            if peak {
                                x.peak_ms = Num::V(util::round(r.ms, 2));
                                x.peak_at = Some(now);
                            }
                            if d.bad.remove(&r.ip).is_some() {
                                changed = true;
                            }
                        } else if let std::collections::hash_map::Entry::Vacant(e) = d.bad.entry(r.ip) {
                            e.insert(Bad {
                                at: now,
                                reason: r.reason.clone(),
                                quality: false,
                            });
                            changed = true;
                        }
                    }
                    if family == 6 && !nearest {
                        // 永久紀錄：台灣 → 保存；POP 移出台灣 → 移除；連不上 → 累計（整輪都連不上視為本機網路問題，不計）
                        let net_ok = results.iter().any(|r| r.status != HStatus::Dead);
                        let mut drop: Vec<IpAddr> = Vec::new();
                        for r in &results {
                            match r.status {
                                HStatus::Tw => {
                                    let ms = d.pool6.iter().find(|x| x.ip == r.ip).and_then(|x| x.ms.get());
                                    if st.v6.mark_ok(name, r.ip, &r.pop, ms) {
                                        info!("★ {} 新的台灣 IPv6 節點 {} ({})，已永久保存", prov.label, r.ip, r.pop);
                                    }
                                }
                                HStatus::NotTw => {
                                    if st.v6.mark_not_tw(name, r.ip) {
                                        warn!("{} IPv6 節點 {} POP 變成 {}，從永久紀錄移除", prov.label, r.ip, r.pop);
                                    }
                                    drop.push(r.ip);
                                }
                                HStatus::Dead => {
                                    if net_ok && st.v6.mark_dead(name, r.ip) {
                                        warn!(
                                            "{} IPv6 節點 {} 連續 {} 次失效，從永久紀錄移除",
                                            prov.label,
                                            r.ip,
                                            crate::v6store::FAIL_LIMIT
                                        );
                                        drop.push(r.ip);
                                    }
                                }
                            }
                        }
                        if !drop.is_empty() {
                            d.pool6.retain(|x| !drop.contains(&x.ip));
                            changed = true;
                        }
                    }
                    // 最近節點型（Fastly）依品質分數排序；一般 CDN 依延遲（有尖峰時段量測時加權）
                    let bad = d.bad.clone();
                    let key = |x: &pools::PoolNode| if nearest { node_score(x) } else { weighted_ms(x, w, now) };
                    d.pool_mut(family).sort_by(|a, b| {
                        (bad.contains_key(&a.ip) as u8)
                            .cmp(&(bad.contains_key(&b.ip) as u8))
                            .then(key(a).partial_cmp(&key(b)).unwrap_or(std::cmp::Ordering::Equal))
                    });
                    let alive = d.pool(family).iter().filter(|x| !bad.contains_key(&x.ip)).count();
                    if alive < min_pool && (family == 4 || v6_ok) {
                        warn!("{} IPv{family} 可用台灣節點只剩 {alive} 個，排入節點池重建", prov.label);
                        st.pools.request_rebuild(name);
                    }
                    changed
                });
            }
        }
        self.with_state(|st| st.pools.dirty = true);
        changed
    }

    /// 最近節點型 CDN 的即時品質監測（預設每 5 分鐘）：每個池內節點連幾次，依「延遲 + 抖動 + 掉包」重新排序；
    /// 海纜壅塞、某個 POP 變差時自動換到下一個 POP。尖峰時段的量測另外記下來，計分時加權（規格 06 第 3.2 節）
    pub async fn quality_check(self: &Arc<Self>) -> bool {
        let mut changed = false;
        let names: Vec<&'static str> = self.state().pools.p.keys().copied().collect();
        for name in names {
            let Some(prov) = providers::get(name) else { continue };
            if !prov.nearest {
                continue;
            }
            let (before, ips): (Option<String>, Vec<IpAddr>) = {
                let st = self.state();
                let Some(d) = st.pools.p.get(name) else { continue };
                (st.pools.best_pop(name), d.pool4.iter().map(|x| x.ip).collect())
            };
            if ips.is_empty() {
                continue;
            }
            let net = self.net.clone();
            let n = self.cfg.quality_samples;
            let res = map_limit(ips, 8, move |ip| {
                let net = net.clone();
                async move {
                    (
                        ip,
                        net.quality(ip, n, Duration::from_millis(1200), Duration::from_millis(120)).await,
                    )
                }
            })
            .await;
            let res: Vec<_> = res.into_iter().flatten().collect();
            if !res.iter().any(|(_, q)| q.loss < 1.0) {
                warn!("{} 品質檢查全部連不上，疑似本機網路問題，暫不調整", prov.label);
                continue;
            }
            let now = now_ms();
            let peak = self.cfg.is_peak(now);
            let w = self.cfg.peak_weight;
            changed |= self.with_state(|st| {
                let mut changed = false;
                let Some(d) = st.pools.p.get_mut(name) else { return false };
                for (ip, q) in &res {
                    let Some(x) = d.pool4.iter_mut().find(|x| x.ip == *ip) else {
                        continue;
                    };
                    if q.ms.is_finite() {
                        x.ms = Num::V(util::round(q.ms, 2));
                    }
                    x.jitter = Num::V(util::round(q.jitter, 2));
                    x.loss = Num::V(util::round(q.loss, 2));
                    x.checked_at = Some(now);
                    if peak {
                        x.peak_ms = if q.ms.is_finite() {
                            Num::V(util::round(q.ms, 2))
                        } else {
                            Num::Null
                        };
                        x.peak_jitter = Num::V(util::round(q.jitter, 2));
                        x.peak_loss = Num::V(util::round(q.loss, 2));
                        x.peak_at = Some(now);
                    }
                    // 分數用這次量到的延遲（連不上是無限大，排到最後）
                    let mut y = x.clone();
                    y.ms = if q.ms.is_finite() { Num::V(q.ms) } else { Num::Absent };
                    x.score = Num::V(util::round(weighted_qscore(&y, w, now), 1));
                    let bad = d.bad.get(ip).cloned();
                    if q.loss >= 1.0 {
                        if bad.is_none() {
                            d.bad.insert(
                                *ip,
                                Bad {
                                    at: now,
                                    reason: "品質檢查連不上".into(),
                                    quality: true,
                                },
                            );
                            changed = true;
                        }
                    } else if bad.map(|b| b.quality).unwrap_or(false) {
                        d.bad.remove(ip);
                        changed = true;
                    }
                }
                let bad = d.bad.clone();
                d.pool4.sort_by(|a, b| {
                    (bad.contains_key(&a.ip) as u8).cmp(&(bad.contains_key(&b.ip) as u8)).then(
                        a.score
                            .or(999.0)
                            .partial_cmp(&b.score.or(999.0))
                            .unwrap_or(std::cmp::Ordering::Equal),
                    )
                });
                let after = st.pools.best_pop(name);
                if after != before {
                    if let Some(top) = st.pools.p.get(name).and_then(|d| d.pool4.first()) {
                        warn!(
                            "{} 主要節點 {} → {}（延遲 {}ms、抖動 {}ms、掉包 {}%）",
                            prov.label,
                            before.as_deref().unwrap_or("—"),
                            after.as_deref().unwrap_or("—"),
                            top.ms.or(0.0),
                            top.jitter.or(0.0),
                            (top.loss.or(0.0) * 100.0).round()
                        );
                    }
                    changed = true;
                }
                if changed {
                    st.pools.dirty = true;
                }
                changed
            });
        }
        changed
    }

    /// 即時發現：解析過程看到這家 CDN 的新 IPv6 位址，背景探測一次 POP，
    /// 是台灣就立刻加入節點池並永久保存（同一個 /48 六小時內只試一次）
    pub async fn try_v6(self: &Arc<Self>, provider: &str, ip: IpAddr) {
        let Some(prov) = providers::get(provider) else { return };
        let Some((host, path)) = prov.probe else { return };
        if self.net.v6_usable() == Some(false) {
            return;
        }
        let Some(key) = util::v6_48(ip) else { return };
        let now = now_ms();
        let go = self.with_state(|st| {
            let Some(d) = st.pools.p.get_mut(provider) else { return false };
            if d.pool6.iter().any(|x| x.ip == ip) {
                return false;
            }
            if let Some(last) = d.tried6.get(&key) {
                if now.saturating_sub(*last) < 6 * util::HOUR_MS {
                    return false;
                }
            }
            d.tried6.insert(key, now);
            if d.tried6.len() > 5000 {
                d.tried6.shift_remove_index(0);
            }
            true
        });
        if !go {
            return;
        }
        let r = self.net.http_probe(ip, host, path, Duration::from_millis(3000)).await;
        let pop = if r.ok { prov.pop(&r.headers, &r.body) } else { String::new() };
        if !is_tw_pop(&pop) {
            return;
        }
        let lat = self.net.tcp_ping(ip, Duration::from_millis(1500), 2).await;
        if !lat.ok {
            return;
        }
        let ms = util::round(lat.ms, 2);
        self.with_state(|st| {
            let st = &mut *st;
            let Some(d) = st.pools.p.get_mut(provider) else { return };
            if d.pool6.iter().any(|x| x.ip == ip) {
                return;
            }
            let mut n = pools::PoolNode::new(ip);
            n.ms = Num::V(ms);
            n.pop = Some(util::intern(&pop));
            n.permanent = Some(true);
            n.checked_at = Some(now_ms());
            d.pool6.push(n);
            let bad = d.bad.clone();
            d.pool6.sort_by(|a, b| {
                (bad.contains_key(&a.ip) as u8)
                    .cmp(&(bad.contains_key(&b.ip) as u8))
                    .then(a.ms.or(999.0).partial_cmp(&b.ms.or(999.0)).unwrap_or(std::cmp::Ordering::Equal))
            });
            let mut tw48 = (*d.tw48).clone();
            tw48.add(&util::subnet_key(ip));
            tw48.finalize();
            d.tw48 = Arc::new(tw48);
            st.v6.mark_ok(provider, ip, &pop, Some(ms));
            st.pools.dirty = true;
            info!("★ {} 發現台灣 IPv6 節點 {ip} ({pop} {ms}ms)，已加入節點池並永久保存", prov.label);
        });
    }
}
