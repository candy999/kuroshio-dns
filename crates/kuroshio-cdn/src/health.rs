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

/// 有上限的並行執行，而且開始時間攤開：第 i 個最早在 `i / per_sec` 秒後才開始。
/// 到 CDN 只有幾 ms 時，光靠並行數擋不住「一秒幾千條新連線」（路由器的連線追蹤表、CPU 一次塞滿）；
/// 做的事不變，只是每秒最多開始 `per_sec` 個
pub async fn map_paced<T, R, F, Fut>(items: Vec<T>, limit: usize, per_sec: u64, f: F) -> Vec<Option<R>>
where
    T: Send + 'static,
    R: Send + 'static,
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
{
    let t0 = tokio::time::Instant::now();
    let gap = Duration::from_micros(1_000_000 / per_sec.max(1));
    let f = Arc::new(f);
    // 下一個可以開始的時間：拿到並行名額時才登記，每個至少隔 `gap`。
    // 以前只排固定時間（第 i 個在 t0 + i × gap）：前面的量測卡住（名額被等逾時的佔滿）時，
    // 後面排定時間已經過了的會在名額空出來時一起開始（Windows 3.4.2 驗證：健檢中途卡 10 秒，
    // 之後 1 秒 600 條新連線、202 個位址）。現在卡住後照樣每秒最多 `per_sec` 個，不補回落後的
    let next = Arc::new(std::sync::Mutex::new(t0));
    let items: Vec<(u32, T)> = items.into_iter().enumerate().map(|(i, x)| (i as u32, x)).collect();
    map_limit(items, limit, move |(i, x)| {
        let f = f.clone();
        let next = next.clone();
        async move {
            let at = {
                let mut n = next.lock().unwrap();
                let at = (t0 + gap * i).max(*n).max(tokio::time::Instant::now());
                *n = at + gap;
                at
            };
            tokio::time::sleep_until(at).await;
            f(x).await
        }
    })
    .await
}

/// 定時健檢每秒最多開始檢查幾個節點（每個節點 3 條連線 → 每秒約 60 條新連線）。
/// 3.4.2 Windows 壓力測試：CloudFront 永久 IPv6 節點 585 個，並行 16 個一秒就做完、1 秒 1,976 條新連線；
/// 現在約 30 秒做完，節點池一般 12 個左右時不到 1 秒
pub const HEALTH_NODES_PER_SEC: u64 = 20;

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
    /// 檢查前的機房（3.5.0 E5：壞掉的節點算在它原本的機房頭上）
    old_pop: String,
    ms: f64,
    reason: String,
}

/// 健檢排序（3.5.0 E5／E6）：壞的在後 → 暫緩機房（E5）的在後 → `key`（延遲或品質分數）；
/// 接著（`spread` 有值時）調整前幾名讓網段分散（E6）。`held` 是 None、`spread` 是 None 時就是 3.4.x 的排序
pub(crate) fn order_pool(
    pool: &mut [pools::PoolNode],
    bad: &std::collections::HashMap<IpAddr, Bad>,
    held: Option<&str>,
    key: &dyn Fn(&pools::PoolNode) -> f64,
    spread: Option<usize>,
) {
    let is_held = |x: &pools::PoolNode| held.is_some_and(|h| !bad.contains_key(&x.ip) && pools::pop3_is(x.pop_str(), h));
    pool.sort_by(|a, b| {
        (bad.contains_key(&a.ip) as u8)
            .cmp(&(bad.contains_key(&b.ip) as u8))
            .then((is_held(a) as u8).cmp(&(is_held(b) as u8)))
            .then(key(a).partial_cmp(&key(b)).unwrap_or(std::cmp::Ordering::Equal))
    });
    if let Some(n) = spread {
        pools::spread_head(pool, &|x| bad.contains_key(&x.ip) || is_held(x), n, key);
    }
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
                let results = map_paced(list, 16, HEALTH_NODES_PER_SEC, move |(ip, old_pop): (IpAddr, String)| {
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
                            old_pop,
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
                let env = self.line_env();
                let (switch_on, spread) = (self.cfg.pop_switch, self.cfg.spread_prefixes && !nearest);
                let serve_n = self.cfg.serve_count_of(name);
                changed |= self.with_state(|st| {
                    let st = &mut *st;
                    let mut changed = false;
                    // 這一輪有沒有把節點移出池（POP 移出台灣、永久失效）
                    let mut shrunk = false;
                    let Some(d) = st.pools.p.get_mut(name) else { return false };
                    // 上游宣稱的機房跟這一輪本機量到的比（3.5.0 E4）：（一樣，不一樣）
                    let (mut same, mut moved) = (0u32, 0u32);
                    for r in &results {
                        let Some(x) = d.pool_mut(family).iter_mut().find(|x| x.ip == r.ip) else {
                            continue;
                        };
                        if r.status != HStatus::Dead && !r.pop.is_empty() {
                            if let Some(up) = x.take_up_pop() {
                                let check = crate::reach::compare_pop(&up, &r.pop, nearest);
                                st.line.audit.note(check != crate::reach::PopCheck::Same, now);
                                if check == crate::reach::PopCheck::Same {
                                    same += 1;
                                } else {
                                    moved += 1;
                                }
                            }
                        }
                        if r.status == HStatus::Tw {
                            x.pop = Some(util::intern(&r.pop));
                            x.ms = Num::V(util::round(r.ms, 2));
                            x.checked_at = Some(now);
                            if peak {
                                x.peak_ms = Num::V(util::round(r.ms, 2));
                                x.peak_at = Some(now);
                            }
                            // 驗證反覆標壞的節點（3.5.1 K2）：暫停時間還沒到，健檢通過也不恢復
                            // （健檢連的是業者自己的網站，證明不了對那個網站可以用）
                            let held = d.strikes.get(&r.ip).is_some_and(|s| s.held(now));
                            if !held && d.bad.remove(&r.ip).is_some() {
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
                            shrunk = true;
                        }
                    }
                    if same + moved > 0 {
                        info!(
                            "{} IPv{family}：上游給的節點這台量到機房一樣 {same} 個、不一樣 {moved} 個{}",
                            prov.label,
                            if moved > 0 { "（改用這台量到的）" } else { "" }
                        );
                    }
                    // 機房層級的健康（3.5.0 E5）：依檢查前的機房彙總這一輪，最近節點型（Fastly）不碰
                    let held = if nearest {
                        None
                    } else {
                        let round: Vec<crate::reach::RoundNode> = results
                            .iter()
                            .map(|r| crate::reach::RoundNode {
                                pop: if is_tw_pop(&r.old_pop) { r.old_pop.clone() } else { r.pop.clone() },
                                ok: r.status == HStatus::Tw,
                                ms: r.ms,
                                ip: r.ip,
                            })
                            .collect();
                        let aggs = crate::reach::aggregate(name, family, &round);
                        let block = st.line.block(name, family, switch_on, env, now);
                        st.line.pop_round(name, family, aggs, block, now)
                    };
                    // 最近節點型（Fastly）依品質分數排序；一般 CDN 依延遲（有尖峰時段量測時加權）。
                    // 3.5.0：暫緩的機房（E5）排在可用節點的最後，前幾名的網段分散（E6）
                    let bad = d.bad.clone();
                    let key = |x: &pools::PoolNode| if nearest { node_score(x) } else { weighted_ms(x, w, now) };
                    order_pool(d.pool_mut(family), &bad, held.as_deref(), &key, spread.then_some(serve_n));
                    let total = d.pool(family).len();
                    let alive = d.pool(family).iter().filter(|x| !bad.contains_key(&x.ip)).count();
                    // 只有「有節點壞掉或被移出」才重建：節點本來就少（例如 Azure 在台灣只有 2 個 IPv6 節點）而且全部正常時，
                    // 重建也變不出更多節點，只會每輪重排一次節點池工作、白白耗 CPU（每天 05:30 的例行重建照常會找新節點）
                    if alive < min_pool && (alive < total || shrunk) && (family == 4 || v6_ok) {
                        warn!("{} IPv{family} 可用台灣節點只剩 {alive} 個，排入節點池重建", prov.label);
                        st.pools.request_rebuild(name);
                    }
                    changed
                });
            }
        }
        let now = now_ms();
        self.with_state(|st| {
            st.pools.dirty = true;
            // 這條線到得了哪些台灣機房（3.5.0 E3）：每一輪健檢結束時重算
            st.pools.reach_dirty = false;
            st.line.after_health(&st.pools, now);
        });
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
                keep_pop(&mut d.pool4, &bad, before.as_deref());
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
            // 同健檢的排序（3.5.0 E5 暫緩的機房在後、E6 網段分散）
            let held = st.line.held_pop(provider, 6, now_ms()).map(String::from);
            let spread = (self.cfg.spread_prefixes && !prov.nearest).then(|| self.cfg.serve_count_of(provider));
            order_pool(&mut d.pool6, &bad, held.as_deref(), &|x| x.ms.or(999.0), spread);
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

/// 主要節點的遲滯（3.4.2）：新的第一名要比原本主要 POP 的最好節點好上 15% 再多 5 分才換。
/// 只差一點點時把原本 POP 的節點放回第一位，不讓量測的雜訊（例如路由器自己很忙時）每 5 分鐘來回切換
/// （padavan-tw 的 D3 壓測：45 分鐘切了 8 次，HKG→ICN→HKG→NRT→…）
pub(crate) const POP_HYST_RATIO: f64 = 0.15;
pub(crate) const POP_HYST_ABS: f64 = 5.0;

pub(crate) fn keep_pop(pool: &mut Vec<pools::PoolNode>, bad: &std::collections::HashMap<IpAddr, Bad>, before: Option<&str>) {
    let Some(before) = before else { return };
    let Some(top) = pool.iter().position(|x| !bad.contains_key(&x.ip)) else {
        return;
    };
    if pools::pop3_is(pool[top].pop_str(), before) {
        return;
    }
    let Some(pos) = pool
        .iter()
        .position(|x| !bad.contains_key(&x.ip) && pools::pop3_is(x.pop_str(), before))
    else {
        return;
    };
    let (new, old) = (pool[top].score.or(999.0), pool[pos].score.or(999.0));
    if old.is_finite() && old <= new * (1.0 + POP_HYST_RATIO) + POP_HYST_ABS {
        let x = pool.remove(pos);
        pool.insert(top, x);
    }
}
