//! CDNtest Step2（對齊 2.x `jobs/cdn-scan.js`）：把 CDN 範圍展開成 /24，每段抽樣探測 POP，
//! 分成 TW / Global / Dead 三類 → `state/cdn/scan/<cdn>-ipv4-TW.txt` 等。
//!
//! 同時數 `scan.concurrency`（預設依 CPU 核心數），用固定數量的工作者輪流取網段（不會一次開幾萬個 task）。
//! 網段分批跑，批與批之間過檢查點（系統吃緊時暫停，暫停時沒有進行中的探測）。
//! 結果依網段排序後寫檔（2.x 是完成順序），內容沒變就不寫。

use super::{v4_lines, JobCtx};
use crate::net::Net;
use crate::providers::{self, is_tw_pop, Provider};
use crate::util::{self, write_if_changed};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::info;

/// 展開成 /24 的前綴（ip >> 8）
pub fn expand_to_24(cidr: &str) -> Vec<u32> {
    let (ip, len) = match cidr.split_once('/') {
        Some((a, b)) => (a, b.trim().parse::<u32>().ok()),
        None => (cidr, Some(32)),
    };
    let Ok(ip) = ip.trim().parse::<Ipv4Addr>() else { return vec![] };
    let Some(len) = len.filter(|l| *l <= 32) else { return vec![] };
    let v = u32::from(ip);
    if len >= 24 {
        return vec![v >> 8];
    }
    let start = v & (u32::MAX << (32 - len));
    let n = 1u64 << (32 - len);
    (0..n / 256).map(|i| ((start as u64 + i * 256) >> 8) as u32).collect()
}

/// 每個 /24 抽 n 個 IP（均勻分布）
pub fn samples(prefix: u32, n: usize) -> Vec<IpAddr> {
    let n = n.max(1);
    let step = 254 / n as u32;
    (0..n as u32)
        .map(|i| IpAddr::V4(Ipv4Addr::from((prefix << 8) + 1 + i * step)))
        .collect()
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProviderScan {
    pub provider: String,
    pub tw: usize,
    pub global: usize,
    pub dead: usize,
    /// 寫入了沒（安全檢查沒過就不覆蓋舊結果）
    pub written: bool,
    /// 檔案內容有變
    pub changed: bool,
    /// POP 分布前 10 名
    pub top_pops: Vec<(String, u32)>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    pub providers: Vec<ProviderScan>,
    pub changed: bool,
}

const TW: u8 = 1;
const GLOBAL: u8 = 2;
const DEAD: u8 = 3;

/// 每批的網段數 = 並行數 × 這個倍數（批次夠大，批尾工作者閒置的時間才少；
/// 批與批之間過檢查點，暫停時最多只有這一批還在跑完）
const BATCH_PER_WORKER: usize = 4;

/// 一批網段的探測（`range` 是 `tasks` 的索引範圍）
struct ScanBatch {
    name: &'static str,
    prov: &'static Provider,
    host: &'static str,
    path: &'static str,
    n: usize,
    timeout: Duration,
    workers: usize,
    range: (usize, usize),
    tasks: Arc<Vec<u32>>,
    cls: Arc<Mutex<Vec<u8>>>,
    pops: Arc<Mutex<HashMap<String, u32>>>,
    done: Arc<AtomicUsize>,
    last_pct: Arc<Mutex<i64>>,
    net: Arc<dyn Net>,
}

/// 用固定數量的工作者輪流取這一批的網段，全部探測完才回來
async fn scan_batch(b: ScanBatch) {
    let b = Arc::new(b);
    let idx = Arc::new(AtomicUsize::new(b.range.0));
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..b.workers {
        let (b, idx) = (b.clone(), idx.clone());
        set.spawn(async move {
            let (name, prov, tasks) = (b.name, b.prov, &b.tasks);
            loop {
                let i = idx.fetch_add(1, Ordering::Relaxed);
                if i >= b.range.1 {
                    return;
                }
                let (mut live, mut tw) = (false, false);
                for ip in samples(tasks[i], b.n) {
                    let r = b.net.http_probe(ip, b.host, b.path, b.timeout).await;
                    if !r.ok {
                        continue;
                    }
                    live = true; // 有任何回應就算活著（同原本 Step2）
                    let pop = prov.pop(&r.headers, &r.body);
                    if pop.is_empty() {
                        continue; // 沒抓到 POP，繼續抽樣看看
                    }
                    *b.pops.lock().unwrap().entry(pop.clone()).or_default() += 1;
                    tw = is_tw_pop(&pop);
                    break; // 已確認 POP，不必再測
                }
                b.cls.lock().unwrap()[i] = if tw {
                    TW
                } else if live {
                    GLOBAL
                } else {
                    DEAD
                };
                let d = b.done.fetch_add(1, Ordering::Relaxed) + 1;
                let pct = (d * 20 / tasks.len()) as i64 * 5;
                let mut lp = b.last_pct.lock().unwrap();
                if pct != *lp {
                    *lp = pct;
                    let c = b.cls.lock().unwrap();
                    let count = |k: u8| c.iter().filter(|x| **x == k).count();
                    info!("[{name}] {pct}%  TW:{} Global:{} Dead:{}", count(TW), count(GLOBAL), count(DEAD));
                }
            }
        });
    }
    while set.join_next().await.is_some() {}
}

pub async fn run(ctx: &JobCtx) -> Result<Report> {
    let jc = ctx.jobs_cfg();
    let n = jc.scan_samples;
    let conc = jc.scan_concurrency.max(1);
    let timeout = Duration::from_millis(jc.scan_timeout_ms);
    let out_dir = ctx.cdn.paths.state_dir.join("cdn").join("scan");
    let mut report = Report::default();
    for prov in providers::PROVIDERS {
        let name = prov.name;
        if !ctx.wants(name) || !prov.alias {
            continue;
        }
        let Some((host, path)) = prov.probe else { continue };
        let cidrs = v4_lines(ctx.cdn.paths.read_cdn_text(&format!("ranges/{name}-ipv4.txt")));
        if cidrs.is_empty() {
            info!("[{name}] 沒有 IP 範圍，跳過（先執行 cdn-ranges）");
            continue;
        }
        let mut seen = HashSet::new();
        let tasks: Arc<Vec<u32>> = Arc::new(cidrs.iter().flat_map(|c| expand_to_24(c)).filter(|p| seen.insert(*p)).collect());
        info!("[{name}] 展開 {} 個 /24，每段抽樣 {n} 個 IP，並行 {conc}", tasks.len());
        let cls: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(vec![0; tasks.len()]));
        let pops: Arc<Mutex<HashMap<String, u32>>> = Arc::new(Mutex::new(HashMap::new()));
        let done = Arc::new(AtomicUsize::new(0));
        let last_pct = Arc::new(Mutex::new(-1i64));
        // 分批跑：每批結束（手上沒有進行中的探測）才過檢查點，系統吃緊時在批與批之間暫停
        let batch = (conc * BATCH_PER_WORKER).max(1);
        let mut start = 0;
        while start < tasks.len() {
            ctx.checkpoint().await;
            let end = (start + batch).min(tasks.len());
            scan_batch(ScanBatch {
                name,
                prov,
                host,
                path,
                n,
                timeout,
                workers: conc.min(end - start),
                range: (start, end),
                tasks: tasks.clone(),
                cls: cls.clone(),
                pops: pops.clone(),
                done: done.clone(),
                last_pct: last_pct.clone(),
                net: ctx.cdn.net().clone(),
            })
            .await;
            start = end;
        }
        let cls = cls.lock().unwrap().clone();
        let pops = pops.lock().unwrap().clone();
        let mut lists: [Vec<u32>; 3] = [vec![], vec![], vec![]];
        for (i, c) in cls.iter().enumerate() {
            match *c {
                TW => lists[0].push(tasks[i]),
                GLOBAL => lists[1].push(tasks[i]),
                _ => lists[2].push(tasks[i]),
            }
        }
        let mut top: Vec<(String, u32)> = pops.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top.truncate(10);
        let mut ps = ProviderScan {
            provider: name.to_string(),
            tw: lists[0].len(),
            global: lists[1].len(),
            dead: lists[2].len(),
            top_pops: top.clone(),
            ..Default::default()
        };
        // 安全檢查：完全沒抓到 POP（回應都不是這家 CDN，可能被中間設備攔截），不覆蓋舊結果
        if top.is_empty() {
            let msg = format!("沒有任何回應帶有 {} 的 POP 特徵，疑似網路被攔截，不覆蓋舊結果", prov.label);
            info!("[{name}] {msg}");
            ps.note = Some(msg);
            report.providers.push(ps);
            continue;
        }
        // 安全檢查：若幾乎全部 Dead，多半是本機網路問題，不覆蓋舊結果
        if ((ps.tw + ps.global) as f64) < tasks.len() as f64 * 0.02 {
            let msg = format!("可用網段過少（{}），疑似網路異常，不覆蓋舊結果", ps.tw + ps.global);
            info!("[{name}] {msg}");
            ps.note = Some(msg);
            report.providers.push(ps);
            continue;
        }
        for (k, label) in [(0, "TW"), (1, "Global"), (2, "Dead")] {
            let mut l = lists[k].clone();
            l.sort_unstable();
            let body: String = l.iter().map(|p| format!("{}.0/24\n", util::prefix24_str(*p))).collect();
            let body = if body.is_empty() { "\n".to_string() } else { body };
            ps.changed |= write_if_changed(&out_dir.join(format!("{name}-ipv4-{label}.txt")), body.as_bytes())?;
        }
        ps.written = true;
        report.changed |= ps.changed;
        info!(
            "[{name}] 完成 TW {} / Global {} / Dead {}；POP 分布 {}",
            ps.tw,
            ps.global,
            ps.dead,
            top.iter().map(|(p, c)| format!("{p}:{c}")).collect::<Vec<_>>().join(" ")
        );
        report.providers.push(ps);
    }
    let done = out_dir.join(".done");
    if report.changed || !done.exists() {
        write_if_changed(&done, util::iso(util::now_ms()).as_bytes())?;
    }
    if report.changed {
        ctx.cdn.reload_ranges();
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_and_sample() {
        assert_eq!(
            expand_to_24("104.16.0.0/22")
                .iter()
                .map(|p| util::prefix24_str(*p))
                .collect::<Vec<_>>(),
            vec!["104.16.0", "104.16.1", "104.16.2", "104.16.3"]
        );
        assert_eq!(expand_to_24("104.16.5.7/26").len(), 1);
        assert_eq!(expand_to_24("104.16.5.7").len(), 1);
        assert_eq!(expand_to_24("104.16.0.0/13").len(), 2048);
        assert!(expand_to_24("x/24").is_empty());
        let s: Vec<String> = samples(util::parse_prefix24("1.2.3").unwrap(), 6)
            .iter()
            .map(|i| i.to_string())
            .collect();
        assert_eq!(s, vec!["1.2.3.1", "1.2.3.43", "1.2.3.85", "1.2.3.127", "1.2.3.169", "1.2.3.211"]);
    }
}
