//! 台灣 IP 清單排程工作的記憶體用量：計數的配置器量整個執行期間「比開始時多用了多少」的峰值。
//! RIR 檔一個好幾 MB，邊收邊解析，峰值要遠小於 2 MB。
//!
//! 用真的資料量（選用）：先用 `tw-ip --cache DIR` 或 curl 把五個 RIR 檔與 65 個 RIPEstat 回應下載到 DIR
//! （檔名同 `--cache`），再 `KUROSHIO_TWIP_REAL_DIR=DIR cargo test -p kuroshio-jobs --test twip_mem -- --nocapture`。

mod common;

use common::{serve, small_fixture, Mock};
use kuroshio_jobs::geo::TwIp;
use kuroshio_jobs::time::{parse_date_utc, ManualClock, HOUR_MS};
use kuroshio_jobs::twip::{all_asns, Hooks, Sources, TwIpJob, RIRS};
use kuroshio_jobs::{Job, JobCtx};
use serde_json::json;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::{Arc, Mutex};

struct Counting;
static CUR: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let n = CUR.fetch_add(l.size() as isize, Ordering::Relaxed) + l.size() as isize;
            PEAK.fetch_max(n, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        CUR.fetch_sub(l.size() as isize, Ordering::Relaxed);
    }
}

#[global_allocator]
static A: Counting = Counting;

fn real_fixture(dir: &str) -> Mock {
    let mut m = Mock::default();
    for (rir, _) in RIRS {
        let name = format!("delegated-{rir}-extended-latest");
        let b = std::fs::read(format!("{dir}/{name}")).unwrap();
        m.files.insert(format!("/{name}"), Arc::new(b));
    }
    for a in all_asns() {
        let b = std::fs::read(format!("{dir}/ripestat-AS{a}.json")).unwrap();
        m.files.insert(format!("/ripestat/AS{a}"), Arc::new(b));
    }
    m
}

#[tokio::test(flavor = "current_thread")]
async fn peak_memory_stays_small() {
    let real = std::env::var("KUROSHIO_TWIP_REAL_DIR").ok().filter(|d| !d.is_empty());
    // 假資料：每個 RIR 檔 6 萬筆別國紀錄（約 4 MB），5 個加起來約 20 MB
    let m = match &real {
        Some(d) => real_fixture(d),
        None => small_fixture(60_000),
    };
    let total: usize = m.files.values().map(|b| b.len()).sum();
    let shared = Arc::new(Mutex::new(m));
    let addr = serve(shared.clone()).await;
    let installed: Arc<Mutex<Option<Vec<u8>>>> = Arc::default();
    let inst = installed.clone();
    let hooks = Hooks {
        current: Arc::new(|| (None, false)),
        memory_short: Arc::new(|| None),
        load: Arc::new(|| None),
        install: Arc::new(move |_t: TwIp, b: Vec<u8>| {
            *inst.lock().unwrap() = Some(b);
            Ok(())
        }),
    };
    let job = TwIpJob::new(Sources::with_base(&format!("http://{addr}")), hooks);
    let cfg = Arc::new(json!({ "jobs": { "tw-ip": { "pauseSec": [0, 0] } } }));
    let clk = Arc::new(ManualClock::new(parse_date_utc("2026-11-11").unwrap() + 3 * HOUR_MS));
    let ctx = JobCtx::new("tw-ip", "手動 (測試)", cfg).with_clock(clk);
    // 熱身：讓 tokio、連線等一次性的配置先發生
    tokio::task::yield_now().await;
    let base = CUR.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let t0 = std::time::Instant::now();
    job.run(ctx).await.unwrap();
    let wall = t0.elapsed();
    let peak = PEAK.load(Ordering::SeqCst) - base;
    let out = installed.lock().unwrap().clone().unwrap();
    let st = job.status_json();
    println!(
        "台灣 IP 清單：來源共 {:.1} MB，輸出 {} KB，峰值多用 {} KB（工作自己估計 {} KB），耗時 {:.2} 秒（不含禮貌停頓）",
        total as f64 / 1_048_576.0,
        out.len() / 1024,
        peak / 1024,
        st["peakMemKB"],
        wall.as_secs_f64()
    );
    if let Some(d) = &real {
        // 跟同一份資料用指令列產生的結果比較（快取目錄裡如果有）
        if let Ok(cli) = std::fs::read(format!("{d}/cli-tw-ip.json")) {
            let a = TwIp::parse(&cli).unwrap();
            let b = TwIp::parse(&out).unwrap();
            assert!(kuroshio_jobs::twip::same_nets(&a, &b), "跟指令列的結果不一樣");
        }
        std::fs::write(format!("{d}/job-tw-ip.json"), &out).unwrap();
    }
    assert!(peak < 1536 * 1024, "峰值多用 {} KB，要遠小於 2 MB", peak / 1024);
}
