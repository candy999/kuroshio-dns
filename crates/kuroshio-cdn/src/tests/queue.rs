//! 背景工作的排隊上限（3.4.1）：慢 CPU 上一波查詢不能堆出上千個在等名額的驗證工作

use super::*;
use crate::cdn::Task;

/// 真的排背景工作（`cdn_with` 只記錄、不執行）
fn real(cfg: Value, tag: &str) -> Arc<Cdn> {
    Cdn::load(&json!({ "cdn": cfg }), paths_no_seed(tag), MockNet::new())
}

fn verify(i: usize) -> Task {
    Task::Verify {
        name: format!("q{i}.example.com"),
        provider: "cloudflare".into(),
        family: 4,
        orig: None,
    }
}

#[test]
fn verify_queue_is_capped_and_slots_return_when_cancelled() {
    let c = real(
        json!({ "verifyConcurrency": 1, "providers": { "cloudflare": { "enabled": true } } }),
        "queue",
    );
    let cap = 32; // queue_cap(1) = max(1 × 16, 32)
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        // 名額全部先拿走：排進去的工作都停在等名額
        let _held = c.verify_sem.clone().acquire_many_owned(1).await.unwrap();
        for i in 0..100 {
            c.schedule(verify(i));
        }
        assert_eq!(c.inflight().0, cap, "最多排 {cap} 個");
        assert_eq!(c.deferred(), 100 - cap as u64, "排不進的記成延後");
        // 已經在排的同一個網域：不算延後（本來就會去重）
        c.schedule(verify(0));
        assert_eq!(c.deferred(), 100 - cap as u64);
        let st = c.status_lite();
        assert_eq!(st["background"]["verify"], cap);
        assert_eq!(st["background"]["deferred"], 100 - cap as u64);
    });
    // 重新載入時舊的 runtime 結束：等名額的工作被取消，佔的位置要還回去（不然之後永遠排不進）
    drop(rt);
    assert_eq!(c.inflight().0, 0);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let _held = c.verify_sem.clone().acquire_many_owned(1).await.unwrap();
        c.schedule(verify(500));
        assert_eq!(c.inflight().0, 1, "新的 runtime 可以再排");
    });
}

#[test]
fn latency_probes_are_capped() {
    let c = real(json!({ "providers": { "cloudflare": { "enabled": true } } }), "queue-lat");
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        // current_thread：spawn 出去的量測在這個 block_on 讓出之前都還沒跑完
        for i in 0..200u32 {
            c.schedule(Task::Latency(IpAddr::from(std::net::Ipv4Addr::from(0xC633_6400 + i))));
        }
        assert_eq!(c.deferred(), 200 - 64, "同時最多 64 個量測");
        // 讓量測跑完：名額還回去，之後又可以排
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        c.schedule(Task::Latency(IpAddr::from([198, 51, 100, 250])));
        assert_eq!(c.deferred(), 200 - 64);
    });
}

/// 3.4.2：主要 POP 的遲滯。新的第一名只好一點點（15% + 5 分以內）不換；好很多才換；原本的 POP 壞掉就換
#[test]
fn main_pop_hysteresis() {
    use crate::health::keep_pop;
    use crate::pools::PoolNode;
    use crate::util::Num;
    use std::collections::HashMap;
    let node = |ip: &str, pop: &str, score: f64| {
        let mut n = PoolNode::new(ip.parse().unwrap());
        n.pop = Some(crate::util::intern(pop));
        n.score = Num::V(score);
        n
    };
    let none = HashMap::new();
    // 重新排序後 ICN 30 分排第一，原本的 HKG 33 分：差不到 15% + 5 → 放回 HKG
    let mut p = vec![node("198.51.100.1", "ICN", 30.0), node("198.51.100.2", "HKG", 33.0)];
    keep_pop(&mut p, &none, Some("HKG"));
    assert_eq!(p[0].pop_str(), "HKG");
    // HKG 50 分：差很多 → 換成 ICN
    let mut p = vec![node("198.51.100.1", "ICN", 30.0), node("198.51.100.2", "HKG", 50.0)];
    keep_pop(&mut p, &none, Some("HKG"));
    assert_eq!(p[0].pop_str(), "ICN");
    // HKG 被標成不能用：照新的排序
    let mut p = vec![node("198.51.100.1", "ICN", 30.0), node("198.51.100.2", "HKG", 31.0)];
    let mut bad = HashMap::new();
    bad.insert(
        "198.51.100.2".parse().unwrap(),
        crate::pools::Bad {
            at: 0,
            reason: "品質檢查連不上".into(),
            quality: true,
        },
    );
    keep_pop(&mut p, &bad, Some("HKG"));
    assert_eq!(p[0].pop_str(), "ICN");
}
