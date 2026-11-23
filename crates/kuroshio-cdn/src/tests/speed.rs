//! 節點測速的相對評分（3.5.0，規格 11 B1）與量測樣本（B2 的量測基礎）。
//! 最後的 `replay_*` 是離線重播：同一份量測資料餵給 3.4.x 與 3.5.0 兩套規則，比較差在哪裡

use super::jobs::{ctx_for, write};
use super::*;
use crate::jobs::pool;
use crate::pools::{qscore, qscore_of, NodeSample, PoolNode, PoolsFile};
use crate::speed::{self, is_slow, order, same_speed, same_speed_legacy, speed_class, speed_ref, tolerance, Ranked};
use crate::util::Num;
use kuroshio_net::iprank::{Latency, Quality};
use kuroshio_net::probe::SpeedSample;
use serde_json::json;

const MIB: u64 = 1024 * 1024;

/// 收了 `bytes`、花 `secs` 秒的樣本
fn sample(mbps: f64, secs: f64) -> SpeedSample {
    SpeedSample {
        mbps,
        bytes: (mbps * secs * MIB as f64) as u64,
        secs,
        connect_ms: 4.0,
        ttfb_ms: 9.0,
    }
}

/// 收滿 8 MiB 的樣本（時間由速度回推）
fn full(mbps: f64) -> SpeedSample {
    SpeedSample::from_mbps(mbps, 8 * MIB)
}

fn ranked(ms: f64, mbps: Option<f64>) -> Ranked {
    Ranked {
        loss: 0.0,
        ms,
        mbps,
        secs: mbps.filter(|s| *s > 0.0).map_or(0.0, |s| 8.0 / s),
        slow: false,
    }
}

#[test]
fn tolerance_shrinks_with_duration_and_is_clamped() {
    // 傳輸時間越短，誤差範圍越大；有上下限
    assert!((tolerance(0.13) - 0.337).abs() < 0.005, "{}", tolerance(0.13));
    assert!((tolerance(1.5) - 0.142).abs() < 0.005, "{}", tolerance(1.5));
    assert!((tolerance(5.0) - 0.105).abs() < 0.005, "{}", tolerance(5.0));
    assert_eq!(tolerance(0.01), speed::TOL_MAX);
    assert_eq!(tolerance(0.0), speed::TOL_MAX, "沒有時間：當成最不準");
    assert_eq!(tolerance(f64::NAN), speed::TOL_MAX);
    assert_eq!(tolerance(3600.0), speed::TOL_MIN);
    let mut last = 1.0;
    for s in [0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 60.0] {
        assert!(tolerance(s) <= last, "{s}");
        last = tolerance(s);
    }
}

#[test]
fn bottleneck_detected_on_fast_line_27_percent_spread() {
    // Windows 實測：Cloudflare 4 個節點 8 MiB 各約 0.13 秒、速度差 27%。以前（5%）不算瓶頸，每個節點都收滿
    let v = [sample(61.5, 0.13), sample(48.0, 0.166), sample(65.7, 0.122), sample(55.0, 0.145)];
    assert_eq!(same_speed(&v), Some(61.5), "中位數");
    assert_eq!(
        same_speed_legacy(&v.iter().map(|s| s.mbps).collect::<Vec<_>>()),
        None,
        "3.4.x：減量不啟動"
    );
    // 傳輸時間長（量得準）的時候，27% 就是真的差別
    let slow_line = [sample(6.15, 1.3), sample(4.8, 1.66), sample(6.57, 1.22), sample(5.5, 1.45)];
    assert_eq!(same_speed(&slow_line), None);
    // 原本就判得出來的照舊
    assert_eq!(same_speed(&[full(61.2), full(61.4), full(60.9), full(61.3)]), Some(61.3));
    assert_eq!(same_speed(&[full(5.5), full(5.4), full(5.6), full(5.5)]), Some(5.5));
}

#[test]
fn not_bottleneck_when_slow_node_among_first_four() {
    // 前 4 個裡有一個明顯慢：照常每個都測
    assert_eq!(same_speed(&[full(61.2), full(30.0), full(61.3), full(61.0)]), None);
    assert_eq!(
        same_speed(&[sample(61.2, 0.13), sample(20.0, 0.4), sample(61.3, 0.13), sample(61.0, 0.13)]),
        None
    );
}

#[test]
fn zeros_not_counted() {
    // 量不到（0）、絕對下限以下：不是瓶頸
    assert_eq!(same_speed(&[full(0.0), full(0.0), full(0.0), full(0.0)]), None);
    assert_eq!(same_speed(&[full(61.0), full(0.0), full(61.0), full(61.0)]), None);
    assert_eq!(same_speed(&[sample(0.05, 8.0); 4]), None);
    assert_eq!(same_speed(&[]), None);
    // 慢的線路（每個都 0.25 MB/s）：以前「都在 1 MB/s 以下不算瓶頸」，現在一樣是瓶頸
    assert_eq!(
        same_speed(&[sample(0.25, 8.0), sample(0.24, 8.0), sample(0.26, 8.0), sample(0.25, 8.0)]),
        Some(0.25)
    );
    assert_eq!(same_speed_legacy(&[0.25, 0.24, 0.26, 0.25]), None);
}

#[test]
fn relative_slow_marks_half_of_reference() {
    let r = speed_ref([60.0, 58.0, 61.0, 20.0, 59.0]);
    assert_eq!(r, Some(59.0));
    assert!(is_slow(20.0, 0.4, r), "不到參考的一半");
    assert!(!is_slow(31.0, 0.26, r), "超過一半");
    // 剛好在邊界附近、傳輸時間很短（量不準）：不標（連樂觀的估計都不到一半才算慢）
    assert!(!is_slow(26.0, 0.13, r));
    assert!(is_slow(26.0, 5.0, r), "量得準的時候 26 < 29.5 就是慢");
    // 量到速度的節點不到 3 個：沒有東西可以比
    assert_eq!(speed_ref([60.0, 20.0]), None);
    assert_eq!(speed_ref([60.0, 0.0, 20.0, 0.0]), None, "量不到的不算");
    assert!(!is_slow(20.0, 0.4, None));
    assert!(!is_slow(0.0, 0.0, r), "量不到不是慢：沒有證據");
}

#[test]
fn no_slow_marks_on_uniformly_slow_line() {
    // 2 Mbps 的線路：每個節點都約 0.25 MB/s。以前全部低於 1 MB/s、全部被罰 80 分（等於沒有區別）
    let v = [0.25, 0.24, 0.26, 0.25, 0.23];
    let r = speed_ref(v);
    for s in v {
        assert!(!is_slow(s, 8.0, r), "{s}");
        assert!(matches!(Num::V(s), Num::V(x) if x < speed::LEGACY_SLOW_MBPS), "3.4.x：{s} 算慢");
    }
    // 節點上的旗標決定分數：不慢就沒有懲罰
    let mut n = PoolNode::new(ip("192.0.2.1"));
    n.ms = Num::V(30.0);
    n.speed = Num::V(0.25);
    assert_eq!(qscore(&n), 110.0, "沒有旗標（舊資料）：舊規則，罰 80");
    n.slow = Some(false);
    assert_eq!(qscore(&n), 30.0, "相對評分：整條線都慢不是節點的問題");
}

#[test]
fn absolute_floor_still_marks_broken() {
    // 低於絕對下限：不管別人多慢都算慢
    let r = speed_ref([0.09, 0.08, 0.09]);
    assert!(is_slow(0.09, 8.0, r));
    assert!(is_slow(0.05, 8.0, None), "沒有參考也算");
    assert!(!is_slow(0.12, 8.0, speed_ref([0.12, 0.11, 0.13])));
}

#[test]
fn speed_classes_then_latency() {
    // 61.2 與 60.8 MB/s 只是雜訊：同一級，延遲低的在前。以前直接比速度，61.2 贏
    let v = [
        ranked(6.0, Some(61.2)),
        ranked(3.0, Some(60.8)),
        ranked(4.0, Some(30.0)),
        ranked(2.0, None),
    ];
    assert_eq!(order(&v, false), [0, 1, 2, 3], "3.4.x：速度大的在前");
    assert_eq!(
        order(&v, true),
        [1, 0, 2, 3],
        "3.5.0：同一級比延遲；明顯慢一級的排後面；沒量到的再後面"
    );
    // 慢的排最後（連沒量到的都不如）
    let mut w = v.to_vec();
    w[2].slow = true;
    assert_eq!(order(&w, true), [1, 0, 3, 2]);
    // 丟包還是最優先
    let mut x = v.to_vec();
    x[1].loss = 0.2;
    assert_eq!(order(&x, true)[3], 1);
    // 級別：每慢一個誤差範圍多一級
    assert_eq!(speed_class(Some(60.0), false, 61.0, 0.3), 0);
    assert_eq!(speed_class(Some(43.0), false, 61.0, 0.3), 0);
    assert_eq!(speed_class(Some(42.0), false, 61.0, 0.3), 1);
    assert_eq!(speed_class(Some(29.0), false, 61.0, 0.3), 2);
    assert_eq!(speed_class(None, false, 61.0, 0.3), speed::CLASS_UNMEASURED);
    assert_eq!(speed_class(Some(0.0), false, 61.0, 0.3), speed::CLASS_UNMEASURED);
    assert_eq!(speed_class(Some(60.0), true, 61.0, 0.3), speed::CLASS_SLOW);
}

#[test]
fn old_pools_json_without_ref_uses_old_rule() {
    // 3.4.x 的 pools.json：節點沒有 `slow`、業者沒有 `speedRef` → 沿用舊規則（低於 1 MB/s 算慢），直到下一次節點池工作
    let f: PoolsFile = serde_json::from_value(json!({ "providers": { "fastly": { "v4": [
        { "ip": "192.0.2.1", "ms": 30.0, "speed": 0.5, "pop": "HKG" },
        { "ip": "192.0.2.2", "ms": 30.0, "speed": 5.0, "pop": "HKG" },
        { "ip": "192.0.2.3", "ms": 30.0, "pop": "HKG" }
    ] } } }))
    .unwrap();
    let v = f.providers["fastly"].v4.as_ref().unwrap();
    assert_eq!((v[0].is_slow(), v[1].is_slow(), v[2].is_slow()), (Some(true), Some(false), None));
    assert_eq!(qscore(&v[0]), 110.0);
    assert_eq!(
        qscore(&v[0]),
        qscore_of(v[0].ms, v[0].jitter, v[0].loss, v[0].speed),
        "跟 2.x 的算法一樣"
    );
    assert_eq!((qscore(&v[1]), qscore(&v[2])), (30.0, 30.0));
    assert!(!serde_json::to_string(&f).unwrap().contains("slow"), "沒有的欄位不會多寫出來");
}

#[test]
fn imported_pool_uses_its_own_ref() {
    // 從上游或好友匯入的節點池：速度是別人線路量的，`slow` 跟著那一份資料算好的旗標走，不用這台的門檻重算
    let f: PoolsFile = serde_json::from_value(json!({ "providers": { "fastly": { "speedRef": 0.25, "v4": [
        { "ip": "192.0.2.1", "ms": 30.0, "speed": 0.25, "slow": false, "pop": "HKG" },
        { "ip": "192.0.2.2", "ms": 30.0, "speed": 0.09, "slow": true, "pop": "HKG" },
        { "ip": "192.0.2.3", "ms": 30.0, "speed": 40.0, "slow": true, "pop": "HKG" }
    ] } } }))
    .unwrap();
    let p = &f.providers["fastly"];
    assert_eq!(p.rest["speedRef"], 0.25, "參考速度原樣保留");
    let v = p.v4.as_ref().unwrap();
    assert_eq!(qscore(&v[0]), 30.0, "那條線上 0.25 MB/s 不算慢");
    assert_eq!(qscore(&v[1]), 110.0);
    assert_eq!(qscore(&v[2]), 110.0, "那一份資料裡它是慢的（別人都更快）");
}

#[test]
fn pool_node_extra_roundtrip() {
    // 量測樣本寫出去再讀回來一樣；舊版不認識的欄位原樣保留
    let mut n = PoolNode::new(ip("192.0.2.1"));
    n.speed = Num::V(55.5);
    n.slow = Some(false);
    n.sample = Some(Box::new(NodeSample::of(&sample(55.5, 0.1441), false)));
    let text = serde_json::to_string(&n).unwrap();
    let j: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        j["sample"],
        json!({ "bytes": 8386038, "secs": 0.144, "connectMs": 4, "ttfbMs": 9 }),
        "{text}"
    );
    assert_eq!(j["slow"], false);
    let back: PoolNode = serde_json::from_str(&text).unwrap();
    assert_eq!(back, n);
    let v: PoolNode = serde_json::from_value(
        json!({ "ip": "192.0.2.2", "speed": 3.0, "xFuture": 7, "sample": { "bytes": 9, "tlsMs": 5.5, "quick": true } }),
    )
    .unwrap();
    assert_eq!(v.sample.as_ref().unwrap().quick, Some(true));
    let out = serde_json::to_value(&v).unwrap();
    assert_eq!((out["xFuture"].clone(), out["sample"]["tlsMs"].clone()), (json!(7), json!(5.5)));
    // 沒量過速度的節點：不多寫任何欄位
    assert_eq!(
        serde_json::to_value(PoolNode::new(ip("192.0.2.3"))).unwrap(),
        json!({ "ip": "192.0.2.3" })
    );
}

/// 節點池工作：`n` 個 /24 各一個台灣節點，延遲依第三段遞增（測速的順序固定）
fn pool_ctx(n: usize, extra: Value) -> (crate::jobs::JobCtx, Arc<MockNet>) {
    let mut cfg = json!({ "pool": { "candidatesPerProvider": n * 2, "poolSize": n, "speedTop": n } });
    kuroshio_config::merge(&mut cfg, &extra);
    let (ctx, net, paths) = ctx_for(json!({ "cloudflare": {"enabled": true} }), cfg);
    let subnets: String = (0..n).map(|i| format!("104.16.{i}.0/24\n")).collect();
    write(&paths, "scan/cloudflare-ipv4-TW.txt", &subnets);
    net.on_ping(|i| match i {
        IpAddr::V4(v) => lat(2.0 + v.octets()[2] as f64 * 0.1),
        IpAddr::V6(_) => Latency {
            ok: false,
            ms: f64::INFINITY,
        },
    });
    net.on_http(|_, _| resp(200, &[], "colo=TPE"));
    net.on_quality(|i| Quality {
        ms: match i {
            IpAddr::V4(v) => 2.0 + v.octets()[2] as f64 * 0.1,
            _ => 9.0,
        },
        jitter: 0.1,
        loss: 0.0,
        n: 5,
    });
    (ctx, net)
}

fn third(i: IpAddr) -> usize {
    match i {
        IpAddr::V4(v) => v.octets()[2] as usize,
        _ => 0,
    }
}

fn calls(net: &MockNet) -> (usize, usize) {
    let c = net.calls("speed");
    let full = c.iter().filter(|c| c.ends_with(&(8 * MIB).to_string())).count();
    (full, c.len() - full)
}

#[tokio::test]
async fn pool_job_fast_line_noisy_speeds_start_reduction() {
    // 快的線路：8 MiB 約 0.13 秒，各節點差到 27%。3.5.0 判成瓶頸，其餘只收 1 MiB；
    // 節點依延遲排（不是依雜訊），每個節點最多一次下載（流量只少不多）
    const MBPS: [f64; 8] = [61.5, 48.0, 65.7, 55.0, 58.0, 50.0, 63.0, 52.0];
    let run = |relative: bool| async move {
        let (ctx, net) = pool_ctx(8, json!({ "pool": { "relativeSpeed": relative } }));
        net.on_sample(|i, max| SpeedSample::from_mbps(MBPS[third(i)], max));
        pool::run(&ctx).await.unwrap();
        let st = ctx.cdn.state();
        let d = &st.pools.p["cloudflare"];
        let order: Vec<usize> = d.pool4.iter().map(|n| third(n.ip)).collect();
        let bytes: u64 = d.pool4.iter().filter_map(|n| n.sample.as_ref()).map(|s| s.bytes).sum();
        (calls(&net), order, bytes, d.pool4.clone(), d.rest.get("speedRef").cloned())
    };
    let (c, order, bytes, pool, sref) = run(true).await;
    assert_eq!(c, (4, 4), "前 4 個完整測，其餘快測");
    assert_eq!(order, [0, 1, 2, 3, 4, 5, 6, 7], "同一級：依延遲");
    assert_eq!(bytes, (4 * 8 + 4) * MIB);
    assert!(pool.iter().all(|n| n.slow == Some(false)), "沒有人被標成慢");
    assert_eq!(pool[5].speed, Num::V(61.5), "快測確認的節點記成瓶頸的速度");
    assert_eq!(pool[5].sample.as_ref().unwrap().quick, Some(true));
    assert_eq!(sref, Some(json!(61.5)));
    // 3.4.x 的規則：5% 門檻不成立，8 個都收滿；名次由雜訊決定
    let (c, order, bytes, pool, sref) = run(false).await;
    assert_eq!(c, (8, 0));
    assert_eq!(order, [2, 6, 0, 4, 3, 7, 5, 1], "速度大的在前");
    assert_eq!(bytes, 8 * 8 * MIB);
    assert!(pool.iter().all(|n| n.slow.is_none()), "舊規則不寫旗標");
    assert_eq!(sref, None);
}

#[tokio::test]
async fn pool_job_slow_line_is_bottleneck_and_nobody_is_penalized() {
    // 2 Mbps 的線路：每個節點約 0.25 MB/s，5 + 3 秒到時間只收到約 2 MiB。
    // 3.5.0：判成瓶頸、其餘快測（確認「不低於參考的一半」），沒有人被標成慢
    let (ctx, net) = pool_ctx(6, json!({}));
    net.on_sample(|i, max| {
        let mbps = [0.25, 0.24, 0.26, 0.25, 0.20, 0.05][third(i)];
        let secs = (max as f64 / MIB as f64 / mbps).min(8.0);
        sample(mbps, secs)
    });
    pool::run(&ctx).await.unwrap();
    assert_eq!(calls(&net), (4, 2));
    let st = ctx.cdn.state();
    let d = &st.pools.p["cloudflare"];
    let by = |k: usize| d.pool4.iter().find(|n| third(n.ip) == k).unwrap();
    for k in 0..5 {
        assert_eq!(by(k).slow, Some(false), "{k}");
    }
    assert_eq!(by(4).speed, Num::V(0.25), "快測 0.20 ≥ 參考的一半：記成瓶頸的速度");
    // 快測沒過的（0.05 MB/s，連絕對下限都不到）：記它自己的速度、算慢、排最後
    assert_eq!((by(5).speed, by(5).slow), (Num::V(0.05), Some(true)));
    assert_eq!(third(d.pool4.last().unwrap().ip), 5);
    assert_eq!(d.rest["speedRef"], 0.25);
}

#[tokio::test]
async fn pool_job_marks_relatively_slow_node() {
    // 一般的線路（量得準）：一個節點不到其他人的一半 → 相對的慢，排最後；3.4.x 的 1 MB/s 抓不到它
    let (ctx, net) = pool_ctx(5, json!({}));
    net.on_sample(|i, max| SpeedSample::from_mbps([11.8, 4.0, 11.7, 11.9, 9.0][third(i)], max));
    pool::run(&ctx).await.unwrap();
    assert_eq!(calls(&net), (5, 0), "前 4 個裡有慢的：不是瓶頸，每個都完整測");
    let st = ctx.cdn.state();
    let d = &st.pools.p["cloudflare"];
    let order: Vec<usize> = d.pool4.iter().map(|n| third(n.ip)).collect();
    assert_eq!(order, [0, 2, 3, 4, 1], "同一級依延遲 → 慢一級的 → 慢的");
    assert_eq!(d.pool4[4].slow, Some(true));
    assert_eq!(d.rest["speedRef"], 11.7);
}

// ------------------------------------------------------------ 離線重播

/// 種子裡的節點池（`data/seed/cdn-pools.json`，實機量到的延遲與速度）當成一次節點池工作的量測結果：
/// 完整測（收滿 8 MiB，時間由速度回推）
fn seed_pool(provider: &str) -> Vec<PoolNode> {
    let text = std::fs::read_to_string(repo().join("data/seed/cdn-pools.json")).unwrap();
    let f: PoolsFile = serde_json::from_str(&text).unwrap();
    f.providers[provider].v4.clone().unwrap()
}

fn replay(nodes: &[PoolNode]) -> (Vec<Ranked>, Option<f64>) {
    let speeds = || nodes.iter().filter_map(|n| n.speed.get());
    let reference = speed_ref(speeds());
    let v = nodes
        .iter()
        .map(|n| {
            let mbps = n.speed.get();
            let secs = mbps.filter(|s| *s > 0.0).map_or(0.0, |s| (8.0 / s).min(8.0));
            Ranked {
                loss: n.loss.or(0.0),
                ms: n.ms.or(999.0),
                mbps,
                secs,
                slow: mbps.is_some_and(|s| is_slow(s, secs, reference)),
            }
        })
        .collect();
    (v, reference)
}

/// 離線重播一：種子的 Cloudflare、CloudFront 節點池（一般的台灣節點，排序：丟包 → 速度 → 延遲）
#[test]
fn replay_seed_pools_old_vs_new_ranking() {
    for (provider, want_moved, want_same_set) in [("cloudflare", true, true), ("cloudfront", true, true)] {
        let nodes = seed_pool(provider);
        let (v, reference) = replay(&nodes);
        let (old, new) = (order(&v, false), order(&v, true));
        let show = |o: &[usize]| {
            o.iter()
                .map(|&i| format!("{}ms/{}", v[i].ms, v[i].mbps.map_or("—".into(), |s| s.to_string())))
                .collect::<Vec<_>>()
                .join("  ")
        };
        println!(
            "[{provider}] 參考速度 {reference:?}，分級的誤差範圍 {:.2}",
            speed::class_basis(&v).1
        );
        println!("  3.4.x：{}", show(&old));
        println!("  3.5.0：{}", show(&new));
        let moved = old.iter().zip(&new).filter(|(a, b)| a != b).count();
        println!(
            "  名次不同的節點：{moved}／{}；被標成慢：{}",
            v.len(),
            v.iter().filter(|x| x.slow).count()
        );
        assert_eq!(moved > 0, want_moved);
        // 同一批節點、只是順序不同：前 N 名（進節點池的）是同一組
        let mut a = old.clone();
        let mut b = new.clone();
        a.sort();
        b.sort();
        assert_eq!(a == b, want_same_set);
        assert!(v.iter().all(|x| !x.slow), "種子裡沒有相對慢的節點");
        // 新的順序：量到速度、同一級的節點依延遲遞增
        let top: Vec<f64> = new.iter().map(|&i| v[i].ms).take(10).collect();
        assert!(top.windows(2).all(|w| w[0] <= w[1]), "{top:?}");
    }
    // CloudFront：8.55 MB/s 的那個比其他（11.6～11.9）慢一級，沒量到的排它後面——跟 3.4.x 的尾巴一樣
    let (v, _) = replay(&seed_pool("cloudfront"));
    let new = order(&v, true);
    let tail: Vec<Option<f64>> = new[new.len() - 2..].iter().map(|&i| v[i].mbps).collect();
    assert_eq!(tail, [Some(8.55), None]);
    assert_eq!(order(&v, false)[new.len() - 2..], new[new.len() - 2..]);
}

/// 離線重播二：種子的 Fastly 節點池（鄰近節點，用品質分數；慢的加 80 分）在三種線路上的「慢」
#[test]
fn replay_seed_fastly_slow_marks_on_three_lines() {
    let nodes = seed_pool("fastly");
    let measured: Vec<f64> = nodes.iter().filter_map(|n| n.speed.get()).collect();
    assert_eq!(measured, [10.31, 11.66, 0.32, 0.13, 30.74]);
    let marks = |scale: f64| {
        let v: Vec<f64> = measured.iter().map(|s| (s * scale * 100.0).round() / 100.0).collect();
        let r = speed_ref(v.iter().copied());
        let secs = |s: f64| (8.0 / s).min(8.0);
        let new: Vec<bool> = v.iter().map(|s| is_slow(*s, secs(*s), r)).collect();
        let old: Vec<bool> = v.iter().map(|s| *s < speed::LEGACY_SLOW_MBPS).collect();
        println!("[fastly ×{scale}] 速度 {v:?}，參考 {r:?}\n  3.4.x 慢：{old:?}\n  3.5.0 慢：{new:?}");
        (old, new)
    };
    // 原本的線路：兩套規則標的是同一批（0.32、0.13）
    let (old, new) = marks(1.0);
    assert_eq!(old, [false, false, true, true, false]);
    assert_eq!(new, old);
    // 線路慢 20 倍（約 4 Mbps）：3.4.x 連正常的 10.31 → 0.52、11.66 → 0.58 都罰；3.5.0 還是只標那兩個
    let (old, new) = marks(0.05);
    assert_eq!(old, [true, true, true, true, false]);
    assert_eq!(new, [false, false, true, true, false]);
    // 線路快 10 倍：3.4.x 的 3.2、1.3 MB/s 不算慢（絕對門檻放過了明顯比別人差的）；3.5.0 照樣標出來
    let (old, new) = marks(10.0);
    assert_eq!(old, [false, false, false, false, false]);
    assert_eq!(new, [false, false, true, true, false]);
}
