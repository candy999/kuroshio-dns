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
        status: 200,
        head_secs: 0.0,
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

/// 3.5.0 F16：誤差範圍 `clamp(0.05 + 0.035 ÷ √秒, 0.06, 0.18)`，規格的表
#[test]
fn tolerance_v2_table() {
    for (secs, want) in [(0.13, 0.147), (0.5, 0.099), (1.5, 0.079), (3.8, 0.068)] {
        assert!((tolerance(secs) - want).abs() < 0.001, "{secs} 秒：{}", tolerance(secs));
    }
    assert_eq!(tolerance(0.01), speed::TOL_MAX);
    assert_eq!(tolerance(0.0), speed::TOL_MAX, "沒有時間：當成最不準");
    assert_eq!(tolerance(f64::NAN), speed::TOL_MAX);
    assert_eq!(tolerance(3600.0), speed::TOL_MIN);
    let mut last = 1.0;
    for s in [0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 60.0] {
        assert!(tolerance(s) <= last, "{s}");
        last = tolerance(s);
    }
    // 每一段都留實測最大差距的 1.5 倍以上（0.13 秒 9%、1.5 秒 4%、3.8 秒 5%）
    assert!(tolerance(0.13) >= 0.09 * 1.5 && tolerance(1.5) >= 0.04 * 1.5 && tolerance(3.8) >= 0.045 * 1.5);
}

/// 3.5.0 F16：W3、D7 的實測（不含 TTFB）收緊之後照樣判成瓶頸
#[test]
fn bottleneck_still_detected_on_w3_and_d7_samples() {
    // W3 Cloudflare 連測：56.7～61.9 MB/s（約 0.13 秒，差 9%）
    let w3 = [sample(56.7, 0.141), sample(61.9, 0.129), sample(59.0, 0.136), sample(60.2, 0.133)];
    assert_eq!(same_speed(&w3), Some(60.2));
    let w3b = [sample(61.8, 0.129), sample(62.4, 0.128), sample(62.0, 0.129), sample(62.1, 0.129)];
    assert!(same_speed(&w3b).is_some());
    // W3 CloudFront：5.38～5.58（約 1.5 秒）
    let cfr = [sample(5.38, 1.49), sample(5.58, 1.43), sample(5.45, 1.47), sample(5.5, 1.45)];
    assert!(same_speed(&cfr).is_some());
    // D7：Cloudflare 2.07～2.15、CloudFront 2.07～2.18（約 3.8 秒）
    let d7cf = [sample(2.07, 3.86), sample(2.15, 3.72), sample(2.12, 3.77), sample(2.1, 3.81)];
    let d7cfr = [sample(2.07, 3.86), sample(2.18, 3.67), sample(2.1, 3.81), sample(2.12, 3.77)];
    assert!(same_speed(&d7cf).is_some() && same_speed(&d7cfr).is_some());
    // 3.4.x 看到的「差 27%」（把 TTFB 算進速度）收緊之後不再算瓶頸：那麼大的差距在不含 TTFB 的量法裡是真的差別
    let v = [sample(61.5, 0.13), sample(48.0, 0.166), sample(65.7, 0.122), sample(55.0, 0.145)];
    assert_eq!(same_speed(&v), None);
    // 原本就判得出來的照舊
    assert_eq!(same_speed(&[full(61.2), full(61.4), full(60.9), full(61.3)]), Some(61.3));
    assert_eq!(same_speed(&[full(5.5), full(5.4), full(5.6), full(5.5)]), Some(5.5));
}

/// 3.5.0 F16：W3「關」的那一輪看得到 40.8～63.5 的節點；前 4 個裡有一個 45 MB/s 就不啟動減量（那個節點是真的比較慢）
#[test]
fn bottleneck_not_detected_with_one_45_among_61() {
    let v = [sample(61.3, 0.13), sample(61.4, 0.13), sample(45.0, 0.178), sample(61.2, 0.131)];
    assert_eq!(same_speed(&v), None);
    let ok = [sample(61.3, 0.13), sample(61.4, 0.13), sample(61.1, 0.131), sample(61.2, 0.131)];
    assert!(same_speed(&ok).is_some());
}

/// 帶「前 1 MiB」時間的完整測樣本
fn full_head(mbps: f64, head_secs: f64) -> SpeedSample {
    SpeedSample { head_secs, ..full(mbps) }
}

/// 3.5.0 F16：快測門檻跟完整測的「前 1 MiB」比。CloudFront 快測 1 MiB 花 0.89 秒（1.15 MB/s，完整測的 21%：開頭慢）
#[test]
fn quick_floor_uses_first_mib_reference() {
    let first = [
        full_head(5.45, 0.87),
        full_head(5.4, 0.88),
        full_head(5.5, 0.86),
        full_head(5.46, 0.87),
    ];
    let q = speed::quick_ref(&first).unwrap();
    assert!((q - 1.15).abs() < 0.01, "{q}");
    let floor = speed::quick_floor_ref(q, 0.89);
    assert!((0.50..0.55).contains(&floor), "{floor}");
    assert!(1.15 / floor >= 2.0, "餘裕 2 倍以上（舊公式只有 1.4 倍）");
    // 舊公式：min(參考 × 0.5, 1) × (1 − 誤差)
    let old = speed::quick_floor(5.45, 0.89);
    assert!(1.15 / old < 1.4, "{old}");
    // Cloudflare：前 1 MiB 約 35～50 MB/s → 門檻約 15～21
    let cf = [
        full_head(61.0, 0.025),
        full_head(61.2, 0.024),
        full_head(60.9, 0.026),
        full_head(61.1, 0.025),
    ];
    let f = speed::quick_floor_ref(speed::quick_ref(&cf).unwrap(), 0.025);
    assert!((15.0..=21.0).contains(&f), "{f}");
}

#[test]
fn quick_floor_falls_back_without_head_secs() {
    assert_eq!(
        speed::quick_ref(&[full(5.45), full(5.4), full(5.5), full(5.46)]),
        None,
        "假的網路、舊資料"
    );
    // 只有 2 個量到前 1 MiB：不夠
    assert_eq!(
        speed::quick_ref(&[full_head(5.45, 0.87), full_head(5.4, 0.88), full(5.5), full(5.46)]),
        None
    );
    assert!(
        (speed::quick_floor(5.45, 0.89) - (1.0 - tolerance(0.89))).abs() < 1e-9,
        "照 B1 的公式"
    );
}

#[test]
fn bottleneck_detected_on_fast_line_9_percent_spread() {
    let v = [sample(61.5, 0.13), sample(57.0, 0.14), sample(61.9, 0.129), sample(59.0, 0.136)];
    assert_eq!(same_speed(&v), Some(61.5), "中位數");
    assert_eq!(
        same_speed_legacy(&v.iter().map(|s| s.mbps).collect::<Vec<_>>()),
        None,
        "3.4.x（5%）：減量不啟動"
    );
    // 傳輸時間長（量得準）的時候，11% 就是真的差別
    let slow_line = [sample(6.15, 1.3), sample(5.5, 1.45), sample(6.19, 1.29), sample(5.9, 1.36)];
    assert_eq!(same_speed(&slow_line), None);
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
    // 慢的線路（每個都約 0.25 MB/s）：以前「都在 1 MB/s 以下不算瓶頸」，現在一樣是瓶頸
    assert_eq!(
        same_speed(&[sample(0.25, 8.0), sample(0.245, 8.0), sample(0.255, 8.0), sample(0.25, 8.0)]),
        Some(0.25)
    );
    assert_eq!(same_speed_legacy(&[0.25, 0.245, 0.255, 0.25]), None);
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
    // 級別：每慢一個誤差範圍多一級（3.5.0 F16：差 15% 以上才算不同級）
    assert_eq!(speed_class(Some(60.0), false, 61.0, 0.15), 0);
    assert_eq!(speed_class(Some(52.0), false, 61.0, 0.15), 0);
    assert_eq!(speed_class(Some(51.0), false, 61.0, 0.15), 1);
    assert_eq!(speed_class(Some(40.0), false, 61.0, 0.15), 2);
    assert_eq!(speed_class(Some(60.8), false, 61.2, 0.15), 0, "61.2 與 60.8 仍然同一級");
    assert_eq!(speed_class(Some(40.0), false, 61.0, 0.3), 2, "誤差範圍最多 0.18");
    assert_eq!(speed_class(None, false, 61.0, 0.15), speed::CLASS_UNMEASURED);
    assert_eq!(speed_class(Some(0.0), false, 61.0, 0.15), speed::CLASS_UNMEASURED);
    assert_eq!(speed_class(Some(60.0), true, 61.0, 0.15), speed::CLASS_SLOW);
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
    // 快的線路：8 MiB 約 0.13 秒，各節點差到 9%（W3）。3.5.0 判成瓶頸，其餘只收 1 MiB；
    // 節點依延遲排（不是依雜訊），每個節點最多一次下載（流量只少不多）
    const MBPS: [f64; 8] = [61.5, 57.0, 61.9, 59.0, 58.0, 60.0, 56.7, 61.0];
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
    assert_eq!(order, [2, 0, 7, 5, 3, 4, 1, 6], "速度大的在前");
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
        let mbps = [0.25, 0.245, 0.255, 0.25, 0.20, 0.05][third(i)];
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

/// 2026-11-11 種子裡的節點池（實機量到的延遲與速度）當成一次節點池工作的量測結果：
/// 完整測（收滿 8 MiB，時間由速度回推）。3.5.1 起種子更新了，重播用的這一份另外存在 `tests/replay-pools.json`，結果才固定
fn seed_pool(provider: &str) -> Vec<PoolNode> {
    let text = include_str!("replay-pools.json");
    let f: PoolsFile = serde_json::from_str(text).unwrap();
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

// ------------------------------------------------------------ 3.5.0 F15：測速被對方限流

/// 第 `limit_at` 次下載（從 0 算）起回 `status`；之前照 `mbps` 回（完整測、時間由速度回推）
fn limited_net(net: &MockNet, mbps: f64, limit_at: usize, status: u16) {
    let k = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    net.on_sample(move |_, max| {
        if k.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= limit_at {
            SpeedSample {
                status,
                connect_ms: 4.0,
                ttfb_ms: 9.0,
                ..Default::default()
            }
        } else {
            SpeedSample::from_mbps(mbps, max)
        }
    });
}

fn pool_of(ctx: &crate::jobs::JobCtx) -> Vec<PoolNode> {
    ctx.cdn.state().pools.p["cloudflare"].pool4.clone()
}

#[tokio::test]
async fn speed_test_stops_for_provider_after_first_429() {
    for status in [429, 503] {
        let (ctx, net) = pool_ctx(8, json!({}));
        limited_net(&net, 5.0, 2, status);
        pool::run(&ctx).await.unwrap();
        assert_eq!(net.calls("speed").len(), 3, "第 3 個被限流：之後 0 次下載（HTTP {status}）");
        let pool = pool_of(&ctx);
        assert_eq!(pool.len(), 8, "節點池照建（照延遲）");
        let measured = pool.iter().filter(|n| n.speed.get().is_some()).count();
        assert_eq!(measured, 2, "沒量到的不記成 0 MB/s");
        assert!(pool.iter().all(|n| n.speed != Num::V(0.0)));
    }
}

#[tokio::test]
async fn unmeasured_nodes_keep_speed_none_in_both_rule_sets() {
    for relative in [true, false] {
        let (ctx, net) = pool_ctx(5, json!({ "pool": { "relativeSpeed": relative } }));
        net.on_sample(|i, max| {
            if third(i) == 1 {
                SpeedSample {
                    status: 403,
                    ..Default::default()
                }
            } else {
                SpeedSample::from_mbps(11.8, max)
            }
        });
        pool::run(&ctx).await.unwrap();
        assert_eq!(net.calls("speed").len(), 5, "其他失敗不停測");
        let pool = pool_of(&ctx);
        let n1 = pool.iter().find(|n| third(n.ip) == 1).unwrap();
        assert_eq!(n1.speed.get(), None, "relative {relative}");
        assert_eq!(n1.is_slow(), None, "沒量到不是慢");
        assert_eq!(qscore(n1), n1.ms.or(0.0), "舊規則也不再加 80 分");
        let order: Vec<usize> = pool.iter().map(|n| third(n.ip)).collect();
        assert_eq!(*order.last().unwrap(), 1, "排在量到的後面（{order:?}）");
    }
}

#[tokio::test]
async fn rate_limited_round_reuses_previous_speed_up_to_three_rounds() {
    let (ctx, net) = pool_ctx(5, json!({}));
    net.on_sample(|i, max| SpeedSample::from_mbps([11.8, 4.0, 11.7, 11.9, 9.0][third(i)], max));
    pool::run(&ctx).await.unwrap();
    let first = pool_of(&ctx);
    let slow1 = first.iter().find(|n| third(n.ip) == 1).unwrap().slow;
    assert_eq!(slow1, Some(true));
    // 之後每一輪一開始就被限流：沿用上一輪的速度與 slow，標第幾輪；參考速度沿用
    for round in 1..=4u32 {
        net.on_sample(|_, _| SpeedSample {
            status: 429,
            ..Default::default()
        });
        pool::run(&ctx).await.unwrap();
        let pool = pool_of(&ctx);
        let n1 = pool.iter().find(|n| third(n.ip) == 1).unwrap();
        let n0 = pool.iter().find(|n| third(n.ip) == 0).unwrap();
        if round <= 3 {
            assert_eq!((n0.speed, n0.speed_age), (Num::V(11.8), Some(round)), "第 {round} 輪");
            assert_eq!((n1.speed, n1.slow), (Num::V(4.0), Some(true)), "旗標照舊");
            assert_eq!(*pool.last().unwrap(), *n1, "慢的照樣排最後");
            assert_eq!(ctx.cdn.state().pools.p["cloudflare"].rest["speedRef"], 11.7);
        } else {
            assert_eq!((n0.speed.get(), n0.speed_age), (None, None), "最多沿用 3 輪");
            assert!(
                ctx.cdn.state().pools.p["cloudflare"].rest.get("speedRef").is_some(),
                "參考值沿用上一輪的"
            );
        }
    }
    // 下一輪沒被限流：自己恢復，speedAge 拿掉
    net.on_sample(|i, max| SpeedSample::from_mbps([11.8, 4.0, 11.7, 11.9, 9.0][third(i)], max));
    pool::run(&ctx).await.unwrap();
    assert!(pool_of(&ctx).iter().all(|n| n.speed_age.is_none() && n.speed.get().is_some()));
    assert!(ctx.cdn.pools_status()["cloudflare"]["speedRefWhy"].is_null());
}

#[tokio::test]
async fn speed_ref_missing_reason_is_logged_and_reported() {
    // 限流、上一輪也沒有參考速度
    let (ctx, net) = pool_ctx(5, json!({}));
    limited_net(&net, 5.0, 1, 429);
    pool::run(&ctx).await.unwrap();
    let st = ctx.cdn.pools_status();
    assert_eq!(st["cloudflare"]["speedRef"], Value::Null);
    assert_eq!(st["cloudflare"]["speedRefWhy"], "被限流（HTTP 429）");
    // 量到的不夠 3 個
    let (ctx, net) = pool_ctx(5, json!({}));
    net.on_sample(|i, max| {
        if third(i) < 2 {
            SpeedSample::from_mbps(5.0, max)
        } else {
            SpeedSample::default()
        }
    });
    pool::run(&ctx).await.unwrap();
    assert_eq!(
        ctx.cdn.pools_status()["cloudflare"]["speedRefWhy"],
        "量到速度的節點只有 2 個（要 3 個）"
    );
}

#[test]
fn log_prints_status_not_zero_mbps() {
    let ip = ip("192.0.2.1");
    let s403 = SpeedSample {
        status: 403,
        connect_ms: 4.0,
        ttfb_ms: 9.0,
        ..Default::default()
    };
    let line = pool::speed_line(ip, "TPE", 3.0, &s403, None);
    assert!(line.contains("沒量到（HTTP 403）") && !line.contains("0 MB/s"), "{line}");
    let line = pool::speed_line(ip, "TPE", 3.0, &SpeedSample::default(), None);
    assert!(line.contains("沒量到（連線失敗）"), "{line}");
    let ok = SpeedSample {
        head_secs: 0.87,
        ..full(5.45)
    };
    let line = pool::speed_line(ip, "TPE", 3.0, &ok, None);
    assert!(line.contains("5.45 MB/s（8192 KB／") && line.contains("前 1 MiB 0.87 秒"), "{line}");
    assert!(pool::rate_limited(429) && pool::rate_limited(503) && !pool::rate_limited(403));
}

/// 3.5.0 F6（H12）：快測那一行印實際量到的速度，排序用的另外寫
#[test]
fn quick_test_log_shows_measured_speed() {
    let q = sample(1.15, 0.89);
    let line = pool::speed_line(ip("192.0.2.1"), "TPE", 3.0, &q, Some((true, 5.45)));
    assert!(line.contains("1.15 MB/s（快測，通過；排序用 5.45）"), "{line}");
    let line = pool::speed_line(ip("192.0.2.1"), "TPE", 3.0, &sample(0.3, 3.3), Some((false, 0.52)));
    assert!(line.contains("0.3 MB/s（快測，低於門檻 0.52，算慢）"), "{line}");
}

/// 3.5.0 F16：節點池工作的快測門檻用完整測的前 1 MiB（`quickRef`），CloudFront 開頭慢的節點照樣通過
#[tokio::test]
async fn pool_job_quick_test_uses_first_mib_reference() {
    let run = |relative: bool| async move {
        let (ctx, net) = pool_ctx(6, json!({ "pool": { "relativeSpeed": relative } }));
        net.on_sample(|i, max| {
            if max <= MIB {
                // 快測：1 MiB 花 0.89 秒（1.15 MB/s）；最後一個真的很慢
                let secs = if third(i) == 5 { 4.0 } else { 0.89 };
                SpeedSample {
                    mbps: (1.0 / secs * 100.0f64).round() / 100.0,
                    bytes: MIB,
                    secs,
                    status: 200,
                    head_secs: secs,
                    ..Default::default()
                }
            } else {
                full_head([5.45, 5.4, 5.5, 5.46, 0.0, 0.0][third(i)], 0.87)
            }
        });
        pool::run(&ctx).await.unwrap();
        let (pool, q) = {
            let st = ctx.cdn.state();
            let d = &st.pools.p["cloudflare"];
            (d.pool4.clone(), d.rest.get("quickRef").cloned())
        };
        (pool, q, ctx.cdn.pools_status())
    };
    let (pool, qref, status) = run(true).await;
    assert_eq!(qref, Some(json!(1.15)));
    assert_eq!(status["cloudflare"]["quickRef"], 1.15);
    let by = |k: usize| pool.iter().find(|n| third(n.ip) == k).unwrap().clone();
    assert_eq!(
        (by(4).speed, by(4).slow),
        (Num::V(5.46), Some(false)),
        "1.15 對門檻約 0.52：通過（記成瓶頸的速度）"
    );
    assert_eq!((by(5).speed, by(5).slow), (Num::V(0.25), Some(true)));
    assert_eq!(by(0).sample.as_ref().unwrap().head_secs, Num::V(0.87), "樣本多 headSecs");
    // pool.relativeSpeed 關：3.4.x 的規則（1 MB/s），沒有 quickRef
    let (pool, qref, _) = run(false).await;
    assert_eq!(qref, None);
    let by = |k: usize| pool.iter().find(|n| third(n.ip) == k).unwrap().clone();
    assert_eq!(by(5).speed, Num::V(0.25));
    assert_eq!(by(5).slow, None, "舊規則不寫旗標");
}

/// 3.5.0 F16：W3（開／關）、D7（開／關）的測速（`/api/cdn/pools` 原始檔不在 repo 裡，照規格 11 F16 的表重建；
/// IP 是文件用位址）重播：收緊之後，W3「開」與 D7 的前 4 個照樣判成瓶頸；W3「關」那一輪有 45 MB/s 的節點就不啟動
#[test]
fn replay_w3_d7_samples_with_tighter_tolerance() {
    let w3_on = [sample(61.2, 0.131), sample(61.5, 0.13), sample(61.35, 0.13), sample(61.4, 0.13)];
    let w3_off = [sample(63.5, 0.126), sample(45.0, 0.178), sample(40.8, 0.196), sample(61.0, 0.131)];
    let d7_on = [sample(2.07, 3.86), sample(2.15, 3.72), sample(2.12, 3.77), sample(2.1, 3.81)];
    let d7_cfr = [sample(2.07, 3.86), sample(2.18, 3.67), sample(2.1, 3.81), sample(2.12, 3.77)];
    let show = |v: &[SpeedSample]| v.iter().map(|s| s.mbps.to_string()).collect::<Vec<_>>().join(" / ");
    for (tag, v, want) in [
        ("W3 開", &w3_on, true),
        ("W3 關", &w3_off, false),
        ("D7 Cloudflare", &d7_on, true),
        ("D7 CloudFront", &d7_cfr, true),
    ] {
        println!("[{tag}] {} → {:?}", show(v), same_speed(v));
        assert_eq!(same_speed(v).is_some(), want, "{tag}");
    }
    // 排序：61.2 與 60.8 同一級（延遲決定），45 慢一級以上
    let r = [ranked(6.0, Some(61.2)), ranked(3.0, Some(60.8)), ranked(2.0, Some(45.0))];
    assert_eq!(order(&r, true), [1, 0, 2]);
}

/// 3.5.0 F16：`pool.relativeSpeed: false`＝3.4.x 的規則，不受誤差範圍收緊與快測門檻影響
#[test]
fn relative_speed_off_unchanged() {
    assert_eq!(same_speed_legacy(&[61.2, 61.4, 60.9, 61.3]), Some(61.3));
    assert_eq!(same_speed_legacy(&[61.5, 57.0, 61.9, 59.0]), None, "5% 門檻不變");
    // 節點池工作：沒有 quickRef、沒有 slow 旗標（見 pool_job_quick_test_uses_first_mib_reference、
    // pool_job_fast_line_noisy_speeds_start_reduction 的「關」）
    let o = order(&[ranked(6.0, Some(61.2)), ranked(3.0, Some(60.8))], false);
    assert_eq!(o, [0, 1], "直接比速度");
}
