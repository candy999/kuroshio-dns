//! 記憶體控制與過濾清單（3.5.0 C3）：記憶體不足時一次停用多份清單、只重建一次；恢復時也一樣。
//!
//! 獨立一個測試檔（獨立的行程）：記憶體控制每一輪會改整個程式共用的「可以長大」旗標，
//! 跟 `filtering.rs` 裡要存本機副本的測試放在一起會互相影響

use kuroshio::resolver::FilterCheck as _;
use serde_json::json;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// 依路徑回不同內容的清單伺服器；`down` = true 時全部回 503（模擬下載失敗）
async fn lists_by_path(lists: Vec<(&'static str, String)>, down: std::sync::Arc<std::sync::atomic::AtomicBool>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let lists = std::sync::Arc::new(lists);
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let (lists, down) = (lists.clone(), down.clone());
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let body = lists.iter().find(|(p, _)| path == format!("/{p}")).map(|x| x.1.clone());
                let resp = match body {
                    Some(b) if !down.load(std::sync::atomic::Ordering::Relaxed) => {
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{b}", b.len())
                    }
                    _ => "HTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n".to_string(),
                };
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    addr
}

fn many(prefix: &str, n: usize) -> String {
    (0..n).map(|i| format!("||{prefix}{i}.example^\n")).collect()
}

const MB: u64 = 1 << 20;

fn reading(avail: u64) -> kuroshio::memgov::Reading {
    kuroshio::memgov::Reading {
        rss: None,
        total: Some(1000 * MB),
        avail: Some(avail),
        psi: None,
    }
}

/// 反詐騙（惡意，預設保護）、標成保護的廣告、4 份廣告、1 份遙測；`ads` = 每份廣告的規則數
async fn c3_service(
    tag: &str,
    ads: [usize; 4],
) -> (
    std::sync::Arc<kuroshio::filtering::FilterService>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::path::PathBuf,
) {
    let down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let srv = lists_by_path(
        vec![
            ("tw165.txt", many("scam", 50)),
            ("keep.txt", many("keep", 100)),
            ("a1.txt", many("aa", ads[0])),
            ("a2.txt", many("ab", ads[1])),
            ("a3.txt", many("ac", ads[2])),
            ("a4.txt", many("ad", ads[3])),
            ("tele.txt", many("tele", 1000)),
        ],
        down.clone(),
    )
    .await;
    let dir = std::env::temp_dir().join(format!("kuroshio-c3-{tag}-{}", std::process::id()));
    let cfg = kuroshio_config::with_overrides(&json!({ "filter": { "customRules": [], "lists": [
        { "name": "反詐騙", "url": format!("http://{srv}/tw165.txt"), "category": "malware" },
        { "name": "保護廣告", "url": format!("http://{srv}/keep.txt"), "category": "ads", "protect": true },
        { "name": "廣告1", "url": format!("http://{srv}/a1.txt"), "category": "ads" },
        { "name": "廣告2", "url": format!("http://{srv}/a2.txt"), "category": "ads" },
        { "name": "廣告3", "url": format!("http://{srv}/a3.txt"), "category": "ads" },
        { "name": "廣告4", "url": format!("http://{srv}/a4.txt"), "category": "ads" },
        { "name": "遙測", "url": format!("http://{srv}/tele.txt"), "category": "telemetry" },
    ] } }));
    let f = kuroshio::filtering::FilterService::from_cfg(&cfg, &dir).unwrap();
    assert!(f.update_lists(true).await.unwrap());
    (f, down, dir)
}

fn names(v: &[kuroshio::filtering::Unloaded]) -> Vec<String> {
    v.iter().map(|u| u.name.clone()).collect()
}

/// 缺口大（可用 30 MB、保留 100 MB）：一輪就把可以停用的清單一次停用、只重建 1 次（以前 5 份重建 5 次）
#[tokio::test]
async fn far_deficit_unloads_several_lists_with_one_rebuild() {
    let (f, _down, _dir) = c3_service("far", [4000, 3000, 2000, 1000]).await;
    let r0 = f.rebuild_count();
    let g = kuroshio::memgov::Governor::new(
        kuroshio::memgov::Reserve::fixed(100 * MB),
        vec![Box::new(kuroshio::memgov::FilterStep { filter: f.clone() })],
        0,
    );
    assert_eq!(g.tick(reading(30 * MB), 1000).await.unwrap(), "shed:filter", "一步");
    assert_eq!(f.rebuild_count(), r0 + 1, "只重建一次");
    assert_eq!(names(&f.unloaded()), ["廣告1", "廣告2", "廣告3", "廣告4", "遙測"]);
    assert!(f.check("aa1.example", 1).is_none() && f.check("tele1.example", 1).is_none());
    assert!(f.check("scam1.example", 1).unwrap().block, "保護清單照常");
    assert!(f.check("keep1.example", 1).unwrap().block);
    let st = g.status_json();
    let detail = st["shed"][0]["detail"].as_str().unwrap();
    assert!(detail.contains("5 份清單") && detail.contains("廣告1"), "{detail}");
    assert!(f.unloaded().iter().all(|u| u.bytes > 0), "每份都有恢復時要的大小");
    // 再一輪：沒有可以停用的（只剩保護清單），不再重建
    assert!(g.tick(reading(30 * MB), 1010).await.is_none());
    assert_eq!(f.rebuild_count(), r0 + 1);
}

/// 3.5.0 退讓於事無補：缺口是其他程式造成（缺 70 MB、黑潮自己 20 MB）時不停用清單、不重建；
/// 缺口回到讓得出來的範圍（黑潮 45 MB：90 ≥ 70 × 1.2）連續 60 秒後照一般的方式停用
#[tokio::test]
async fn futile_deficit_keeps_lists() {
    let (f, _down, _dir) = c3_service("futile", [4000, 3000, 2000, 1000]).await;
    let r0 = f.rebuild_count();
    let g = kuroshio::memgov::Governor::new(
        kuroshio::memgov::Reserve::fixed(100 * MB),
        vec![Box::new(kuroshio::memgov::FilterStep { filter: f.clone() })],
        0,
    );
    let own = |mb: u64| kuroshio::memgov::Reading {
        rss: Some(mb * MB),
        ..reading(30 * MB)
    };
    let mut now = 1000;
    for _ in 0..10 {
        assert!(g.observe_futile(&own(20), now));
        assert!(g.tick(own(20), now).await.is_none());
        now += 2;
    }
    assert!(f.unloaded().is_empty(), "不停用清單");
    assert_eq!(f.rebuild_count(), r0, "不重建");
    assert!(f.check("aa1.example", 1).unwrap().block, "清單照常擋");
    assert_eq!(g.status_json()["futile"], true);
    // 讓得出來了：離開要連續 60 秒，之後一輪停用、重建 1 次
    let mut did = None;
    for _ in 0..40 {
        g.observe_futile(&own(45), now);
        did = did.or(g.tick(own(45), now).await);
        now += 2;
    }
    assert_eq!(did.as_deref(), Some("shed:filter"));
    assert_eq!(f.rebuild_count(), r0 + 1);
    assert!(!f.unloaded().is_empty());
}

/// 缺口小（或沒說缺多少）：照舊一次一份
#[tokio::test]
async fn near_deficit_still_unloads_one() {
    use kuroshio::memgov::Step;
    let (f, _down, _dir) = c3_service("near", [4000, 3000, 2000, 1000]).await;
    let step = kuroshio::memgov::FilterStep { filter: f.clone() };
    let r0 = f.rebuild_count();
    let o = step.shed(&reading(40 * MB)).await.unwrap();
    assert_eq!(names(&f.unloaded()), ["廣告1"]);
    assert!(o.detail.contains("廣告1 清單（4000 條規則）"), "{}", o.detail);
    // 缺的比下一份小：也只停用一份
    step.shed_for(&reading(40 * MB), 1).await.unwrap();
    assert_eq!(names(&f.unloaded()), ["廣告1", "廣告2"]);
    assert_eq!(f.rebuild_count(), r0 + 2);
    // 取到合計 ≥ 目標為止：目標比下一份（廣告3）大一點 → 廣告3、廣告4
    let next = f.next_shed_bytes().unwrap();
    let v = f.unload_many(next + 1, None).await.unwrap();
    assert_eq!(names(&v), ["廣告3", "廣告4"]);
    assert_eq!(f.rebuild_count(), r0 + 3);
}

#[tokio::test]
async fn unload_many_never_includes_protected() {
    let (f, _down, _dir) = c3_service("protect", [400, 300, 200, 100]).await;
    let v = f.unload_many(u64::MAX, None).await.unwrap();
    assert_eq!(names(&v), ["廣告1", "廣告2", "廣告3", "廣告4", "遙測"]);
    assert!(f.unload_many(u64::MAX, None).await.unwrap().is_empty(), "只剩保護清單");
    assert!(f.check("scam1.example", 1).unwrap().block && f.check("keep1.example", 1).unwrap().block);
    // 停用之後的新的一份放不進可用記憶體的一半：不做
    let (f, _down, _dir) = c3_service("protect2", [400, 300, 200, 100]).await;
    assert!(f.unload_many(0, Some(0)).await.is_err());
    assert!(f.unloaded().is_empty());
}

/// 重建失敗（沒有副本、下載失敗）：這次登記的全部撤回，舊的過濾器照常
#[tokio::test]
async fn unload_many_rolls_back_on_failure() {
    use std::sync::atomic::Ordering;
    let (f, down, _dir) = c3_service("rollback", [400, 300, 200, 100]).await;
    down.store(true, Ordering::Relaxed);
    assert!(f.unload_many(u64::MAX, None).await.is_err());
    assert!(f.unloaded().is_empty(), "全部撤回");
    assert!(f.check("aa1.example", 1).unwrap().block, "舊的照常");
    down.store(false, Ordering::Relaxed);
    assert_eq!(f.unload_many(u64::MAX, None).await.unwrap().len(), 5);
}

/// 恢復：從最後停用的開始，取到合計 × 1.3 ≤ 空間（至少 1 份），重建一次
#[tokio::test]
async fn restore_many_fits_room_and_rebuilds_once() {
    use std::sync::atomic::Ordering;
    let (f, down, _dir) = c3_service("restore", [4000, 3000, 2000, 1000]).await;
    f.unload_many(u64::MAX, None).await.unwrap();
    let u = f.unloaded();
    let (tele, a4) = (u[4].bytes, u[3].bytes);
    let r0 = f.rebuild_count();
    // 空間只夠遙測 + 廣告4
    let v = f.restore_many((tele + a4) * 13 / 10 + 1).await.unwrap();
    assert_eq!(names(&v), ["廣告4", "遙測"], "依停用順序列出");
    assert_eq!(f.rebuild_count(), r0 + 1, "兩份一起、重建一次");
    assert!(f.check("tele1.example", 1).unwrap().block && f.check("ad1.example", 1).unwrap().block);
    assert_eq!(names(&f.unloaded()), ["廣告1", "廣告2", "廣告3"]);
    // 空間不夠任何一份也至少 1 份（記憶體控制已經確認最後一份放得下）
    assert_eq!(names(&f.restore_many(0).await.unwrap()), ["廣告3"]);
    // 下載失敗：這幾份維持停用、順序不變
    down.store(true, Ordering::Relaxed);
    assert!(f.restore_many(u64::MAX).await.is_err());
    assert_eq!(names(&f.unloaded()), ["廣告1", "廣告2"]);
    down.store(false, Ordering::Relaxed);
    let r1 = f.rebuild_count();
    assert_eq!(names(&f.restore_many(u64::MAX).await.unwrap()), ["廣告1", "廣告2"]);
    assert_eq!(f.rebuild_count(), r1 + 1);
    assert!(f.unloaded().is_empty());
    assert!(f.restore_many(u64::MAX).await.unwrap().is_empty());
}

/// 一次恢復多份之後又不足：再停用；既有的退避（恢復後 10 分鐘內又吃緊，下次恢復的間隔加倍）照樣生效
#[tokio::test]
async fn restore_then_pressure_again_backs_off() {
    let (f, _down, _dir) = c3_service("flap", [1000, 1000, 1000, 1000]).await;
    let g = kuroshio::memgov::Governor::new(
        kuroshio::memgov::Reserve::fixed(100 * MB),
        vec![Box::new(kuroshio::memgov::FilterStep { filter: f.clone() })],
        0,
    );
    let mut now = 1000;
    g.tick(reading(30 * MB), now).await.unwrap();
    assert_eq!(f.unloaded().len(), 5);
    // 空間只夠一次恢復一份（每份大小差不多）
    let one = f.unloaded().iter().map(|u| u.bytes).max().unwrap();
    let ok = reading(150 * MB + one * 15 / 10);
    let mut times = Vec::new();
    while times.len() < 2 && now < 10_000 {
        now += 5;
        if g.tick(ok, now).await.as_deref() == Some("restore:filter") {
            times.push(now);
        }
    }
    assert_eq!(times.len(), 2, "一次一份（空間只夠一份）");
    let gap1 = times[1] - times[0];
    assert_eq!(f.unloaded().len(), 3);
    // 剛恢復又不足：再停用（一次、重建一次）
    let r0 = f.rebuild_count();
    now += 5;
    assert_eq!(g.tick(reading(30 * MB), now).await.unwrap(), "shed:filter");
    assert_eq!(f.rebuild_count(), r0 + 1);
    assert_eq!(f.unloaded().len(), 5);
    // 再恢復：間隔加倍
    let mut times = Vec::new();
    while times.len() < 2 && now < 20_000 {
        now += 5;
        if g.tick(ok, now).await.as_deref() == Some("restore:filter") {
            times.push(now);
        }
    }
    assert_eq!(times.len(), 2);
    let gap2 = times[1] - times[0];
    assert!(gap2 >= gap1 * 2, "退避：{gap1} → {gap2}");
}
