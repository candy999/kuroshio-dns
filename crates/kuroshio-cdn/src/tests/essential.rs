//! 內建一定通過的服務（3.5.0，規格 11 F11）的 CDN 部分：「不改寫」的四類照原本的答案回、不排任何背景工作。
//! 內建表是真實網域（`kuroshio_net::comm`）；這裡用測試專用的表注入 `*.example.com`（`test_essential`）

use super::selftest::setup;
use super::*;
use crate::cdn::test_essential;
use crate::explain::Context;
use crate::Task;
use std::sync::Mutex;

/// `filter.protectComm` 的開關是行程層級的：會切換它的測試一個一個跑
static SWITCH: Mutex<()> = Mutex::new(());

const NAME: &str = "time.essential.example.com";

fn query(c: &Arc<Cdn>, name: &str) -> (crate::ApplyResult, Message) {
    let mut m = msg(name, 1, &["104.21.0.5"], vec![]);
    let r = c.apply(&mut m, name, 1);
    (r, m)
}

#[test]
fn no_rewrite_kinds_are_served_untouched_and_never_verified() {
    let _g = SWITCH.lock().unwrap_or_else(|e| e.into_inner());
    kuroshio_net::comm::set_enabled(true);
    test_essential::set(&["essential.example.com"]);
    let (c, _) = setup(json!({}));
    for _ in 0..3 {
        let (r, m) = query(&c, NAME);
        assert_eq!(answer_ips(&m, 1), ["104.21.0.5"], "原本的答案");
        assert_eq!((r.provider, r.rewritten, r.ttl_cap), (Some("cloudflare"), None, None));
        assert_eq!(r.tags, ["內建服務:不改寫"]);
    }
    // AAAA、HTTPS、子網域、大小寫、結尾的點都一樣
    let (r, _) = query(&c, "A.TIME.Essential.example.com.");
    assert_eq!(r.tags, ["內建服務:不改寫"]);
    assert!(c.take_tasks().is_empty(), "不排驗證、ECS、跨 CDN、延遲量測");
    assert_eq!(c.stats().essential_kept, 4);
    assert_eq!(c.status_lite()["stats"]["essentialKept"], 4);
    assert!(c.state().db.get(NAME).is_none(), "不記進網域資料庫");
    let other = "x.notessential.example.com";
    query(&c, other);
    assert!(c.take_tasks().iter().any(|t| matches!(t, Task::Verify { .. })), "其他網域照常");
    test_essential::set(&[]);
}

#[test]
fn update_kind_is_rewritten_as_usual() {
    use kuroshio_net::comm::CommKind;
    // 系統與安全更新：只保證不被清單誤擋，CDN 照常改寫（大檔從台灣節點拿最有感）；推播照 B6
    assert!(!CommKind::Update.flags().no_rewrite);
    assert!(!CommKind::Apns.flags().no_rewrite && !CommKind::Fcm.flags().no_rewrite);
    let (c, _) = setup(json!({}));
    let (r, _) = query(&c, "dl.update.example.com");
    assert!(r.tags.iter().all(|t| t != "內建服務:不改寫"));
    assert!(c.take_tasks().iter().any(|t| matches!(t, Task::Verify { .. })));
}

#[test]
fn protect_comm_off_restores_list_blocking_and_rewrite() {
    let _g = SWITCH.lock().unwrap_or_else(|e| e.into_inner());
    test_essential::set(&["essential.example.com"]);
    let (c, _) = setup(json!({}));
    kuroshio_net::comm::set_enabled(false);
    let (r, _) = query(&c, NAME);
    kuroshio_net::comm::set_enabled(true);
    assert!(r.tags.iter().all(|t| t != "內建服務:不改寫"), "關掉＝照常處理（下一次查詢就生效）");
    assert!(c.take_tasks().iter().any(|t| matches!(t, Task::Verify { .. })));
    assert_eq!(c.stats().essential_kept, 0);
    let (r, _) = query(&c, NAME);
    assert_eq!(r.tags, ["內建服務:不改寫"], "打開馬上回來");
    test_essential::set(&[]);
}

#[test]
fn keep_names_do_not_affect_cdn_rewrite() {
    // 使用者自己加的後綴（resolver.keepNames）只有不擋＋快取優先，CDN 照常改寫
    kuroshio_net::comm::set_user(&["keepnames.example.com".into()]);
    let (c, _) = setup(json!({}));
    let (r, _) = query(&c, "a.keepnames.example.com");
    kuroshio_net::comm::set_user(&[]);
    assert!(r.tags.iter().all(|t| t != "內建服務:不改寫"));
    assert!(c.take_tasks().iter().any(|t| matches!(t, Task::Verify { .. })));
}

#[test]
fn explain_reports_essential() {
    let _g = SWITCH.lock().unwrap_or_else(|e| e.into_inner());
    kuroshio_net::comm::set_enabled(true);
    test_essential::set(&["essential.example.com"]);
    let (c, _) = setup(json!({}));
    query(&c, NAME);
    let v = c.explain(NAME, Context::default());
    test_essential::set(&[]);
    assert_eq!(v["decision"], "essential", "{v}");
    assert!(v["text"].as_str().unwrap().contains("不改寫、不擋"), "{v}");
    assert!(c.take_tasks().is_empty());
}
