//! 需要網路的行為（驗證、ECS、健檢、IPv6 發現）用假的網路測；另外測尖峰加權、ECS 網段順序、基準統計

use super::selftest::setup;
use super::*;
use crate::cdn::{CrossHint, HintIp, Hints, Task};
use crate::pools::{weighted_qscore, PoolNode};
use crate::util::{intern, now_ms, Num};
use kuroshio_net::iprank::Quality;
use kuroshio_proto::message::rtype;

fn cf_ok(colo: &str) -> ProbeResult {
    resp(
        200,
        &[("cf-ray", &format!("8a-{colo}")), ("server", "cloudflare")],
        "<html><title>Site</title></html>",
    )
}

/// 3.5.1 M2：基準（`base`）只給 v4。以前 v6 驗證也寫同一格，把 `base.ip` 蓋成 IPv6，
/// 之後 v4 的複驗、「原本就在台灣不換」拿 IPv6 量到的 POP 判 v4
#[tokio::test]
async fn v6_verify_does_not_overwrite_v4_base() {
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        st.db.touch(
            "both.test",
            "cloudflare",
            "ip",
            &ips(&["104.21.0.5"]),
            &ips(&["2606:4700::5"]),
            None,
        );
    });
    net.on_https(|i, _| match i.to_string().as_str() {
        "104.21.0.5" => cf_ok("NRT"),
        "2606:4700::5" => cf_ok("TPE"),
        "104.16.161.36" | "104.18.20.216" => cf_ok("TPE"),
        _ => fail("ECONNREFUSED"),
    });
    c.verify("both.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await;
    c.verify("both.test", "cloudflare", 6, Some(ip("2606:4700::5"))).await;
    let st = c.state();
    let e = st.db.get("both.test").unwrap();
    let b = e.base.as_ref().unwrap();
    assert_eq!(
        (b.ip, b.pop.as_deref()),
        (Some(ip("104.21.0.5")), Some("NRT")),
        "v6 驗證不動 v4 的基準"
    );
    assert_eq!(e.orig_ip(4), Some(ip("104.21.0.5")));
    assert!(e.v4.as_ref().unwrap().is("ok"), "原本在 NRT：照常換");
    drop(st);
    // 舊資料：基準 IP 已經被蓋成 IPv6 → v4 當成沒有基準，用最近一次的 A
    c.with_state(|st| st.db.get_mut("both.test").unwrap().base.as_mut().unwrap().ip = Some(ip("2606:4700::5")));
    let e = c.state().db.get("both.test").unwrap().clone();
    assert_eq!(e.orig_ip(4), Some(ip("104.21.0.5")));
    assert_eq!(e.base_ip4(), None);
    // 就算有人拿 IPv6 當 v4 的原本 IP 來驗證：不探測它、不拿它的 TPE 判「原本就在台灣」
    let r = c.verify("both.test", "cloudflare", 4, Some(ip("2606:4700::5"))).await;
    assert_eq!(r, Some("ok"));
    assert!(c
        .state()
        .db
        .get("both.test")
        .unwrap()
        .v4
        .as_ref()
        .unwrap()
        .extra
        .get("origTw")
        .is_none());
}

/// 3.5.1（測試版第二版 Windows C3）：複驗、輪流抽驗、手動驗證拿 `orig_ip()`（沒有基準時是答案裡第一個 A）當原本的 IP。
/// 第一個 A 不一定是這一家的（答案混著非 CDN 的位址），以前照樣量、寫進 `base`，下次啟動的整理才清掉「範圍外的基準」。
/// 現在改用這一格答案裡第一個在範圍裡的；都不在範圍裡就不量基準
#[tokio::test]
async fn out_of_range_orig_is_not_written_as_base() {
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        st.db.touch(
            "mixed.example.com",
            "cloudflare",
            "ip",
            &ips(&["198.51.100.7", "104.21.0.5"]),
            &[],
            None,
        );
        st.db
            .touch("cname.example.com", "cloudflare", "cname", &ips(&["198.51.100.8"]), &[], None);
    });
    net.on_https(|i, _| match i.to_string().as_str() {
        // 範圍外的那一台回「台灣」：拿它判「原本就在台灣、不換」就錯了
        "198.51.100.7" | "198.51.100.8" => cf_ok("TPE"),
        "104.21.0.5" => cf_ok("NRT"),
        "104.16.161.36" | "104.18.20.216" => cf_ok("TPE"),
        _ => fail("ECONNREFUSED"),
    });
    let orig = c.state().db.get("mixed.example.com").unwrap().orig_ip(4);
    assert_eq!(orig, Some(ip("198.51.100.7")), "前提：答案的第一個 A 在範圍外");
    assert_eq!(c.verify("mixed.example.com", "cloudflare", 4, orig).await, Some("ok"));
    {
        let st = c.state();
        let e = st.db.get("mixed.example.com").unwrap();
        let b = e.base.as_ref().unwrap();
        assert_eq!(
            (b.ip, b.pop.as_deref()),
            (Some(ip("104.21.0.5")), Some("NRT")),
            "用答案裡這一家的 IP 量基準"
        );
        assert!(
            e.v4.as_ref().unwrap().extra.get("origTw").is_none(),
            "不拿範圍外的 TPE 判原本就在台灣"
        );
        assert_eq!(e.orig_ip(4), Some(ip("104.21.0.5")), "之後的複驗用對的基準");
    }
    // 這一格答案裡沒有任何這一家的 IP：不量基準（驗證照做）
    let orig = c.state().db.get("cname.example.com").unwrap().orig_ip(4);
    c.verify("cname.example.com", "cloudflare", 4, orig).await;
    assert!(c.state().db.get("cname.example.com").unwrap().base.is_none());
    // 手動驗證（`POST /api/cdn/verify`）也一樣
    c.verify_now("mixed.example.com", 4).await;
    assert_eq!(
        c.state().db.get("mixed.example.com").unwrap().base.as_ref().unwrap().ip,
        Some(ip("104.21.0.5"))
    );
    assert_eq!(c.clean_stale_learning()[1], 0, "下次啟動沒有範圍外的基準要清");
}

/// 3.5.1 L4：驗證時本機通訊端出錯（連接埠用完、緩衝不足、檔案描述元用完）不當成網站或節點的結論
#[tokio::test]
async fn verifier_local_socket_errors_are_unsure() {
    let (c, net) = setup(json!({}));
    third_node(&c);
    c.with_state(|st| {
        for n in ["l1.example.com", "l2.example.com"] {
            st.db.touch(n, "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
        }
    });
    // 原站正常、候選全部是本機的錯誤：不算 3 個節點都連不上（那會記成網站的失敗），也不記到節點上
    net.on_https(|i, _| match i.to_string().as_str() {
        "104.21.0.5" => cf_ok("NRT"),
        _ => fail("EADDRINUSE"),
    });
    for n in ["l1.example.com", "l2.example.com"] {
        assert_eq!(c.verify(n, "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("unknown"));
        let v = c.state().db.get(n).unwrap().v4.clone().unwrap();
        assert_eq!(v.fails, None);
        assert!(v.reason.unwrap().contains("本機通訊端錯誤"));
    }
    assert!(
        c.state().pools.usable("cloudflare", ip("104.16.161.36")),
        "兩個網站都這樣也不暫停節點"
    );
    // 連原站都是本機的錯誤（Windows 的原始文字）
    net.on_https(|_, _| {
        fail("An operation on a socket could not be performed because the system lacked sufficient buffer space (os error 10055)")
    });
    assert_eq!(
        c.verify("l1.example.com", "cloudflare", 4, Some(ip("104.21.0.5"))).await,
        Some("unknown")
    );
    assert!(kuroshio_net::probe::is_local_error("EMFILE") && !kuroshio_net::probe::is_local_error("ECONNRESET"));
}

/// 3.5.1 L3：「特定產品專用」算不同的網站，7 天沒有新的「不服務」就消退
#[test]
fn zone_restricted_counts_sites_and_decays() {
    let (c, _) = setup(json!({}));
    let x = ip("104.16.161.36");
    c.with_state(|st| {
        let p = &mut st.pools;
        for _ in 0..5 {
            p.zone_note_site("cloudflare", x, false, "a.example.com");
        }
        assert!(!p.is_restricted("cloudflare", x), "同一個網站重驗 5 次只算一次");
        p.zone_note_site("cloudflare", x, false, "b.example.com");
        assert!(p.is_restricted("cloudflare", x), "兩個不同的網站");
        let now = now_ms();
        assert_eq!(p.decay_zone(now + 6 * 86_400_000), 0, "6 天：還在");
        assert_eq!(p.decay_zone(now + 8 * 86_400_000), 1, "7 天沒有新的就清掉");
        assert!(!p.is_restricted("cloudflare", x));
        assert!(!p.zone.contains_key("cloudflare|104.16.161.36"), "也沒有「服務」的整筆拿掉");
        // 有「服務」紀錄的留著，只清「不服務」
        p.zone_note_site("cloudflare", x, true, "c.example.com");
        p.zone_note_site("cloudflare", x, false, "a.example.com");
        assert_eq!(p.decay_zone(now + 8 * 86_400_000), 1);
        let z = &p.zone["cloudflare|104.16.161.36"];
        assert_eq!((z.hit, z.miss, z.sites.len()), (1, 0, 0));
    });
}

/// 3.5.1：「多個網站無法使用」的日誌附上網站數與前 3 個網站（名稱只在記憶體裡；重新啟動前記的沒有名稱）
#[test]
fn zone_restricted_log_lists_sites() {
    use crate::pools::sites_text;
    let n = |v: &[&str]| v.iter().map(|s| Box::<str>::from(*s)).collect::<Vec<_>>();
    assert_eq!(
        sites_text(&n(&["a.example.com", "b.example.com"]), 2),
        "a.example.com、b.example.com"
    );
    assert_eq!(
        sites_text(&n(&["a.example.com", "b.example.com", "c.example.com"]), 5),
        "a.example.com、b.example.com、c.example.com 等"
    );
    assert_eq!(sites_text(&n(&["a.example.com"]), 2), "a.example.com；另 1 個是之前記的，沒有名稱");
    assert_eq!(sites_text(&[], 3), "3 個是之前記的，沒有名稱");
    let (c, _) = setup(json!({}));
    let x = ip("104.16.161.36");
    c.with_state(|st| {
        let p = &mut st.pools;
        for s in ["a.example.com", "a.example.com", "b.example.com", "c.example.com", "d.example.com"] {
            p.zone_note_site("cloudflare", x, false, s);
        }
        assert!(p.is_restricted("cloudflare", x));
        assert_eq!(
            p.zone_site_names("cloudflare", x),
            n(&["a.example.com", "b.example.com", "c.example.com"]),
            "同一個網站只記一次，最多 3 個"
        );
        // 7 天沒有新的「不服務」：名稱跟著清掉
        assert_eq!(p.decay_zone(now_ms() + 8 * 86_400_000), 1);
        assert!(p.zone_site_names("cloudflare", x).is_empty());
    });
}

/// 3.5.1 L1／L2：載入時清掉舊資料裡不成立的學習資料（會讓 `has_learning()` 誤判）
#[test]
fn stale_learning_cleaned_on_load() {
    use crate::db::{Policy, Strategy};
    let (c, _) = setup(json!({}));
    let now = now_ms();
    let ok = || {
        Some(Box::new(crate::db::Verdict {
            verdict: Some(intern("ok")),
            until: Some(now + 3_600_000),
            ..Default::default()
        }))
    };
    let base = |s: &str| {
        Some(Box::new(crate::db::Base {
            ip: Some(ip(s)),
            ..Default::default()
        }))
    };
    c.with_state(|st| {
        // App 層（只辨識不改寫）的格子：v4／v6／基準都清掉
        st.db.touch("app.example.com", "google", "cname", &[], &[], None);
        let e = st.db.get_mut("app.example.com").unwrap();
        e.v4 = ok();
        e.base = base("192.0.2.40");
        // 手動「一定換」的 App 層不動
        st.db.touch("app-always.example.com", "google", "cname", &[], &[], None);
        st.db.set_policy("app-always.example.com", Policy::Always);
        st.db.get_mut("app-always.example.com").unwrap().v4 = ok();
        // 基準 IP 是 IPv6、不在這家的範圍：清掉；在範圍裡的留著
        for (n, b) in [
            ("b6.example.com", "2606:4700::5"),
            ("bout.example.com", "198.51.100.1"),
            ("bok.example.com", "104.21.0.5"),
        ] {
            st.db.touch(n, "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
            st.db.get_mut(n).unwrap().base = base(b);
        }
        // 過期很久的 ECS、跨 CDN；best 指向不成立的策略
        st.db.touch("stale.example.com", "akamai", "cname", &[], &[], None);
        let e = st.db.get_mut("stale.example.com").unwrap();
        e.ecs = Some(Box::new(crate::db::Ecs {
            verdict: Some(intern("ok")),
            until: Some(now - 8 * 86_400_000),
            ..Default::default()
        }));
        e.cross4 = Some(Box::new(crate::db::Cross {
            verdict: Some(intern("none")),
            until: Some(now - 6 * 86_400_000),
            ..Default::default()
        }));
        e.best = Some(Strategy::Ecs);
        st.db.touch("alias.example.com", "cloudflare", "ip", &[], &[], None);
        st.db.get_mut("alias.example.com").unwrap().best = Some(Strategy::Alias);
        st.db.take_marks(false);
    });
    assert_eq!(c.clean_stale_learning(), [1, 2, 1, 0, 2]);
    let st = c.state();
    let g = |n: &str| st.db.get(n).unwrap();
    assert!(g("app.example.com").v4.is_none() && g("app.example.com").base.is_none());
    assert!(g("app-always.example.com").v4.is_some());
    assert!(g("b6.example.com").base.is_none() && g("bout.example.com").base.is_none());
    assert!(g("bok.example.com").base.is_some());
    let s = g("stale.example.com");
    assert!(s.ecs.is_none() && s.best.is_none(), "到期超過 7 天的 ECS 清掉，best 跟著清");
    assert!(s.cross4.is_some(), "到期 6 天的留著");
    assert!(g("alias.example.com").best.is_none());
    assert!(!crate::db::has_learning(g("app.example.com")));
    assert!(st.db.changed(), "清掉的要寫回去");
    drop(st);
    assert_eq!(c.clean_stale_learning(), [0; 5], "第二次沒有東西可以清");
}

#[tokio::test]
async fn verifier_ok_collects_all_passing_ips() {
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        st.db.touch("v.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|i, _| match i.to_string().as_str() {
        "104.21.0.5" => cf_ok("NRT"),
        "104.16.161.36" => cf_ok("TPE"),
        "104.18.20.216" => cf_ok("TPE"),
        _ => fail("ECONNREFUSED"),
    });
    let r = c.verify("v.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await;
    assert_eq!(r, Some("ok"));
    let st = c.state();
    let e = st.db.get("v.test").unwrap();
    let v = e.v4.as_ref().unwrap();
    assert_eq!(v.ip, Some(ip("104.16.161.36")));
    assert_eq!(v.ips, Some(ips(&["104.16.161.36", "104.18.20.216"])));
    assert_eq!(v.pop.as_deref(), Some("TPE"));
    assert_eq!((v.algo, v.fails, v.tried), (Some(2), Some(0), Some(1)));
    let b = e.base.as_ref().unwrap();
    assert_eq!((b.pop.as_deref(), b.ok), (Some("NRT"), Some(true)), "基準記下原本的 POP");
    assert!(st.pools.zone_hit("cloudflare", ip("104.18.20.216")));
}

/// 節點池加到 3 個節點（3.5.1 M4：候選 3 個以上都回「不服務這個網站」才算網站的問題）
fn third_node(c: &Cdn) {
    c.with_state(|st| {
        let mut n = PoolNode::new(ip("104.16.162.7"));
        n.ms = Num::V(5.0);
        st.pools.p.get_mut("cloudflare").unwrap().pool4.push(n);
    });
}

#[tokio::test]
async fn verifier_error_1034_then_fail_and_backoff() {
    let (c, net) = setup(json!({ "verifyFailHours": 6 }));
    third_node(&c);
    c.with_state(|st| {
        st.db.touch("b.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    // 原站正常；台灣節點都回 Error 1034 → 「這個 IP 不服務這個網站」，全部試完判定失敗
    net.on_https(|i, _| match i.to_string().as_str() {
        "104.21.0.5" => cf_ok("NRT"),
        _ => resp(403, &[("cf-ray", "x-TPE")], "error code: 1034"),
    });
    assert_eq!(c.verify("b.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("fail"));
    let v = c.state().db.get("b.test").unwrap().v4.clone().unwrap();
    assert!(
        v.reason.as_deref().unwrap().contains("Cloudflare 錯誤 1034（試了 3 個網段）"),
        "{:?}",
        v.reason
    );
    let first_until = v.until.unwrap();
    assert!(first_until > now_ms() + 5 * 3_600_000 && first_until <= now_ms() + 6 * 3_600_000 + 1000);
    assert_eq!(v.fails, Some(1));
    // 第二次失敗：間隔加倍
    assert_eq!(c.verify("b.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("fail"));
    let v = c.state().db.get("b.test").unwrap().v4.clone().unwrap();
    assert_eq!(v.fails, Some(2));
    assert!(v.until.unwrap() > now_ms() + 11 * 3_600_000);
    // 同一個網站失敗兩次只算一個網站（3.5.1 L3）；第二個網站也這樣 → 特定產品專用 IP
    assert!(!c.state().pools.is_restricted("cloudflare", ip("104.16.161.36")));
    c.with_state(|st| {
        st.db.touch("b2.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    assert_eq!(c.verify("b2.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("fail"));
    assert!(c.state().pools.is_restricted("cloudflare", ip("104.16.161.36")));
    // 3 個候選都這樣：網站的問題，節點不暫停
    assert!(c.state().pools.usable("cloudflare", ip("104.16.161.36")));
}

/// 3.5.1 M4：候選不到 3 個、都回「不服務這個網站」（421、錯誤 1xxx）：分不出是網站還是節點的問題 →
/// 不記在網站上（暫時無法判定、短時間後重試、連續幾次就拉長）；同一個節點 1 小時內對 2 個不同的網站都這樣才暫停節點
#[tokio::test]
async fn single_node_misdirected_is_not_recorded_on_site() {
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        for n in ["a.example.com", "b.example.com"] {
            st.db.touch(n, "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
        }
    });
    net.on_https(|i, _| match i.to_string().as_str() {
        "104.21.0.5" => cf_ok("NRT"),
        _ => resp(403, &[("cf-ray", "x-TPE")], "error code: 1034"),
    });
    assert_eq!(
        c.verify("a.example.com", "cloudflare", 4, Some(ip("104.21.0.5"))).await,
        Some("unknown")
    );
    let v = c.state().db.get("a.example.com").unwrap().v4.clone().unwrap();
    assert_eq!(v.fails, None, "不算網站的失敗");
    assert!(v.reason.as_deref().unwrap().contains("先不記在網站上"), "{:?}", v.reason);
    let u1 = v.until.unwrap() - v.at.unwrap();
    assert!((9 * 60_000..=10 * 60_000 + 1000).contains(&u1), "{u1}");
    assert!(c.state().pools.usable("cloudflare", ip("104.16.161.36")), "一個網站：節點不暫停");
    // 同一個網站又一次：重試間隔加倍（不會每 10 分鐘一直重驗）
    c.verify("a.example.com", "cloudflare", 4, Some(ip("104.21.0.5"))).await;
    let v = c.state().db.get("a.example.com").unwrap().v4.clone().unwrap();
    assert!(v.until.unwrap() - v.at.unwrap() >= 19 * 60_000);
    assert!(c.state().pools.usable("cloudflare", ip("104.16.161.36")), "同一個網站不算兩個");
    // 第二個網站也一樣 → 節點暫停（同 K2）
    assert_eq!(
        c.verify("b.example.com", "cloudflare", 4, Some(ip("104.21.0.5"))).await,
        Some("unknown")
    );
    assert!(!c.state().pools.usable("cloudflare", ip("104.16.161.36")), "兩個網站：暫停節點");
    // 換了好的節點、驗證通過：連續的次數歸零
    net.on_https(|i, _| match i.to_string().as_str() {
        "104.21.0.5" => cf_ok("NRT"),
        _ => cf_ok("TPE"),
    });
    c.with_state(|st| st.pools.p.get_mut("cloudflare").unwrap().bad.clear());
    assert_eq!(c.verify("a.example.com", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("ok"));
    let v = c.state().db.get("a.example.com").unwrap().v4.clone().unwrap();
    assert!(v.extra.get(crate::verifier::UNSURE).is_none());
}

/// 3.5.1（Azure「台北換台北」）：驗證時原本的答案已經落在台灣機房 → 當成已是台灣、不換，也不再試候選節點。
/// 不算驗證失敗、不加失敗次數、不標壞節點；「一定換」與 `cdn.slowerFallback: false` 照舊換
#[tokio::test]
async fn verifier_original_already_in_taiwan_is_not_replaced() {
    let name = "www.example.com";
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        st.db.touch(name, "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|_, _| cf_ok("TPE"));
    assert_eq!(c.verify(name, "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("fail"));
    assert_eq!(net.calls("https ").len(), 1, "只連了原本的 IP：{:?}", net.calls("https "));
    {
        let st = c.state();
        let v = st.db.get(name).unwrap().v4.clone().unwrap();
        assert!(v.is("fail"));
        assert_eq!(v.fails, Some(0), "不加失敗次數");
        assert_eq!(crate::verifier::orig_tw_pop(&v), Some("TPE"));
        assert!(v.reason.as_deref().unwrap().contains("台灣機房"), "{:?}", v.reason);
        let until = v.until.unwrap();
        assert!(
            until > now_ms() + 5 * 3_600_000 && until <= now_ms() + 6 * 3_600_000 + 1000,
            "6 小時後再看"
        );
        assert!(st.pools.p["cloudflare"].bad.is_empty(), "不標壞節點");
        assert!(st.pools.zone.is_empty(), "不記相容性");
    }
    let s = c.stats();
    assert_eq!((s.orig_tw, s.verify_fail, s.verify_ok), (1, 0, 0));
    // 查詢路徑：照原本的答案（走既有的「驗證失敗 → 原始」），不縮短 TTL、不重新驗證
    let mut m = msg(name, 1, &["104.21.0.5"], vec![]);
    let r = c.apply(&mut m, name, 1);
    assert_eq!(answer_ips(&m, 1), ["104.21.0.5"]);
    assert!(r.rewritten.is_none() && r.ttl_cap.is_none(), "{r:?}");
    assert!(c.take_tasks().is_empty());
    let v = c.explain(name, crate::explain::Context::default());
    assert_eq!(v["decision"], "already-tw", "{v}");
    assert!(v["text"].as_str().unwrap().contains("TPE"), "{v}");

    // 到期之後原本的答案改到國外：照常換台灣節點，`origTw` 清掉
    c.with_state(|st| st.db.set_verdict(name, 4, |v| v.until = Some(1)));
    net.on_https(|i, _| cf_ok(if i == ip("104.21.0.5") { "HKG" } else { "TPE" }));
    assert_eq!(c.verify(name, "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("ok"));
    let v = c.state().db.get(name).unwrap().v4.clone().unwrap();
    assert!(v.is("ok") && crate::verifier::orig_tw_pop(&v).is_none(), "{v:?}");

    // 手動「一定換」：照使用者的
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        st.db.touch(name, "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
        st.db.set_policy(name, crate::db::Policy::Always);
    });
    net.on_https(|_, _| cf_ok("TPE"));
    assert_eq!(c.verify(name, "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("ok"));
    // `cdn.slowerFallback: false`：驗證通過就換，跟 3.5.0 一樣
    let (c, net) = setup(json!({ "slowerFallback": false }));
    c.with_state(|st| {
        st.db.touch(name, "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|_, _| cf_ok("TPE"));
    assert_eq!(c.verify(name, "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("ok"));
    // 原本的回應不正常（5xx）：不當成已是台灣
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        st.db.touch(name, "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|i, _| {
        if i == ip("104.21.0.5") {
            resp(502, &[("cf-ray", "x-TPE"), ("server", "cloudflare")], "")
        } else {
            cf_ok("TPE")
        }
    });
    assert_eq!(c.verify(name, "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("ok"));
}

#[tokio::test]
async fn verifier_network_failure_is_unknown_and_marks_bad() {
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        st.db.touch("u.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|i, _| if i == ip("104.21.0.5") { cf_ok("NRT") } else { fail("ECONNRESET") });
    assert_eq!(c.verify("u.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("unknown"));
    let st = c.state();
    let v = st.db.get("u.test").unwrap().v4.clone().unwrap();
    assert!(v.is("unknown"));
    assert_eq!(v.reason.as_deref(), Some("連線失敗 ECONNRESET"));
    // 3.5.1 K2：只有一個網站連不上還不暫停（可能是那個網站的問題）；1 小時內第 2 個網站也連不上才暫停
    assert!(st.pools.p["cloudflare"].bad.is_empty(), "一個網站還不暫停");
    drop(st);
    c.with_state(|st| {
        st.db.touch("u2.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    assert_eq!(c.verify("u2.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("unknown"));
    let st = c.state();
    assert!(
        st.pools.p["cloudflare"].bad.contains_key(&ip("104.16.161.36")),
        "原站可以連、台灣節點對兩個網站都連不上 → 暫停"
    );
}

#[tokio::test]
async fn verifier_pop_drift_and_same_error() {
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        st.db.touch("d.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    // 第一個節點漂移到香港、第二個跟原站一樣是 522（網站本身的問題）
    net.on_https(|i, _| match i.to_string().as_str() {
        "104.16.161.36" => cf_ok("HKG"),
        _ => resp(522, &[("cf-ray", "x-TPE")], ""),
    });
    assert_eq!(c.verify("d.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("ok"));
    let st = c.state();
    assert!(st.pools.p["cloudflare"].bad[&ip("104.16.161.36")].reason.contains("HKG"));
    let v = st.db.get("d.test").unwrap().v4.clone().unwrap();
    assert_eq!(v.reason.as_deref(), Some("原站同樣錯誤"));
    assert_eq!(v.ip, Some(ip("104.18.20.216")));
}

#[tokio::test]
async fn verifier_http_only_site() {
    // 只開 HTTP 的網站（OCSP、軟體更新鏡像）：原站 HTTPS 失敗就改用 HTTP 驗證
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        st.db.touch("ocsp.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|_, _| fail("ECONNREFUSED"));
    // 原本的答案落在國外（落在台灣機房的話 3.5.1 起不換）
    net.on_http(|i, _| resp(200, &[("cf-ray", if i == ip("104.21.0.5") { "x-HKG" } else { "x-TPE" })], "ok"));
    assert_eq!(c.verify("ocsp.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("ok"));
    assert_eq!(c.state().db.get("ocsp.test").unwrap().v4.as_ref().unwrap().http, Some(true));
}

struct TestHints {
    results: Mutex<Vec<(String, bool)>>,
}

impl Hints for TestHints {
    fn domain_hint(&self, _n: &str, _p: &str, _f: u8) -> Vec<HintIp> {
        vec![HintIp {
            ip: ip("104.16.99.1"),
            from: "friend".into(),
        }]
    }
    fn hint_result(&self, from: &str, _kind: crate::cdn::HintKind, ok: bool) {
        self.results.lock().unwrap().push((from.into(), ok));
    }
    fn cross_hint(&self, _n: &str) -> Option<CrossHint> {
        None
    }
}

#[tokio::test]
async fn verifier_tries_community_hints_first() {
    let (c, net) = setup(json!({}));
    let h = Arc::new(TestHints {
        results: Mutex::new(vec![]),
    });
    c.set_hints(Some(h.clone()));
    c.with_state(|st| {
        st.db.touch("h.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
        // 好友給的 IP 不在我的節點池：驗證成功也不會拿來回給用戶端，但命中率照算
    });
    net.on_https(|i, _| cf_ok(if i == ip("104.21.0.5") { "NRT" } else { "TPE" }));
    c.verify("h.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await;
    assert!(net.calls("https 104.16.99.1").len() == 1);
    let https: Vec<String> = net.calls("https ");
    assert_eq!(https[1], "https 104.16.99.1 h.test", "原站之後先試好友的");
    assert_eq!(h.results.lock().unwrap().as_slice(), [("friend".to_string(), true)]);
}

/// 好友提示：可以指定多個 IP
struct ListHints {
    list: Vec<(&'static str, &'static str)>,
    results: Mutex<Vec<(String, bool)>>,
}

impl Hints for ListHints {
    fn domain_hint(&self, _n: &str, _p: &str, _f: u8) -> Vec<HintIp> {
        self.list
            .iter()
            .map(|(i, f)| HintIp {
                ip: ip(i),
                from: f.to_string(),
            })
            .collect()
    }
    fn hint_result(&self, from: &str, _kind: crate::cdn::HintKind, ok: bool) {
        self.results.lock().unwrap().push((from.into(), ok));
    }
    fn cross_hint(&self, _n: &str) -> Option<CrossHint> {
        None
    }
}

#[tokio::test]
async fn verifier_hint_outside_provider_range_is_never_probed() {
    // 好友給的 IP 不在這家 CDN 的官方範圍（可能是任何人的機器）：連試都不試、算沒命中
    let (c, net) = setup(json!({}));
    let h = Arc::new(ListHints {
        list: vec![("203.0.113.9", "bad"), ("2606:4700::1", "v6"), ("104.16.99.1", "good")],
        results: Mutex::new(vec![]),
    });
    c.set_hints(Some(h.clone()));
    c.with_state(|st| {
        st.db.touch("hr.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|i, _| cf_ok(if i == ip("104.21.0.5") { "NRT" } else { "TPE" }));
    assert_eq!(c.verify("hr.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("ok"));
    assert!(net.calls("https 203.0.113.9").is_empty(), "範圍外的不試");
    assert!(net.calls("https 2606:4700::1").is_empty(), "家族不符的不試");
    let mut r = h.results.lock().unwrap().clone();
    r.sort();
    assert_eq!(
        r,
        [("bad".to_string(), false), ("good".to_string(), true), ("v6".to_string(), false)]
    );
    // 判定裡只有自己節點池的 IP：好友的 IP 驗證通過也不回給用戶端
    let st = c.state();
    let v = st.db.get("hr.test").unwrap().v4.clone().unwrap();
    assert_eq!(v.ip, Some(ip("104.16.161.36")));
    assert_eq!(v.ips, Some(ips(&["104.16.161.36", "104.18.20.216"])));
}

#[tokio::test]
async fn verifier_hint_only_pass_is_not_ok() {
    // 只有好友的 IP 通過、自己節點池的都連不上：不能寫成「通過」（查詢時沒有 IP 可以回）
    let (c, net) = setup(json!({}));
    let h = Arc::new(ListHints {
        list: vec![("104.16.99.1", "friend")],
        results: Mutex::new(vec![]),
    });
    c.set_hints(Some(h.clone()));
    c.with_state(|st| {
        st.db.touch("ho.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|i, _| match i.to_string().as_str() {
        "104.21.0.5" => cf_ok("NRT"),
        "104.16.99.1" => cf_ok("TPE"),
        _ => fail("ECONNRESET"),
    });
    assert_eq!(c.verify("ho.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("unknown"));
    assert_eq!(h.results.lock().unwrap().as_slice(), [("friend".to_string(), true)]);
    assert!(c.state().db.get("ho.test").unwrap().v4.as_ref().unwrap().is("unknown"));
}

/// 3.5.1（L6）：好友給的節點連不上，原因在本機（記憶體不能長大、本機的通訊端錯誤）時不算好友的；
/// 平常照算，憑證不符一律照算
#[tokio::test]
async fn verifier_hint_conn_fail_not_counted_when_local_is_strained() {
    for (case, strained, err, counted) in [
        ("平常連不上", false, "TIMEOUT", true),
        ("記憶體不能長大", true, "TIMEOUT", false),
        ("本機通訊端用完", false, "EADDRNOTAVAIL", false),
        ("憑證不符", true, "ERR_TLS_CERT_ALTNAME_INVALID", true),
    ] {
        let (c, net) = setup(json!({}));
        let h = Arc::new(ListHints {
            list: vec![("104.16.99.1", "friend")],
            results: Mutex::new(vec![]),
        });
        c.set_hints(Some(h.clone()));
        c.set_admit_new(!strained);
        c.with_state(|st| {
            st.db.touch("hs.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
        });
        let tls = err.starts_with("ERR_");
        net.on_https(move |i, _| match i.to_string().as_str() {
            "104.21.0.5" => cf_ok("NRT"),
            "104.16.99.1" if tls => ProbeResult::failed(err, true),
            "104.16.99.1" => fail(err),
            _ => cf_ok("TPE"),
        });
        c.verify("hs.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await;
        assert_eq!(net.calls("https 104.16.99.1").len(), 1, "{case}");
        let r = h.results.lock().unwrap().clone();
        if counted {
            assert_eq!(r, [("friend".to_string(), false)], "{case}");
        } else {
            assert!(r.is_empty(), "{case}：{r:?}");
        }
    }
}

#[tokio::test]
async fn verifier_http_only_requires_consistent_https() {
    // 原始節點的 HTTPS 只是一時連不上（ECONNRESET）、HTTP 可以用 → 改用 HTTP 驗證。
    // 候選節點 HTTP 也可以用，但 HTTPS 是「憑證不符」：跟原始節點不一樣，不能算通過
    // （否則用 HTTPS 的用戶端會被導到憑證沒驗證過的節點）
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        st.db.touch("mix.test", "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|i, _| {
        if i == ip("104.21.0.5") {
            fail("ECONNRESET")
        } else {
            ProbeResult::failed("ERR_TLS_CERT_ALTNAME_INVALID", true)
        }
    });
    net.on_http(|i, _| resp(200, &[("cf-ray", if i == ip("104.21.0.5") { "x-HKG" } else { "x-TPE" })], "ok"));
    assert_eq!(c.verify("mix.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("unknown"));
    let v = c.state().db.get("mix.test").unwrap().v4.clone().unwrap();
    assert!(!v.is("ok"));
    assert!(v.reason.as_deref().unwrap().contains("HTTPS"), "{:?}", v.reason);

    // 候選節點的 HTTPS 有效（憑證驗證過）：比原始節點還好，通過
    net.on_https(|i, _| if i == ip("104.21.0.5") { fail("ECONNRESET") } else { cf_ok("TPE") });
    assert_eq!(c.verify("mix.test", "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("ok"));
}

#[tokio::test]
async fn ecs_probe_finds_closer_node() {
    let (c, net) = setup(json!({ "ecs": { "twSubnets": ["168.95.0.0/24", "1.160.0.0/24"], "resolvers": ["udp://8.8.8.8"] } }));
    c.with_state(|st| {
        st.db
            .touch("www.ak.test", "akamai", "cname", &ips(&["23.1.1.1"]), &ips(&["2600::1"]), None);
    });
    net.on_dns(|_, name, qtype, ecs| {
        let sub = ecs.map(|e| e.0.to_string()).unwrap_or_default();
        let mut m = msg(name, qtype, &[], vec![]);
        if qtype == rtype::A {
            let a = if sub == "1.160.0.0" { "23.9.9.9" } else { "23.5.5.5" };
            m.answers.push(Record::a(name, 60, a.parse().unwrap()));
        } else {
            m.answers.push(Record::aaaa(name, 60, "2600:9::1".parse().unwrap()));
        }
        Some(m)
    });
    net.set_cached("23.1.1.1", 60.0);
    net.set_cached("23.5.5.5", 50.0);
    net.set_cached("23.9.9.9", 4.0);
    net.set_cached("2600:9::1", 5.0);
    net.on_https(|_, _| resp(200, &[], "ok"));
    c.ecs_probe("www.ak.test", &ips(&["23.1.1.1"]), &ips(&["2600::1"])).await;
    let e = c.state().db.get("www.ak.test").unwrap().ecs.clone().unwrap();
    assert!(e.is("ok"));
    assert_eq!(e.subnet.as_deref(), Some("1.160.0.0/24"));
    assert_eq!(e.ips4, Some(ips(&["23.9.9.9"])));
    assert_eq!(e.ips6, Some(ips(&["2600:9::1"])));
    assert_eq!((e.gain_ms, e.orig_ms, e.ecs_ms), (Num::V(56.0), Num::V(60.0), Num::V(4.0)));
    // 成功過的網段排前面（規格 06 第 3.1 節）；外層指定的優先網段永遠最前面
    assert_eq!(c.ecs_subnets(), ["1.160.0.0/24", "168.95.0.0/24"]);
    c.ecs_set_preferred(vec!["203.0.113.0/24".into(), "壞掉".into()]);
    c.ecs_add_subnet("198.51.100.0/24");
    assert_eq!(
        c.ecs_subnets(),
        ["203.0.113.0/24", "1.160.0.0/24", "198.51.100.0/24", "168.95.0.0/24"]
    );
    // 查詢時改寫
    let mut m = msg(
        "e1.akamaiedge.net",
        1,
        &["23.1.1.1"],
        vec![cname("www.ak.test", "e1.akamaiedge.net", 60)],
    );
    let r = c.apply(&mut m, "www.ak.test", 1);
    assert_eq!(answer_ips(&m, 1), ["23.9.9.9"]);
    assert_eq!(r.gain_ms, Some(56.0));
    let route = c.route(None, &r, &m).unwrap();
    assert!(route.abroad && route.tw && route.saved_ms == Some(56.0));
}

#[tokio::test]
async fn ecs_probe_no_gain_and_no_answer() {
    let (c, net) = setup(json!({ "ecs": { "twSubnets": ["168.95.0.0/24"] } }));
    c.with_state(|st| {
        st.db.touch("n.test", "akamai", "cname", &[], &[], None);
    });
    c.ecs_probe("n.test", &ips(&["23.1.1.1"]), &[]).await;
    assert_eq!(
        c.state().db.get("n.test").unwrap().ecs.as_ref().unwrap().reason.as_deref(),
        Some("ECS 查無結果")
    );
    net.on_dns(|_, name, _, _| {
        let mut m = msg(name, 1, &[], vec![]);
        m.answers.push(Record::a(name, 60, "23.5.5.5".parse().unwrap()));
        Some(m)
    });
    net.set_cached("23.1.1.1", 10.0);
    net.set_cached("23.5.5.5", 9.0);
    c.ecs_probe("n.test", &ips(&["23.1.1.1"]), &[]).await;
    let e = c.state().db.get("n.test").unwrap().ecs.clone().unwrap();
    assert_eq!(e.reason.as_deref(), Some("無明顯改善 (原 10ms / ECS 9ms)"));
}

#[tokio::test]
async fn health_check_marks_and_sorts() {
    let (c, net) = setup(json!({ "minPool": 3 }));
    let low = Arc::new(Mutex::new(Vec::<String>::new()));
    let l2 = low.clone();
    c.set_on_low_pool(move |p| l2.lock().unwrap().push(p.to_string()));
    c.with_state(|st| {
        let mut a = PoolNode::new(ip("104.16.161.36"));
        a.ms = Num::V(9.0);
        let mut b = PoolNode::new(ip("104.18.20.216"));
        b.ms = Num::V(3.0);
        st.pools.p.get_mut("cloudflare").unwrap().pool4 = vec![a, b];
        st.pools.p.get_mut("fastly").unwrap().pool4 = vec![];
    });
    net.on_http(|i, _| if i == ip("104.16.161.36") { cf_ok("TPE") } else { cf_ok("HKG") });
    net.on_ping(|_| lat(2.5));
    assert!(c.health_check().await);
    let st = c.state();
    let d = &st.pools.p["cloudflare"];
    assert_eq!(d.pool4[0].ip, ip("104.16.161.36"), "可用的排前面");
    assert_eq!(d.pool4[0].ms, Num::V(2.5));
    assert_eq!(d.bad[&ip("104.18.20.216")].reason, "POP=HKG");
    drop(st);
    assert_eq!(low.lock().unwrap().as_slice(), ["cloudflare"], "可用節點不足：通知重建節點池");
}

/// 3.5.1 K2：同一個節點反覆被驗證標壞，暫停時間逐次加倍（30 → 60 → 120 分鐘…最多 8 小時），
/// 暫停期間健檢通過也不恢復；24 小時沒再發生就從頭算；紀錄有上限
#[tokio::test]
async fn repeated_mark_bad_doubles_hold_and_health_respects_it() {
    let (c, net) = setup(json!({}));
    let (a, b) = (ip("192.0.2.1"), ip("192.0.2.2"));
    c.with_state(|st| {
        let mut x = PoolNode::new(a);
        x.ms = Num::V(3.0);
        let mut y = PoolNode::new(b);
        y.ms = Num::V(4.0);
        st.pools.p.get_mut("cloudflare").unwrap().pool4 = vec![x, y];
    });
    net.on_http(|_, _| cf_ok("TPE"));
    net.on_ping(|_| lat(2.5));
    let age = |c: &Cdn, min: u64| {
        c.with_state(|st| {
            let d = st.pools.p.get_mut("cloudflare").unwrap();
            d.strikes.get_mut(&a).unwrap().at = now_ms() - min * 60_000;
        })
    };
    let bad = |c: &Cdn| c.state().pools.p["cloudflare"].bad.contains_key(&a);
    // 第 1 次：30 分鐘
    c.with_state(|st| st.pools.mark_bad("cloudflare", a, "驗證 www.example.com 時 TIMEOUT"));
    assert_eq!(c.state().pools.p["cloudflare"].strikes[&a].hold_ms(), 30 * 60_000);
    age(&c, 10);
    c.health_check().await;
    assert!(bad(&c), "暫停中：健檢通過也不恢復");
    age(&c, 31);
    c.health_check().await;
    assert!(!bad(&c), "過了 30 分鐘：健檢通過就恢復");
    // 第 2 次（24 小時內）：60 分鐘
    c.with_state(|st| st.pools.mark_bad("cloudflare", a, "驗證 www.example.com 時 TIMEOUT"));
    assert_eq!(c.state().pools.p["cloudflare"].strikes[&a].n, 2);
    age(&c, 31);
    c.health_check().await;
    assert!(bad(&c), "第 2 次要 60 分鐘");
    age(&c, 61);
    c.health_check().await;
    assert!(!bad(&c));
    // 第 3 次：120 分鐘；別的節點不受影響
    c.with_state(|st| st.pools.mark_bad("cloudflare", a, "x"));
    assert_eq!(c.state().pools.p["cloudflare"].strikes[&a].hold_ms(), 120 * 60_000);
    assert!(!c.state().pools.p["cloudflare"].bad.contains_key(&b));
    // 上限 8 小時
    let s = crate::pools::Strike { n: 30, at: 0 };
    assert_eq!(s.hold_ms(), crate::pools::STRIKE_MAX_MS);
    // 24 小時沒再發生：從 1 算
    age(&c, 25 * 60);
    c.with_state(|st| st.pools.mark_bad("cloudflare", a, "x"));
    assert_eq!(c.state().pools.p["cloudflare"].strikes[&a].n, 1);
    // 紀錄有上限
    c.with_state(|st| {
        let d = st.pools.p.get_mut("cloudflare").unwrap();
        for i in 0..400u32 {
            d.strike(IpAddr::from(std::net::Ipv4Addr::from(0xC633_6400 + i)), now_ms());
        }
        assert!(d.strikes.len() <= crate::pools::STRIKE_CAP);
    });
}

/// 3.5.1 K2：驗證時連不上，同一個節點 1 小時內第 2 個不同的網站也連不上才暫停；
/// 保留最後一段的 CDN（Fastly）以 /24 算，到門檻時暫停網段裡節點池的節點
#[tokio::test]
async fn conn_fail_needs_two_sites_before_pausing() {
    let (c, _net) = setup(json!({}));
    let pf = |s: &str| crate::util::parse_prefix24(s).unwrap();
    let (cf, node) = (ip("192.0.2.1"), ip("198.51.100.2"));
    c.with_state(|st| {
        st.pools.p.get_mut("cloudflare").unwrap().pool4 = vec![PoolNode::new(cf)];
        let d = st.pools.p.get_mut("fastly").unwrap();
        let mut n = PoolNode::new(node);
        n.pop = Some(intern("HKG"));
        n.ms = Num::V(26.0);
        n.score = Num::V(28.0);
        d.pool4 = vec![n];
        d.prefixes = [("HKG".to_string(), vec![pf("198.51.100")])].into_iter().collect();
    });
    c.with_state(|st| {
        let p = &mut st.pools;
        assert!(!p.note_conn_fail("cloudflare", cf, "a.example.com", "x"));
        assert!(!p.note_conn_fail("cloudflare", cf, "a.example.com", "x"), "同一個網站再一次不算");
        assert!(p.p["cloudflare"].bad.is_empty());
        assert!(p.note_conn_fail("cloudflare", cf, "b.example.com", "x"), "第 2 個網站：暫停");
        assert!(p.p["cloudflare"].bad[&cf].reason.contains("2 個網站"));
        // 3.5.1：暫停的原因寫出是哪幾個網站（日誌與 `/api/cdn/pools` 的 `bad`）
        assert!(
            p.p["cloudflare"].bad[&cf].reason.contains("a.example.com、b.example.com"),
            "{}",
            p.p["cloudflare"].bad[&cf].reason
        );
        // Fastly：同一個 /24、不同最後一段（不同網站的憑證組）
        assert!(!p.note_conn_fail("fastly", ip("198.51.100.140"), "a.example.com", "x"));
        assert!(p.p["fastly"].bad.is_empty() && p.p["fastly"].bad24.is_empty());
        assert!(p.note_conn_fail("fastly", ip("198.51.100.77"), "b.example.com", "x"));
        assert!(p.p["fastly"].bad.contains_key(&node), "暫停網段裡節點池的節點");
        // 超過 1 小時的紀錄不算
        assert!(!p.note_conn_fail("fastly", ip("203.0.113.1"), "a.example.com", "x"));
        p.p.get_mut("fastly")
            .unwrap()
            .conn_fails
            .values_mut()
            .for_each(|x| x.at = now_ms() - 61 * 60_000);
        assert!(!p.note_conn_fail("fastly", ip("203.0.113.1"), "b.example.com", "x"));
        assert!(p.p["fastly"].bad24.is_empty());
    });
}

/// 3.5.1 K2：一個網站對 3 個以上不同的台灣節點都連不上（例如只接受業者專用 IP）：記在網站上（`fail`、逐次拉長），
/// 不暫停那些節點；節點對別的網站照常可以用
#[tokio::test]
async fn site_failing_on_many_nodes_is_recorded_on_site_not_nodes() {
    let name = "www.example.com";
    let (c, net) = setup(json!({}));
    let nodes = ips(&["192.0.2.1", "192.0.2.2", "198.51.100.1", "198.51.100.2"]);
    c.with_state(|st| {
        st.pools.p.get_mut("cloudflare").unwrap().pool4 = nodes.iter().map(|i| PoolNode::new(*i)).collect();
        st.db.touch(name, "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|i, _| if i == ip("104.21.0.5") { cf_ok("NRT") } else { fail("ECONNRESET") });
    assert_eq!(c.verify(name, "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("fail"));
    {
        let st = c.state();
        let d = &st.pools.p["cloudflare"];
        assert!(d.bad.is_empty() && d.conn_fails.is_empty(), "節點沒有被暫停、也沒有記");
        let v = st.db.get(name).unwrap().v4.clone().unwrap();
        assert!(v.is("fail"));
        assert_eq!(v.fails, Some(1));
        assert!(v.reason.as_deref().unwrap().contains("試了 4 個台灣節點都連不上"), "{:?}", v.reason);
        assert!(v.until.unwrap() > now_ms() + 5 * 3_600_000, "照一般失敗逐次拉長（6 小時起）");
    }
    // 第二次失敗：12 小時
    c.with_state(|st| st.db.set_verdict(name, 4, |v| v.until = Some(1)));
    assert_eq!(c.verify(name, "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("fail"));
    let v = c.state().db.get(name).unwrap().v4.clone().unwrap();
    assert_eq!(v.fails, Some(2));
    assert!(v.until.unwrap() > now_ms() + 11 * 3_600_000);
    // 只連不上 1～2 個（其他通過）：網站驗證通過；那個節點只記一筆，還沒暫停
    let (c, net) = setup(json!({}));
    c.with_state(|st| {
        st.pools.p.get_mut("cloudflare").unwrap().pool4 = nodes.iter().map(|i| PoolNode::new(*i)).collect();
        st.db.touch(name, "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    });
    net.on_https(|i, _| match i.to_string().as_str() {
        "104.21.0.5" => cf_ok("NRT"),
        "192.0.2.1" => fail("ECONNRESET"),
        _ => cf_ok("TPE"),
    });
    assert_eq!(c.verify(name, "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("ok"));
    let st = c.state();
    let d = &st.pools.p["cloudflare"];
    assert!(d.bad.is_empty());
    assert_eq!(d.conn_fails.len(), 1);
}

/// 3.5.1 K2：GitHub Pages（Fastly 的業者專用 IP）照原本的答案，不驗證；別的 Fastly IP 照舊
#[test]
fn github_pages_dedicated_ips_are_not_rewritten() {
    use crate::providers::dedicated_ip;
    for s in [
        "185.199.108.153",
        "185.199.109.153",
        "185.199.110.153",
        "185.199.111.153",
        "2606:50c0:8000::153",
        "2606:50c0:8003::153",
    ] {
        assert!(dedicated_ip("fastly", ip(s)), "{s}");
    }
    for s in [
        "185.199.108.133",
        "185.199.112.153",
        "2606:50c0:8004::153",
        "2606:50c0:8000::154",
        "151.101.1.140",
    ] {
        assert!(!dedicated_ip("fastly", ip(s)), "{s}");
    }
    assert!(!dedicated_ip("cloudflare", ip("185.199.108.153")));
    let (c, _net) = setup(json!({}));
    let name = "www.example.com";
    for _ in 0..3 {
        let mut m = msg(
            name,
            1,
            &["185.199.108.153", "185.199.109.153"],
            vec![cname(name, "example.github.io", 300)],
        );
        let r = c.apply(&mut m, name, 1);
        assert_eq!(r.provider, Some("fastly"));
        assert!(r.rewritten.is_none() && r.ttl_cap.is_none(), "{r:?}");
        assert!(r.tags.iter().any(|t| t.contains("業者專用 IP")), "{:?}", r.tags);
        assert_eq!(answer_ips(&m, 1), ["185.199.108.153", "185.199.109.153"]);
        assert!(c.take_tasks().is_empty(), "不驗證、不跨 CDN");
    }
    assert_eq!(c.stats().dedicated, 3);
    let v = c.explain(name, crate::explain::Context::default());
    assert_eq!(v["decision"], "dedicated-ip", "{v}");
}

#[tokio::test]
async fn small_healthy_pool_does_not_request_rebuild() {
    // 節點池本來就只有 2 個（少於 minPool 3）但都正常：重建也找不到更多，不要一直重排節點池工作
    let (c, net) = setup(json!({ "minPool": 3 }));
    let low = Arc::new(Mutex::new(Vec::<String>::new()));
    let l2 = low.clone();
    c.set_on_low_pool(move |p| l2.lock().unwrap().push(p.to_string()));
    c.with_state(|st| {
        st.pools.p.get_mut("cloudflare").unwrap().pool4 = vec![PoolNode::new(ip("104.16.161.36")), PoolNode::new(ip("104.18.20.216"))];
        st.pools.p.get_mut("fastly").unwrap().pool4 = vec![];
    });
    net.on_http(|_, _| cf_ok("TPE"));
    net.on_ping(|_| lat(2.5));
    c.health_check().await;
    c.health_check().await;
    assert!(low.lock().unwrap().is_empty(), "節點都正常：不通知重建");
}

#[tokio::test]
async fn try_v6_discovers_taiwan_node() {
    let (c, net) = setup(json!({}));
    net.on_http(|_, _| resp(200, &[], "fl=1\ncolo=TPE\n"));
    net.on_ping(|_| lat(3.21));
    c.try_v6("cloudflare", ip("2606:4700:3030::9")).await;
    {
        let st = c.state();
        assert_eq!(st.pools.p["cloudflare"].pool6[0].ip, ip("2606:4700:3030::9"));
        assert!(st.v6.contains("cloudflare", ip("2606:4700:3030::9")), "永久保存");
        assert_eq!(
            st.pools.classify(ip("2606:4700:3030::1")).unwrap().cls,
            crate::Cls::Tw,
            "同一個 /48 視為台灣"
        );
    }
    // 同一個 /48 六小時內只試一次
    let n = net.calls("http ").len();
    c.try_v6("cloudflare", ip("2606:4700:3030::10")).await;
    assert_eq!(net.calls("http ").len(), n);
}

#[test]
fn peak_hours_weighting() {
    // 規格 06 第 3.2 節：凌晨很快、晚上很塞的節點，分數要反映尖峰時段
    let now = now_ms();
    let mut x = PoolNode::new(ip("151.101.0.1"));
    x.ms = Num::V(20.0);
    x.jitter = Num::V(0.0);
    x.loss = Num::V(0.0);
    assert_eq!(weighted_qscore(&x, 2.0, now), 20.0, "沒有尖峰量測：跟一般分數一樣");
    x.peak_ms = Num::V(80.0);
    x.peak_jitter = Num::V(10.0);
    x.peak_loss = Num::V(0.0);
    x.peak_at = Some(now - 3_600_000);
    assert_eq!(weighted_qscore(&x, 2.0, now), (20.0 + 2.0 * 100.0) / 3.0);
    x.peak_at = Some(now - 4 * 86_400_000);
    assert_eq!(weighted_qscore(&x, 2.0, now), 20.0, "太舊的尖峰量測不算");
    let cfg = crate::CdnConfig::from_value(&json!({}));
    // 2026-11-10 12:30 UTC = 台北 20:30
    assert!(cfg.is_peak(1_794_313_800_000));
    assert!(!cfg.is_peak(1_794_313_800_000 - 4 * 3_600_000));
}

#[tokio::test]
async fn quality_check_records_peak_samples() {
    let (c, net) = setup(json!({ "peak": { "startHour": 0, "endHour": 24 } }));
    c.with_state(|st| {
        let mut a = PoolNode::new(ip("151.101.0.5"));
        a.pop = Some(intern("NRT"));
        a.ms = Num::V(40.0);
        st.pools.p.get_mut("fastly").unwrap().pool4 = vec![a];
    });
    net.on_quality(|_| Quality {
        ms: 45.0,
        jitter: 1.0,
        loss: 0.0,
        n: 6,
    });
    c.quality_check().await;
    let st = c.state();
    let x = &st.pools.p["fastly"].pool4[0];
    assert_eq!((x.peak_ms, x.peak_jitter, x.score), (Num::V(45.0), Num::V(1.0), Num::V(47.0)));
    assert!(x.peak_at.is_some());
}

#[test]
fn baseline_and_route() {
    let (c, net) = setup(json!({}));
    net.set_cached("104.21.0.5", 60.0);
    net.set_cached("104.16.161.36", 3.0);
    let abroad = msg("s.test", 1, &["104.21.0.5"], vec![]);
    let tw = msg("s.test", 1, &["104.16.161.99"], vec![]);
    let b = c.baseline(&[&abroad, &abroad, &tw]).unwrap();
    assert_eq!((b.provider, b.abroad, b.ms), ("cloudflare", true, Some(60.0)));
    assert!(c.baseline(&[&msg("s.test", 1, &["8.8.8.8"], vec![])]).is_none());
    // 改寫成台灣節點：省下 57ms
    let served = msg("s.test", 1, &["104.16.161.36"], vec![]);
    let res = crate::ApplyResult {
        rewritten: Some(crate::Rewrite::Alias),
        provider: Some("cloudflare"),
        ..Default::default()
    };
    let r = c.route(Some(&b), &res, &served).unwrap();
    assert!(r.abroad && r.tw);
    assert_eq!(r.saved_ms, Some(57.0));
}

#[test]
fn recheck_and_shrink() {
    let (c, _) = setup(json!({}));
    c.with_state(|st| {
        for i in 0..10 {
            let n = format!("r{i}.test");
            st.db.touch(&n, "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
            st.db.set_verdict(&n, 4, |v| {
                v.verdict = Some(intern("ok"));
                v.until = Some(now_ms() + if i < 4 { 600_000 } else { 86_400_000 });
            });
            st.db.get_mut(&n).unwrap().hits = 2;
        }
    });
    assert_eq!(c.recheck(), 4, "一小時內到期的先重新驗證");
    assert!(c
        .take_tasks()
        .iter()
        .all(|t| matches!(t, Task::Verify { family: 4, orig: Some(o), .. } if *o == ip("104.21.0.5"))));
    c.shrink(0.5);
    assert_eq!(c.state().db.domains.len(), 5);
}

#[test]
fn new_domains_held_when_growth_stops() {
    // 3.5.1 K4：記憶體控制說不能長大時，新網域照上游的答案回、不記進資料庫；已經記著的照常；恢復後照常收
    let (c, _net) = setup(json!({}));
    c.with_state(|st| st.pools.p.get_mut("cloudflare").unwrap().range4 = crate::pools::cidr(&["198.51.100.0/24"]));
    let mut m = msg("old.example.com", 1, &["198.51.100.7"], vec![]);
    assert_eq!(c.apply(&mut m, "old.example.com", rtype::A).provider, Some("cloudflare"));
    assert!(c.state().db.get("old.example.com").is_some());
    c.set_admit_new(false);
    let mut m = msg("new.example.com", 1, &["198.51.100.8"], vec![]);
    let r = c.apply(&mut m, "new.example.com", rtype::A);
    assert_eq!(r.provider, Some("cloudflare"), "照樣認得");
    assert!(r.tags.iter().any(|t| t.starts_with("新網域先不記")), "{:?}", r.tags);
    assert!(c.state().db.get("new.example.com").is_none(), "不記");
    assert_eq!(c.state().stats.new_held, 1);
    let hits = c.state().db.get("old.example.com").unwrap().hits;
    let mut m = msg("old.example.com", 1, &["198.51.100.7"], vec![]);
    c.apply(&mut m, "old.example.com", rtype::A);
    assert_eq!(c.state().db.get("old.example.com").unwrap().hits, hits + 1, "已經記著的照常");
    c.set_admit_new(true);
    let mut m = msg("new.example.com", 1, &["198.51.100.8"], vec![]);
    c.apply(&mut m, "new.example.com", rtype::A);
    assert!(c.state().db.get("new.example.com").is_some(), "恢復後照常收");
}

#[test]
fn new_domains_held_when_far_over_budget() {
    // 3.5.1 K4：總筆數到了磁碟預算換算筆數的 2 倍：先不收新網域（淘汰追上之後自己恢復）
    let (c, _net) = setup(json!({}));
    c.with_state(|st| st.pools.p.get_mut("cloudflare").unwrap().range4 = crate::pools::cidr(&["198.51.100.0/24"]));
    c.with_state(|st| {
        for i in 0..(2 * 100) {
            st.db.touch(&format!("d{i}.example.com"), "cloudflare", "ip", &[], &[], None);
        }
    });
    c.budget_cap.store(100, std::sync::atomic::Ordering::Relaxed);
    let mut m = msg("over.example.com", 1, &["198.51.100.9"], vec![]);
    c.apply(&mut m, "over.example.com", rtype::A);
    assert!(c.state().db.get("over.example.com").is_none(), "預算 100 筆、已經 200 筆");
    c.budget_cap.store(1000, std::sync::atomic::Ordering::Relaxed);
    let mut m = msg("over.example.com", 1, &["198.51.100.9"], vec![]);
    c.apply(&mut m, "over.example.com", rtype::A);
    assert!(c.state().db.get("over.example.com").is_some());
}

#[test]
fn new_domains_need_second_ask_near_max_entries() {
    // 3.5.1 H1：沒有磁碟預算（Windows、大磁碟）時 K4 不會擋；筆數到了 cdn.maxEntries 的 90%，新網域問第二次才記
    let (c, _net) = setup(json!({ "maxEntries": 100 }));
    c.with_state(|st| st.pools.p.get_mut("cloudflare").unwrap().range4 = crate::pools::cidr(&["198.51.100.0/24"]));
    c.with_state(|st| {
        for i in 0..90 {
            st.db.touch(&format!("d{i}.example.com"), "cloudflare", "ip", &[], &[], None);
        }
    });
    let mut m = msg("once.example.net", 1, &["198.51.100.9"], vec![]);
    let r = c.apply(&mut m, "once.example.net", rtype::A);
    assert!(r.tags.iter().any(|t| t.contains("問第二次才記")), "{:?}", r.tags);
    assert!(c.state().db.get("once.example.net").is_none());
    assert!(c.take_tasks().is_empty(), "不記也不排驗證");
    let mut m = msg("once.example.net", 1, &["198.51.100.9"], vec![]);
    c.apply(&mut m, "once.example.net", rtype::A);
    assert!(c.state().db.get("once.example.net").is_some(), "第二次就記");
    let hits = c.state().db.get("d1.example.com").unwrap().hits;
    let mut m = msg("d1.example.com", 1, &["198.51.100.9"], vec![]);
    c.apply(&mut m, "d1.example.com", rtype::A);
    assert_eq!(c.state().db.get("d1.example.com").unwrap().hits, hits + 1, "已經記著的照常");
}

#[test]
fn classifier_snapshot_follows_range_changes() {
    // `apply()` 用唯讀快照判斷是不是 CDN（不拿狀態鎖）；範圍 / 分類不管怎麼換，放開鎖之後快照都要跟上
    let (c, _net) = setup(json!({}));
    let x = ip("198.51.100.7");
    assert_eq!(c.classify(x), None);
    let mut m = msg("snap.test", 1, &["198.51.100.7"], vec![]);
    assert_eq!(c.apply(&mut m, "snap.test", rtype::A).provider, None);
    assert!(c.state().db.get("snap.test").is_none(), "不是 CDN 的回應不進資料庫");

    // 直接換掉欄位
    c.with_state(|st| st.pools.p.get_mut("cloudflare").unwrap().range4 = crate::pools::cidr(&["198.51.100.0/24"]));
    assert_eq!(
        c.classify(x).map(|k| (k.provider, k.cls)),
        Some(("cloudflare", crate::Cls::Unknown))
    );
    assert_eq!(c.classify(x), c.state().pools.classify(x), "快照跟節點池的判斷一致");
    let mut m = msg("snap.test", 1, &["198.51.100.7"], vec![]);
    assert_eq!(c.apply(&mut m, "snap.test", rtype::A).provider, Some("cloudflare"));

    // 透過 state() 的鎖改也一樣
    {
        let mut st = c.state();
        st.pools.p.get_mut("cloudflare").unwrap().tw = crate::pools::cidr(&["198.51.100.0/24"]);
    }
    assert_eq!(c.classify(x).map(|k| k.cls), Some(crate::Cls::Tw));

    // 重新讀範圍檔（每週工作之後）：回到檔案裡的內容
    c.reload_ranges();
    assert_eq!(c.classify(x), None);
    assert_eq!(c.classify(ip("104.16.0.1")).map(|k| k.provider), Some("cloudflare"));

    // CNAME 後綴不分大小寫、結尾的點不影響
    assert_eq!(crate::providers::provider_by_cname("D111.CloudFront.NET."), Some("cloudfront"));
    assert_eq!(crate::providers::provider_by_cname("notcloudfront.net"), None);
}

#[test]
fn provider_by_cname_matches_plain_suffix_scan() {
    // 索引版的結果要跟「所有後綴由長到短逐一比對」（2.x 的做法）完全一樣
    use crate::providers::{provider_by_cname, PROVIDERS};
    let mut all: Vec<(&str, &str)> = PROVIDERS.iter().flat_map(|p| p.cname.iter().map(move |s| (*s, p.name))).collect();
    all.sort_by_key(|x| std::cmp::Reverse(x.0.len()));
    let naive = |host: &str| {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        all.iter()
            .find(|(suf, _)| h == *suf || (h.len() > suf.len() && h.ends_with(suf) && h.as_bytes()[h.len() - suf.len() - 1] == b'.'))
            .map(|x| x.1)
            // 有編號的後綴（3.5.1）：索引沒命中才比規則
            .or_else(|| crate::providers::last2(&h).and_then(|k| crate::providers::provider_by_pattern(&h, k)))
    };
    let mut n = 0;
    for (suf, _) in &all {
        let long = format!("{}.{suf}", "a".repeat(70));
        for host in [
            suf.to_string(),
            format!("x.{suf}"),
            format!("a.b.{}.", suf.to_ascii_uppercase()),
            format!("x{suf}"),
            format!("{suf}.example.com"),
            suf.split_once('.').map(|x| x.1.to_string()).unwrap_or_default(),
            long,
        ] {
            assert_eq!(provider_by_cname(&host), naive(&host), "{host}");
            n += 1;
        }
    }
    assert!(n > 100);
    for host in ["", ".", "com", "example.com", "localhost."] {
        assert_eq!(provider_by_cname(host), naive(host), "{host}");
    }
}

#[tokio::test]
async fn verifier_octet_mode_verifies_backup_ips_for_this_site() {
    // Fastly（保留最後一段）：驗證通過後，備援 IP 也要逐一針對這個網站驗證，只記通過的
    let (c, net) = setup(json!({ "providers": { "fastly": { "enabled": true, "serveCount": 3 } } }));
    let pf = |s: &str| crate::util::parse_prefix24(s).unwrap();
    c.with_state(|st| {
        st.pools.zone.clear();
        let d = st.pools.p.get_mut("fastly").unwrap();
        let mut n = PoolNode::new(ip("151.101.76.2"));
        n.pop = Some(intern("HKG"));
        n.ms = Num::V(26.0);
        n.score = Num::V(28.0);
        d.pool4 = vec![n];
        d.prefixes = [("HKG".to_string(), vec![pf("151.101.76"), pf("151.101.77"), pf("151.101.78")])]
            .into_iter()
            .collect();
        st.db.touch("fo.test", "fastly", "ip", &ips(&["151.101.65.140"]), &[], None);
    });
    let ok = || resp(200, &[("x-served-by", "cache-hkg17920-HKG")], "<html>ok</html>");
    // .78.140 的憑證不是這個網站的；原本的答案在東京
    net.on_https(move |i, _| match i.to_string().as_str() {
        "151.101.78.140" => ProbeResult::failed("ERR_TLS_CERT_ALTNAME_INVALID", true),
        "151.101.65.140" => resp(200, &[("x-served-by", "cache-nrt12345-NRT")], "<html>ok</html>"),
        _ => ok(),
    });
    assert_eq!(c.verify("fo.test", "fastly", 4, Some(ip("151.101.65.140"))).await, Some("ok"));
    let v = c.state().db.get("fo.test").unwrap().v4.clone().unwrap();
    assert_eq!(v.ip, Some(ip("151.101.76.140")));
    assert_eq!(v.ips, Some(ips(&["151.101.76.140", "151.101.77.140"])), "憑證不符的 .78 不列入");
    assert_eq!(net.calls("https 151.101.78.140").len(), 1);
    // 3.5.1 L11：原本的答案就在 HKG，最近的節點也在 HKG → 換到同一個 POP 不算改善，不換、不算失敗
    net.on_https(move |i, _| match i.to_string().as_str() {
        "151.101.78.140" => ProbeResult::failed("ERR_TLS_CERT_ALTNAME_INVALID", true),
        _ => ok(),
    });
    assert_eq!(c.verify("fo.test", "fastly", 4, Some(ip("151.101.65.140"))).await, Some("fail"));
    let v = c.state().db.get("fo.test").unwrap().v4.clone().unwrap();
    assert_eq!(crate::verifier::same_pop_of(&v), Some("HKG"));
    assert_eq!(v.fails, Some(0), "不加失敗次數");
    assert_eq!(v.ip, Some(ip("151.101.65.140")));
    let e = c.explain("fo.test", crate::explain::Context::default());
    assert_eq!(e["decision"], "no-tw-node", "{e}");
    assert_eq!(e["steps"][0]["samePop"], "HKG", "{e}");
    let mut m = msg("fo.test", 1, &["151.101.65.140"], vec![]);
    assert_eq!(c.apply(&mut m, "fo.test", rtype::A).rewritten, None, "查詢路徑照原本的答案");
}

#[tokio::test]
async fn ecs_probe_only_keeps_ips_validated_for_this_site() {
    // ECS 找到的節點：要回給用戶端的每一個（含 IPv6）都要用這個網站的名稱驗證過憑證，沒通過的不列入
    let (c, net) = setup(json!({ "ecs": { "twSubnets": ["1.160.0.0/24"], "resolvers": ["udp://8.8.8.8"] } }));
    c.with_state(|st| {
        st.db
            .touch("multi.ak.test", "akamai", "cname", &ips(&["23.1.1.1"]), &ips(&["2600::1"]), None);
    });
    net.on_dns(|_, name, qtype, _| {
        let mut m = msg(name, qtype, &[], vec![]);
        if qtype == rtype::A {
            for a in ["23.9.9.9", "23.9.9.10", "23.9.9.11"] {
                m.answers.push(Record::a(name, 60, a.parse().unwrap()));
            }
        } else {
            for a in ["2600:9::1", "2600:9::2"] {
                m.answers.push(Record::aaaa(name, 60, a.parse().unwrap()));
            }
        }
        Some(m)
    });
    net.set_cached("23.1.1.1", 60.0);
    net.set_cached("23.9.9.9", 4.0);
    net.set_cached("23.9.9.10", 5.0);
    net.set_cached("23.9.9.11", 6.0);
    net.set_cached("2600:9::1", 5.0);
    net.set_cached("2600:9::2", 6.0);
    net.on_https(|i, _| match i.to_string().as_str() {
        "23.9.9.10" => ProbeResult::failed("ERR_TLS_CERT_ALTNAME_INVALID", true),
        "2600:9::1" => resp(503, &[], ""),
        _ => resp(200, &[], "ok"),
    });
    c.ecs_probe("multi.ak.test", &ips(&["23.1.1.1"]), &ips(&["2600::1"])).await;
    let e = c.state().db.get("multi.ak.test").unwrap().ecs.clone().unwrap();
    assert!(e.is("ok"));
    assert_eq!(e.ips4, Some(ips(&["23.9.9.9", "23.9.9.11"])));
    assert_eq!(e.ips6, Some(ips(&["2600:9::2"])));
}

/// 改寫中、判定還有效的網域（上次驗證在 `age_h` 小時前，`left_h` 小時後到期）
fn rewritten_ok(st: &mut crate::cdn::State, name: &str, hits: u32, age_h: u64, left_h: u64) {
    let now = now_ms();
    st.db.touch(name, "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
    st.db.set_verdict(name, 4, |v| {
        v.verdict = Some(intern("ok"));
        v.ip = Some(ip("104.16.161.36"));
        v.ips = Some(ips(&["104.16.161.36"]));
        v.until = Some(now + left_h * 3_600_000);
    });
    let e = st.db.get_mut(name).unwrap();
    e.v4.as_mut().unwrap().at = Some(now - age_h * 3_600_000);
    e.hits = hits;
    e.best = Some(crate::db::Strategy::Alias);
}

fn verify_names(c: &Cdn) -> Vec<String> {
    c.take_tasks()
        .into_iter()
        .map(|t| match t {
            Task::Verify { name, family: 4, orig, .. } => {
                assert_eq!(orig, Some(ip("104.21.0.5")));
                name
            }
            t => panic!("{t:?}"),
        })
        .collect()
}

#[test]
fn recheck_rotates_through_active_rewrites() {
    let (c, _) = setup(json!({ "reverifyRatio": 0.1, "reverifyMin": 3, "reverifyMax": 4 }));
    c.with_state(|st| {
        for i in 0..20u32 {
            // 熱門程度 × 距上次驗證的時間：i 越大越先
            rewritten_ok(st, &format!("hot{i}.test"), i * 10, 5, 20);
        }
        // 一小時內剛驗證過：不抽
        rewritten_ok(st, "fresh.test", 100_000, 0, 23);
        // 沒有改寫過（`best` 不是換節點）：不抽
        rewritten_ok(st, "idle.test", 100_000, 10, 20);
        st.db.get_mut("idle.test").unwrap().best = None;
        // 一天以上沒出現：不抽
        rewritten_ok(st, "old.test", 100_000, 10, 20);
        st.db.get_mut("old.test").unwrap().last_seen = now_ms() - 2 * 86_400_000;
        // 快到期的交給原本的複驗（只排一次）
        rewritten_ok(st, "soon.test", 100_000, 23, 0);
        st.db.get_mut("soon.test").unwrap().v4.as_mut().unwrap().until = Some(now_ms() + 600_000);
    });
    // 改寫中 22 個（含快到期與剛驗證的）× 0.1 → 3（下限 3、上限 4）；加上快到期的 1 個
    assert_eq!(c.recheck(), 4);
    assert_eq!(verify_names(&c), ["soon.test", "hot19.test", "hot18.test", "hot17.test"]);

    // 抽過的驗證通過（`at` 更新成現在）後，下一個小時輪到下一批
    c.with_state(|st| {
        for n in ["hot19.test", "hot18.test", "hot17.test", "soon.test"] {
            let v = st.db.get_mut(n).unwrap().v4.as_mut().unwrap();
            v.at = Some(now_ms());
            v.until = Some(now_ms() + 86_400_000);
        }
    });
    assert_eq!(c.recheck(), 3);
    assert_eq!(verify_names(&c), ["hot16.test", "hot15.test", "hot14.test"]);

    // 上限
    let (c, _) = setup(json!({ "reverifyRatio": 1, "reverifyMin": 1, "reverifyMax": 2 }));
    c.with_state(|st| {
        for i in 0..10u32 {
            rewritten_ok(st, &format!("m{i}.test"), i, 5, 20);
        }
    });
    assert_eq!(c.recheck(), 2);

    // 比例 0 = 關閉
    let (c, _) = setup(json!({ "reverifyRatio": 0 }));
    c.with_state(|st| rewritten_ok(st, "a.test", 10, 5, 20));
    assert_eq!(c.recheck(), 0);
}

#[tokio::test]
async fn reverify_failure_drops_rewrite_immediately() {
    // 節點本身健康，但這個網站開始不讓它服務（Cloudflare 1034）：抽驗失敗後下一次查詢就回原始結果，
    // 不必等 24 小時的判定過期
    let (c, net) = setup(json!({}));
    third_node(&c);
    c.with_state(|st| rewritten_ok(st, "s.test", 50, 5, 20));
    let q = || msg("s.test", 1, &["104.21.0.5"], vec![]);
    let a = |m: &Message| {
        m.answers
            .iter()
            .filter_map(|r| match r.data {
                kuroshio_proto::message::RData::A(v) => Some(IpAddr::V4(v)),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let mut m = q();
    let r = c.apply(&mut m, "s.test", rtype::A);
    assert_eq!(r.rewritten, Some(crate::Rewrite::Alias), "{:?}", r.tags);
    assert_eq!(a(&m), ips(&["104.16.161.36"]));
    c.take_tasks();

    assert_eq!(c.recheck(), 1);
    let Some(Task::Verify {
        name,
        provider,
        family,
        orig,
    }) = c.take_tasks().into_iter().next()
    else {
        panic!("沒有排入複驗")
    };
    net.on_https(|i, _| match i.to_string().as_str() {
        "104.21.0.5" => cf_ok("NRT"),
        _ => resp(403, &[("cf-ray", "x-TPE")], "error code: 1034"),
    });
    assert_eq!(c.verify(&name, &provider, family, orig).await, Some("fail"));

    let mut m = q();
    let r = c.apply(&mut m, "s.test", rtype::A);
    assert_eq!(r.rewritten, None, "{:?}", r.tags);
    assert!(r.tags.iter().any(|t| t.contains("驗證失敗→原始")), "{:?}", r.tags);
    assert_eq!(a(&m), ips(&["104.21.0.5"]));
}

#[test]
fn friend_nodes_become_harvest_candidates_only() {
    // 好友給的台灣節點：官方範圍內、我的節點池沒有的才放進候選名單；不直接進節點池
    let (c, _net) = setup(json!({}));
    let nodes = [
        ("cloudflare", "104.16.50.1"),
        ("cloudflare", "104.16.161.36"), // 已經在我的節點池
        ("cloudflare", "203.0.113.9"),   // 不在官方範圍
        ("cloudflare", "2606:4700::9"),  // IPv6 放 IPv6 的候選
        ("cloudflare", "::ffff:104.16.50.3"),
        ("nosuchcdn", "104.16.50.2"),
    ];
    let n = c.add_friend_nodes(nodes.iter().map(|(p, i)| (*p, ip(i))));
    assert_eq!(n, 3);
    let st = c.state();
    assert_eq!(st.db.harvest_of("cloudflare", false), ips(&["104.16.50.1", "104.16.50.3"]));
    assert_eq!(st.db.harvest_of("cloudflare", true), ips(&["2606:4700::9"]));
    assert_eq!(st.pools.pool_size("cloudflare", 4), 2, "節點池不動");
    drop(st);
    // 同一個不重複放
    assert_eq!(c.add_friend_nodes([("cloudflare", ip("104.16.50.1"))]), 0);

    // 一次最多 500 個
    let (c, _net) = setup(json!({}));
    let many: Vec<IpAddr> = (0..600u32)
        .map(|i| IpAddr::V4(std::net::Ipv4Addr::from(0x6811_0000 + i * 7)))
        .collect();
    assert_eq!(
        c.add_friend_nodes(many.iter().map(|i| ("cloudflare", *i))),
        crate::cdn::FRIEND_MAX_NODES
    );

    // 候選名單滿了：不擠掉自己流量收集到的
    let (c, _net) = setup(json!({}));
    c.with_state(|st| {
        for i in 0..crate::db::HARVEST_MAX as u32 {
            st.db
                .add_harvest("cloudflare", IpAddr::V4(std::net::Ipv4Addr::from(0x6812_0000 + i)));
        }
    });
    assert_eq!(c.add_friend_nodes([("cloudflare", ip("104.16.50.1"))]), 0);
    let h = c.state().db.harvest_of("cloudflare", false);
    assert_eq!(h.len(), crate::db::HARVEST_MAX);
    assert!(!h.contains(&ip("104.16.50.1")));
}

#[test]
fn friend_nodes_capped_per_batch_never_above_default() {
    // 3.5.0 E10：每批上限只會變少（別群組的好友四分之一），超過 500 的照 500 算
    let many: Vec<IpAddr> = (0..600u32)
        .map(|i| IpAddr::V4(std::net::Ipv4Addr::from(0x6811_0000 + i * 7)))
        .collect();
    let (c, _net) = setup(json!({}));
    assert_eq!(c.add_friend_nodes_capped(many.iter().map(|i| ("cloudflare", *i)), 125), 125);
    let (c, _net) = setup(json!({}));
    assert_eq!(
        c.add_friend_nodes_capped(many.iter().map(|i| ("cloudflare", *i)), 10_000),
        crate::cdn::FRIEND_MAX_NODES
    );
    let (c, _net) = setup(json!({}));
    assert_eq!(c.add_friend_nodes_capped(many.iter().map(|i| ("cloudflare", *i)), 0), 0);
}

#[test]
fn recheck_skips_one_shot_and_covers_alt_slot() {
    // 3.5.1 M3：只複驗真的有在改寫（best = 換節點）或問過 2 次以上的；只問過一次的到期就讓它到期。
    // L13：多來源網域另一家的那一格也用同樣的條件複驗
    let (c, _) = setup(json!({ "reverifyRatio": 0 }));
    let soon = now_ms() + 600_000;
    c.with_state(|st| {
        for (n, hits, alias) in [("once.test", 1, false), ("twice.test", 2, false), ("alias.test", 1, true)] {
            st.db.touch(n, "cloudflare", "ip", &ips(&["104.21.0.5"]), &[], None);
            st.db.set_verdict(n, 4, |v| {
                v.verdict = Some(intern("ok"));
                v.until = Some(soon);
            });
            let e = st.db.get_mut(n).unwrap();
            e.hits = hits;
            if alias {
                e.best = Some(crate::db::Strategy::Alias);
            }
        }
        // 多來源：主格是別家、另一格是 Cloudflare 而且快到期
        st.db.touch("multi.test", "cloudfront", "ip", &ips(&["198.51.100.20"]), &[], None);
        let e = st.db.get_mut("multi.test").unwrap();
        e.hits = 5;
        e.src = Some(Box::new(crate::db::Src {
            alt: Some(Box::new(crate::db::Alt {
                provider: crate::util::Field::Val(intern("cloudflare")),
                ips4: ips(&["104.21.0.9"]).into_boxed_slice(),
                v4: Some(Box::new(crate::db::Verdict {
                    verdict: Some(intern("ok")),
                    until: Some(soon),
                    ..Default::default()
                })),
                last: now_ms(),
                ..Default::default()
            })),
            ..Default::default()
        }));
    });
    assert_eq!(c.recheck(), 3);
    let mut got: Vec<(String, String, Option<IpAddr>)> = c
        .take_tasks()
        .into_iter()
        .filter_map(|t| match t {
            Task::Verify { name, provider, orig, .. } => Some((name, provider, orig)),
            _ => None,
        })
        .collect();
    got.sort();
    assert_eq!(
        got,
        [
            ("alias.test".to_string(), "cloudflare".to_string(), Some(ip("104.21.0.5"))),
            ("multi.test".to_string(), "cloudflare".to_string(), Some(ip("104.21.0.9"))),
            ("twice.test".to_string(), "cloudflare".to_string(), Some(ip("104.21.0.5"))),
        ]
    );
}

#[test]
fn imported_never_queried_domains_are_not_rechecked() {
    // 分享檔匯入的網域（lastSeen = 0、已過期的通過）：每小時的複驗不去驗證，等這台有人查到才驗證
    let (c, _net) = setup(json!({ "reverifyRatio": 0 }));
    let file = |last: u64| {
        serde_json::to_vec(&json!({ "domains": [
            { "name": "imported.example.com", "provider": "cloudflare", "firstSeen": now_ms(), "lastSeen": last, "hits": 3,
              "v4": { "verdict": "ok", "until": 0 } }
        ] }))
        .unwrap()
    };
    c.with_state(|st| st.db.load_domains(&file(0), false).unwrap());
    assert_eq!(c.recheck(), 0, "沒人查過的不驗證");
    c.with_state(|st| st.db.load_domains(&file(now_ms()), false).unwrap());
    assert_eq!(c.recheck(), 1, "最近有人查過的照常複驗");
}

/// 3.5.1：「特定產品專用」消退時寫一行（同一家 CDN 合併）；`/api/cdn/pools` 列出目前被標成特定產品專用的節點與網站數
#[test]
fn zone_restricted_listed_and_lift_logged() {
    use crate::pools::lifted_text;
    assert_eq!(lifted_text(&[]), None);
    assert_eq!(
        lifted_text(&["fastly|192.0.2.1", "cloudflare|198.51.100.3", "fastly|192.0.2.2"]).unwrap(),
        "fastly 2 個（192.0.2.1、192.0.2.2）、cloudflare 1 個（198.51.100.3）",
        "同一家 CDN 合併成一段"
    );
    let many: Vec<String> = (1..=7).map(|i| format!("fastly|192.0.2.{i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(
        lifted_text(&many).unwrap(),
        "fastly 7 個（192.0.2.1、192.0.2.2、192.0.2.3、192.0.2.4、192.0.2.5 等）",
        "每家最多列 5 個"
    );

    let (c, _) = setup(json!({}));
    let (x, y) = (ip("192.0.2.10"), ip("192.0.2.11"));
    c.with_state(|st| {
        let p = &mut st.pools;
        for s in ["a.example.com", "b.example.com", "c.example.com"] {
            p.zone_note_site("cloudflare", x, false, s);
        }
        // 只有一個網站不能用：還不是特定產品專用，不列
        p.zone_note_site("cloudflare", y, false, "a.example.com");
        let v = p.status();
        let cf = &v["cloudflare"];
        assert_eq!(cf["restrictedTotal"], 1);
        let r = &cf["restricted"][0];
        assert_eq!(
            (r["ip"].as_str(), r["sites"].as_u64(), r["hit"].as_u64(), r["inPool"].as_bool()),
            (Some("192.0.2.10"), Some(3), Some(0), Some(false))
        );
        assert!(r["until"].as_u64().unwrap() > r["missAt"].as_u64().unwrap());
        for (name, d) in v.as_object().unwrap() {
            if name != "cloudflare" {
                assert_eq!(d["restrictedTotal"], 0, "{name}");
            }
        }
        // 消退之後不再列出
        assert_eq!(p.decay_zone(now_ms() + 8 * 86_400_000), 2);
        assert_eq!(p.status()["cloudflare"]["restrictedTotal"], 0);
    });
}
