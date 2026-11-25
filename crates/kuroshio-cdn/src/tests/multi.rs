//! 尊重多來源 CDN、第一層 CNAME 變了就失效（3.5.0，規格 11 B3）。
//! 時間都是傳進去的（`Db::touch_at` 的 `now`），不等真的時間

use super::selftest::setup;
use super::*;
use crate::db::{c1_key, Cross, Db, Domain, Ecs, Mark, Policy, Strategy, C1_CONFIRM_MS, C1_MAX, MULTI_KEEP_MS, SRC_GAP_MS, SRC_WINDOW_MS};
use crate::explain::Context;
use crate::util::{intern, now_ms};
use crate::{Rewrite, Task};
use serde_json::json;

const T0: u64 = 1_800_000_000_000;
const MIN: u64 = 60_000;
const HOUR: u64 = 3_600_000;

fn db() -> Db {
    let mut d = Db::new(1000);
    d.set_shards(1);
    d
}

/// 已經驗證通過、有跨 CDN 與 ECS 結果的網域（`c1` 有沒有由呼叫端決定）
fn seeded(db: &mut Db, name: &str, provider: &str, c1: &str) {
    db.touch_at(name, provider, "cname", &ips(&["192.0.2.1"]), &[], Some("t.example.net"), c1, T0);
    db.set_verdict(name, 4, |v| {
        v.verdict = Some(intern("ok"));
        v.until = Some(T0 + 30 * 24 * HOUR);
        v.ip = Some(ip("198.51.100.1"));
    });
    db.set_cross(
        name,
        Cross {
            verdict: Some(intern("ok")),
            until: Some(T0 + 30 * 24 * HOUR),
            ..Default::default()
        },
    );
    db.set_ecs(
        name,
        Ecs {
            verdict: Some(intern("ok")),
            until: Some(T0 + 30 * 24 * HOUR),
            ..Default::default()
        },
    );
    db.set_best(name, Strategy::Cross);
    db.take_marks(false);
}

fn important(db: &Db) -> bool {
    db.marks().contains(&Mark::Important)
}

#[test]
fn c1_key_ignores_per_request_labels() {
    // 前面每次查詢都不同的標籤（節點、地區、雜湊）不算；最後三段才是鍵
    assert_eq!(c1_key("a1b2.node7.edge.example.net"), "edge.example.net");
    assert_eq!(c1_key("c3d4.node9.edge.example.net."), "edge.example.net");
    assert_eq!(c1_key("d111.example.net"), "d111.example.net");
    assert_eq!(c1_key("D111.Example.NET"), "D111.Example.NET", "不改大小寫（比對時不分）");
    assert_eq!(c1_key("example.net"), "example.net");
    assert_eq!(c1_key("localhost"), "localhost");
    assert_eq!(c1_key(""), "");
    // 太長：退到最後兩段；還是太長就不記
    let long = format!("{}.example.net", "a".repeat(60));
    assert_eq!(c1_key(&long), "example.net");
    let too_long = format!("x.{}.net", "a".repeat(70));
    assert_eq!(c1_key(&too_long), "");
    assert!(c1_key(&format!("{}.b.c", "a".repeat(C1_MAX - 4))).len() <= C1_MAX);
}

#[test]
fn c1_backfill_on_upgrade_is_not_a_change() {
    // 3.4.x 存下來的紀錄沒有 c1：升級後第一次看到只是補上，不清任何結果、不算重要變動（不觸發寫入）
    let old = json!({
        "name": "old.example.com", "provider": "cloudfront", "via": "cname", "cname": "d111.cdn.example.net",
        "firstSeen": T0 - 1000, "lastSeen": T0 - 1000, "hits": 9, "ips4": ["192.0.2.1"], "ips6": [],
        "v4": { "verdict": "ok", "until": T0 + HOUR, "ip": "198.51.100.1" },
        "cross4": { "verdict": "ok", "until": T0 + HOUR }, "ecs": { "verdict": "ok", "until": T0 + HOUR },
        "best": "cross"
    });
    let d: Domain = serde_json::from_value(old).unwrap();
    assert!(d.c1.is_none() && d.src.is_none());
    let mut db = db();
    db.domains.insert(d.name.clone(), d);
    let t = db.touch_at(
        "old.example.com",
        "cloudfront",
        "cname",
        &ips(&["192.0.2.1"]),
        &[],
        Some("d111.cdn.example.net"),
        "d111.cdn.example.net",
        T0,
    );
    assert_eq!(t, Default::default(), "不是變動");
    assert!(!important(&db), "只有計數：不單獨觸發寫入");
    let e = db.get("old.example.com").unwrap();
    assert_eq!(e.c1.as_deref(), Some("d111.cdn.example.net"));
    assert!(e.v4.as_ref().unwrap().is("ok") && e.cross4.is_some() && e.ecs.is_some());
    assert_eq!(e.best, Some(Strategy::Cross));
    assert!(e.src.is_none(), "沒有變動的網域不多佔記憶體");
}

#[test]
fn provider_switch_invalidates_verdict_cross_ecs_best() {
    // 網站從 A 家搬到 B 家：B 家從試用期重新驗證；跨 CDN、ECS、最佳策略清掉。
    // A 家的驗證結果不刪（留在另一格，萬一只是兩家輪流），但不會用在 B 家的回答上
    let mut db = db();
    seeded(&mut db, "moved.example.com", "cloudfront", "d111.cdn.example.net");
    let t = db.touch_at(
        "moved.example.com",
        "cloudflare",
        "ip",
        &ips(&["192.0.2.9"]),
        &[],
        Some("moved.example.com"),
        "",
        T0 + MIN,
    );
    assert!(t.new_slot && t.invalidated && t.no_cross && !t.held);
    assert!(important(&db));
    let e = db.get("moved.example.com").unwrap();
    assert_eq!(e.provider(), Some("cloudflare"));
    assert!(e.v4.is_none() && e.v6.is_none() && e.base.is_none(), "新的一家從試用期開始");
    assert!(e.cross4.is_none() && e.ecs.is_none() && e.best.is_none());
    assert_eq!(&*e.ips4, &ips(&["192.0.2.9"])[..]);
    let alt = e.src.as_ref().unwrap().alt.as_ref().unwrap();
    assert_eq!(alt.provider.val().map(|p| &**p), Some("cloudfront"));
    assert!(alt.v4.as_ref().unwrap().is("ok"));
    assert_eq!(alt.last, T0);
    assert!(!e.multi(T0 + MIN), "只看到換家，還沒看到輪流");

    // 之後一直是 B 家：24 小時後定下來是「換家」，A 家那一格丟掉，可以做跨 CDN 了
    let t = db.touch_at("moved.example.com", "cloudflare", "ip", &[], &[], None, "", T0 + 12 * HOUR);
    assert!(t.no_cross && !t.new_slot && !t.invalidated);
    let t = db.touch_at(
        "moved.example.com",
        "cloudflare",
        "ip",
        &[],
        &[],
        None,
        "",
        T0 + SRC_WINDOW_MS + 2 * MIN,
    );
    assert!(!t.no_cross);
    let e = db.get("moved.example.com").unwrap();
    assert!(e.src.as_ref().is_none_or_alt_gone());
}

trait AltGone {
    fn is_none_or_alt_gone(&self) -> bool;
}
impl AltGone for Option<&Box<crate::db::Src>> {
    fn is_none_or_alt_gone(&self) -> bool {
        self.map(|s| s.alt.is_none()).unwrap_or(true)
    }
}

#[test]
fn same_provider_cname_change_keeps_verdict() {
    // 同一家裡換了第一層 CNAME：只清跨 CDN 與 ECS，驗證結果留著。要連續看到 3 次、相隔 10 分鐘以上才算
    let mut db = db();
    let name = "site.example.com";
    seeded(&mut db, name, "cloudfront", "d111.cdn.example.net");
    let touch = |db: &mut Db, c1: &str, at: u64| {
        db.touch_at(
            name,
            "cloudfront",
            "cname",
            &ips(&["192.0.2.1"]),
            &[],
            Some("t.example.net"),
            c1,
            at,
        )
    };
    // 同一份快取的答案連續出現很多次：次數夠了、時間不夠，不算
    for i in 0..20 {
        assert!(!touch(&mut db, "d222.cdn.example.net", T0 + MIN + i).invalidated);
    }
    assert!(db.get(name).unwrap().cross4.is_some());
    assert!(!important(&db), "還沒確認：不觸發寫入");
    // 10 分鐘後還是新的鍵：確認變了
    let t = touch(&mut db, "d222.cdn.example.net", T0 + MIN + C1_CONFIRM_MS);
    assert!(t.invalidated && !t.new_slot);
    let e = db.get(name).unwrap();
    assert_eq!(e.c1.as_deref(), Some("d222.cdn.example.net"));
    assert!(e.cross4.is_none() && e.ecs.is_none() && e.best.is_none());
    assert!(e.v4.as_ref().unwrap().is("ok"), "驗證結果留著");
    assert!(important(&db));

    // 換回舊的鍵：24 小時內看過，不算新的（不會來回失效）
    db.set_cross(name, Cross::default());
    for i in 0..5 {
        assert!(!touch(&mut db, "d111.cdn.example.net", T0 + 30 * MIN + i * 5 * MIN).invalidated);
    }
    assert!(db.get(name).unwrap().cross4.is_some());

    // 又來一個全新的鍵、也確認了，但離上次失效不到 6 小時：鍵照樣更新，結果不清（上限）
    let at = T0 + 2 * HOUR;
    for i in 0..3 {
        assert!(!touch(&mut db, "d333.cdn.example.net", at + i * C1_CONFIRM_MS).invalidated);
    }
    assert_eq!(db.get(name).unwrap().c1.as_deref(), Some("d333.cdn.example.net"));
    assert!(db.get(name).unwrap().cross4.is_some());
    // 6 小時之後的新鍵：可以再失效一次
    let at = T0 + MIN + C1_CONFIRM_MS + SRC_GAP_MS;
    touch(&mut db, "d444.cdn.example.net", at);
    touch(&mut db, "d444.cdn.example.net", at + 1);
    assert!(touch(&mut db, "d444.cdn.example.net", at + C1_CONFIRM_MS).invalidated);
}

#[test]
fn flapping_first_layer_is_not_a_change() {
    // 網站自己在兩個第一層之間輪流（同一家 CDN）：第二個鍵出現過、舊的又回來 → 記成「輪流的另一個」，永遠不失效
    let mut db = db();
    let name = "flap.example.com";
    seeded(&mut db, name, "cloudfront", "geo-a.example.net");
    let mut n = 0;
    for i in 0..200u64 {
        let k = if (i / 3) % 2 == 0 {
            "geo-b.example.net"
        } else {
            "geo-a.example.net"
        };
        let t = db.touch_at(
            name,
            "cloudfront",
            "cname",
            &ips(&["192.0.2.1"]),
            &[],
            Some("t.example.net"),
            k,
            T0 + i * 4 * MIN,
        );
        n += t.invalidated as u32;
    }
    assert_eq!(n, 0);
    assert!(db.get(name).unwrap().cross4.is_some());
    assert!(db.get(name).unwrap().src.as_ref().unwrap().seen.len() <= crate::db::C1_SEEN_MAX);
}

#[test]
fn alternating_providers_marks_multi_and_does_not_thrash() {
    // 兩家輪流回答 100 次：失效 ≤ 1 次、排入的驗證 ≤ 2 個、沒有重要變動（不一直寫 Flash），
    // 而且驗證過的那一家每次都照常換成台灣節點
    let (c, _net) = setup(json!({}));
    let name = "gslb.example.com";
    let cf = || msg(name, 1, &["104.21.0.5"], vec![]);
    let other = || msg(name, 1, &["192.0.2.10"], vec![cname(name, "d111.cloudfront.net", 60)]);
    let mut verifies = 0;
    let count = |c: &Arc<Cdn>| c.take_tasks().iter().filter(|t| matches!(t, Task::Verify { .. })).count();
    // 第一家：試用期、排驗證；模擬驗證通過
    let mut m = cf();
    assert_eq!(c.apply(&mut m, name, 1).ttl_cap, Some(10));
    verifies += count(&c);
    c.with_state(|st| {
        st.db.with_slot(name, "cloudflare", |db| {
            db.set_verdict(name, 4, |v| {
                v.verdict = Some(intern("ok"));
                v.until = Some(now_ms() + 3_600_000);
                v.ip = Some(ip("104.16.161.36"));
            })
        });
        st.db.take_marks(false);
    });
    // 第二家第一次出現：開一格（重要變動一次）
    let mut m = other();
    let r = c.apply(&mut m, name, 1);
    assert_eq!(r.provider, Some("cloudfront"));
    assert_eq!(answer_ips(&m, 1), ["192.0.2.10"], "沒驗證過的那一家：原始答案");
    verifies += count(&c);
    // 各回答一次之後就穩定了（第一次改寫會記「最佳策略」，那是一次重要變動）
    for m in [&mut cf(), &mut other()] {
        c.apply(m, name, 1);
        verifies += count(&c);
    }
    c.with_state(|st| st.db.take_marks(false));
    for i in 0..100 {
        let mut m = if i % 2 == 0 { cf() } else { other() };
        let r = c.apply(&mut m, name, 1);
        if i % 2 == 0 {
            assert_eq!(r.rewritten, Some(Rewrite::Alias), "第 {i} 次");
            assert_eq!(answer_ips(&m, 1), ["104.16.161.36"]);
        } else {
            assert_eq!(r.rewritten, None);
            assert_eq!(answer_ips(&m, 1), ["192.0.2.10"]);
        }
        verifies += count(&c);
    }
    let st = c.state();
    assert!(st.stats.src_invalidated <= 1, "{}", st.stats.src_invalidated);
    assert!(verifies <= 2, "{verifies}");
    assert!(!st.db.marks().contains(&Mark::Important), "輪流回答只算計數");
    let e = st.db.get(name).unwrap();
    assert!(e.multi(now_ms()));
    assert_eq!(e.provs().len(), 2);
    assert_eq!(st.stats.multi_held, 0);
}

#[test]
fn multi_serves_original_for_unverified_provider() {
    // 第三家（6 小時內的第二次換家）：沒有格子，照原始答案回，不驗證、不改寫，也不蓋掉另外兩家的紀錄
    let (c, _net) = setup(json!({}));
    let name = "three.example.com";
    let mut m = msg(name, 1, &["104.21.0.5"], vec![]);
    c.apply(&mut m, name, 1);
    let mut m = msg(name, 1, &["192.0.2.10"], vec![cname(name, "d111.cloudfront.net", 60)]);
    c.apply(&mut m, name, 1);
    c.take_tasks();
    let mut m = msg(name, 1, &["151.101.1.140"], vec![]);
    let r = c.apply(&mut m, name, 1);
    assert_eq!(r.provider, Some("fastly"));
    assert_eq!((r.rewritten, r.ttl_cap), (None, None));
    assert_eq!(answer_ips(&m, 1), ["151.101.1.140"]);
    assert!(r.tags.iter().any(|t| t.contains("多來源")), "{:?}", r.tags);
    assert!(c.take_tasks().is_empty(), "不驗證、不探索");
    let st = c.state();
    assert_eq!(st.stats.multi_held, 1);
    let e = st.db.get(name).unwrap();
    assert_eq!(e.provider(), Some("cloudfront"), "目前這一格沒有被蓋掉");
    assert_eq!(&*e.ips4, &ips(&["192.0.2.10"])[..]);
    let p = e.provs();
    assert_eq!(p.len(), 3);
    assert_eq!((p[2].0.as_str(), p[2].2), ("fastly", false));
}

#[test]
fn new_slot_at_most_once_per_gap() {
    // 三家輪流：每 6 小時最多替新的一家開一格（＝最多多一次驗證），其餘照原始答案回
    let mut db = db();
    let name = "rr.example.com";
    db.touch_at(name, "cloudflare", "ip", &[], &[], None, "", T0);
    let provs = ["cloudfront", "fastly", "cloudflare"];
    let (mut slots, mut held) = (0, 0);
    for i in 0..300u64 {
        let t = db.touch_at(name, provs[(i % 3) as usize], "ip", &[], &[], None, "", T0 + (i + 1) * MIN);
        slots += t.new_slot as u32;
        held += t.held as u32;
    }
    // 300 分鐘 = 5 小時：只有第一次開了一格
    assert_eq!(slots, 1);
    assert!(held >= 99, "{held}");
    // 過了 6 小時：可以再開一格
    let t = db.touch_at(name, "fastly", "ip", &[], &[], None, "", T0 + MIN + SRC_GAP_MS);
    assert!(t.new_slot);
}

#[test]
fn multi_cleared_after_seven_days() {
    let mut db = db();
    let name = "wk.example.com";
    db.touch_at(name, "cloudflare", "ip", &[], &[], None, "", T0);
    db.touch_at(name, "cloudfront", "cname", &[], &[], None, "", T0 + MIN);
    assert!(!db.get(name).unwrap().multi(T0 + MIN), "第二家第一次出現：還不算輪流");
    let t = db.touch_at(name, "cloudflare", "ip", &[], &[], None, "", T0 + 2 * MIN);
    assert!(t.no_cross && !t.new_slot && !t.invalidated);
    assert!(db.get(name).unwrap().multi(T0 + 2 * MIN), "回到第一家：兩家在輪流");
    // 6 天後還是多來源，另一格還在
    let t = db.touch_at(name, "cloudflare", "ip", &[], &[], None, "", T0 + 6 * 24 * HOUR);
    assert!(t.no_cross);
    assert!(db.get(name).unwrap().src.as_ref().unwrap().alt.is_some());
    // 7 天沒有再看到第二家：取消，另一格丟掉，來源紀錄整個收掉
    let at = T0 + 2 * MIN + MULTI_KEEP_MS + MIN;
    let t = db.touch_at(name, "cloudflare", "ip", &[], &[], None, "", at);
    assert!(!t.no_cross);
    let e = db.get(name).unwrap();
    assert!(!e.multi(at));
    assert!(e.src.is_none(), "{:?}", e.src);
}

#[test]
fn multi_domain_skips_cross_cdn() {
    // 多來源：不排跨 CDN 探索，已經有的跨 CDN 結果也不用（網站自己在多家之間選）
    let (c, net) = setup(json!({}));
    let name = "fx.example.com";
    net.set_cached("151.101.1.140", 80.0);
    let fastly = || msg(name, 1, &["151.101.1.140"], vec![]);
    let mut m = fastly();
    c.apply(&mut m, name, 1);
    assert!(c.take_tasks().iter().any(|t| matches!(t, Task::Cross { .. })), "單一來源：照常探索");
    // 第二家出現
    let mut m = msg(name, 1, &["192.0.2.10"], vec![cname(name, "d111.cloudfront.net", 60)]);
    c.apply(&mut m, name, 1);
    c.take_tasks();
    let mut m = fastly();
    let r = c.apply(&mut m, name, 1);
    assert_eq!(r.rewritten, None);
    assert!(!c.take_tasks().iter().any(|t| matches!(t, Task::Cross { .. })));
    assert_eq!(c.explain(name, Context::default())["decision"], "multi-cdn");
    let v = c.explain(name, Context::default());
    assert_eq!(v["multi"], true);
    assert_eq!(v["provs"].as_array().unwrap().len(), 2, "{v}");
    assert!(v["text"].as_str().unwrap().contains("CloudFront"), "{v}");
    assert!(c.domain(name).unwrap()["multi"].as_bool().unwrap());
}

#[tokio::test]
async fn cross_explore_refuses_multi_domain() {
    // 排進佇列之後才變成多來源的：探索開始時再看一次，不連線
    let (c, net) = setup(json!({}));
    let name = "late.example.com";
    c.with_state(|st| {
        st.db.touch_at(name, "fastly", "ip", &[], &[], None, "", now_ms());
        st.db.touch_at(name, "cloudfront", "cname", &[], &[], None, "", now_ms());
    });
    assert_eq!(c.cross_explore(name, "fastly", ip("151.101.1.140")).await, "none");
    assert!(net.calls("https").is_empty());
    assert!(c.state().db.get(name).unwrap().cross4.is_none());
}

#[tokio::test]
async fn verify_result_goes_to_its_own_provider_slot() {
    // 驗證跑到一半、回答換成另一家：結果寫回自己那一格，不會寫進別家的格子
    let (c, net) = setup(json!({}));
    let name = "slot.example.com";
    let mut m = msg(name, 1, &["104.21.0.5"], vec![]);
    c.apply(&mut m, name, 1);
    let mut m = msg(name, 1, &["192.0.2.10"], vec![cname(name, "d111.cloudfront.net", 60)]);
    c.apply(&mut m, name, 1);
    net.on_https(|i, _| {
        resp(
            200,
            &[
                ("server", "cloudflare"),
                ("cf-ray", if i == ip("104.21.0.5") { "1-NRT" } else { "1-TPE" }),
            ],
            "ok",
        )
    });
    assert_eq!(c.verify(name, "cloudflare", 4, Some(ip("104.21.0.5"))).await, Some("ok"));
    {
        let st = c.state();
        let e = st.db.get(name).unwrap();
        assert_eq!(e.provider(), Some("cloudfront"), "目前這一格還是最後回答的那一家");
        assert!(e.v4.is_none(), "沒有寫進別家的格子");
        let alt = e.src.as_ref().unwrap().alt.as_ref().unwrap();
        assert!(alt.v4.as_ref().unwrap().is("ok"));
        assert_eq!(alt.base.as_ref().unwrap().ip, Some(ip("104.21.0.5")));
    }
    // 下一次是 Cloudflare 回答：馬上用得到
    let mut m = msg(name, 1, &["104.21.0.5"], vec![]);
    assert_eq!(c.apply(&mut m, name, 1).rewritten, Some(Rewrite::Alias));
    // 已經沒有格子的那一家：不驗證、不連線
    let before = net.calls("https").len();
    assert_eq!(c.verify(name, "fastly", 4, None).await, None);
    assert_eq!(net.calls("https").len(), before);
}

#[test]
fn app_layer_provider_never_rewritten_but_counted() {
    // App 自己選節點的服務：只辨識與統計，不改寫、不 ECS、不跨 CDN
    let (c, net) = setup(json!({ "providers": { "apple": { "enabled": true, "ecs": true } } }));
    let name = "updates.example.com";
    net.set_cached("192.0.2.20", 90.0);
    let mk = || msg(name, 1, &["192.0.2.20"], vec![cname(name, "dl.example.aaplimg.com", 60)]);
    let mut m = mk();
    let r = c.apply(&mut m, name, 1);
    assert_eq!(r.provider, Some("apple"), "照樣辨識（統計用）");
    assert_eq!((r.rewritten, r.ttl_cap), (None, None));
    assert_eq!(answer_ips(&m, 1), ["192.0.2.20"]);
    assert!(c.take_tasks().is_empty(), "不 ECS、不跨 CDN");
    assert_eq!(c.state().stats.app_layer, 1);
    assert_eq!(c.state().db.get(name).unwrap().hits, 1, "資料庫照樣記");
    assert_eq!(c.explain(name, Context::default())["decision"], "app-layer");

    // `cdn.appLayer: false`：同 3.4.x（Apple 設成 ecs 時會排 ECS 突破）
    let (c, _) = setup(json!({ "appLayer": false, "providers": { "apple": { "enabled": true, "ecs": true } } }));
    let mut m = mk();
    c.apply(&mut m, name, 1);
    assert!(c.take_tasks().iter().any(|t| matches!(t, Task::Ecs { .. })));
}

#[test]
fn policy_override_still_wins() {
    let (c, _net) = setup(json!({ "providers": { "apple": { "enabled": true, "ecs": true } } }));
    let name = "mine.example.com";
    let mk = || msg(name, 1, &["192.0.2.20"], vec![cname(name, "dl.example.aaplimg.com", 60)]);
    // 手動「一定換」：App 層的標記不擋（照一般流程，這裡是 ECS 突破）
    c.with_state(|st| {
        st.db.set_policy(name, Policy::Always);
    });
    let mut m = mk();
    c.apply(&mut m, name, 1);
    assert!(c.take_tasks().iter().any(|t| matches!(t, Task::Ecs { .. })));
    assert_eq!(c.state().stats.app_layer, 0);
    // 手動「不換」：照舊最優先
    c.with_state(|st| {
        st.db.set_policy(name, Policy::Never);
    });
    let mut m = mk();
    let r = c.apply(&mut m, name, 1);
    assert!(r.tags.iter().any(|t| t == "CDN-略過"));
    assert!(c.take_tasks().is_empty());
}

#[test]
fn multi_cdn_off_restores_old_behavior() {
    // `cdn.multiCdn: false`：同 3.4.x，業者欄位直接改寫、不分格子、不失效
    let (c, _net) = setup(json!({ "multiCdn": false }));
    let name = "legacy.example.com";
    let mut m = msg(name, 1, &["104.21.0.5"], vec![]);
    c.apply(&mut m, name, 1);
    let mut m = msg(name, 1, &["192.0.2.10"], vec![cname(name, "d111.cloudfront.net", 60)]);
    c.apply(&mut m, name, 1);
    let st = c.state();
    let e = st.db.get(name).unwrap();
    assert_eq!(e.provider(), Some("cloudfront"));
    assert!(e.src.is_none() && e.c1.is_none());
    assert_eq!((st.stats.src_invalidated, st.stats.multi_held), (0, 0));
}

#[test]
fn src_roundtrip_and_memory_estimate() {
    // 寫出去再讀回來一樣；有另一格的網域，記憶體估計要算進去；種子資料不帶別台的另一格
    let mut db = db();
    let name = "rt.example.com";
    seeded(&mut db, name, "cloudfront", "d111.cdn.example.net");
    db.touch_at(name, "cloudflare", "ip", &ips(&["192.0.2.9"]), &[], None, "", T0 + MIN);
    db.touch_at(name, "cloudfront", "cname", &[], &[], None, "d111.cdn.example.net", T0 + 2 * MIN);
    let e = db.get(name).unwrap().clone();
    let mut plain = e.clone();
    plain.src = None;
    assert!(
        e.approx_bytes() > plain.approx_bytes() + 100,
        "{} {}",
        e.approx_bytes(),
        plain.approx_bytes()
    );
    let text = serde_json::to_string(&e).unwrap();
    assert!(
        text.contains("\"c1\":\"d111.cdn.example.net\"") && text.contains("\"multiAt\""),
        "{text}"
    );
    let back: Domain = serde_json::from_str(&text).unwrap();
    assert_eq!(back, e);
    // 沒有變動的網域：不多寫任何欄位
    let mut db2 = self::db();
    db2.touch_at("p.example.com", "cloudflare", "ip", &[], &[], None, "", T0);
    let text = serde_json::to_string(db2.get("p.example.com").unwrap()).unwrap();
    assert!(!text.contains("c1") && !text.contains("src"), "{text}");
    // 種子
    let file = format!("{{\"domains\":[{}]}}", serde_json::to_string(&e).unwrap());
    let mut db3 = self::db();
    db3.load_domains(file.as_bytes(), true).unwrap();
    assert!(db3.get(name).unwrap().src.is_none());
}
