//! 線路感知（3.5.0，規格 11 E3～E7）：到得了哪些台灣機房、機房以本機為準、機房層級的切換、網段分散、比原本慢就退回。
//! 假的網路、文件用 IP（節點與官方範圍都換成 192.0.2.0/24、198.51.100.0/24、2001:db8::/32）

use super::*;
use crate::cdn::{CrossHint, HintIp, HintKind, Hints};
use crate::explain::Context;
use crate::pools::{cidr, PoolNode};
use crate::util::{intern, now_ms, Num, DAY_MS, HOUR_MS};
use kuroshio_net::iprank::{Latency, Quality};
use kuroshio_net::probe::Timing;

const ORIG: &str = "198.51.100.200";
const SITE: &str = "slow.example.com";

fn setup(over: Value) -> (Arc<Cdn>, Arc<MockNet>) {
    let net = MockNet::new();
    let mut cfg = json!({
        "trialTtl": 10, "v6Policy": "keep",
        "providers": { "cloudflare": { "enabled": true }, "fastly": { "enabled": true } },
        "ecs": { "twSubnets": [] }
    });
    kuroshio_config::merge(&mut cfg, &over);
    let c = cdn_with(cfg, paths_no_seed("line"), net.clone());
    c.with_state(|st| {
        let cf = st.pools.p.get_mut("cloudflare").unwrap();
        cf.pool4 = vec![];
        cf.pool6 = vec![];
        cf.bad.clear();
        cf.range4 = cidr(&["192.0.2.0/24", "198.51.100.0/24"]);
        cf.range6 = cidr(&["2001:db8::/32"]);
        cf.global = cidr(&[]);
        cf.tw = cidr(&[]);
        cf.dead = cidr(&[]);
        cf.tw48 = cidr(&[]);
        let f = st.pools.p.get_mut("fastly").unwrap();
        f.pool4 = vec![];
        f.pool6 = vec![];
        f.bad.clear();
    });
    (c, net)
}

fn node(i: &str, pop: &str, ms: f64) -> PoolNode {
    let mut n = PoolNode::new(ip(i));
    n.ms = Num::V(ms);
    n.pop = Some(intern(pop));
    n
}

fn set_pool(c: &Cdn, p: &str, family: u8, nodes: Vec<PoolNode>) {
    c.with_state(|st| *st.pools.p.get_mut(p).unwrap().pool_mut(family) = nodes);
}

fn pool_ips(c: &Cdn, p: &str, family: u8) -> Vec<String> {
    c.state().pools.p[p].pool(family).iter().map(|x| x.ip.to_string()).collect()
}

fn cf_ok(colo: &str) -> ProbeResult {
    resp(200, &[("cf-ray", &format!("8a-{colo}")), ("server", "cloudflare")], "<html></html>")
}

/// 健檢：每個 IP 回哪個機房（`None` = 連不上）、延遲
fn health_net(net: &MockNet, f: impl Fn(&str) -> Option<(&'static str, f64)> + Send + Sync + Clone + 'static) {
    let g = f.clone();
    net.on_http(move |i, _| match f(&i.to_string()) {
        Some((pop, _)) => cf_ok(pop),
        None => fail("ECONNREFUSED"),
    });
    net.on_ping(move |i| match g(&i.to_string()) {
        Some((_, ms)) => lat(ms),
        None => Latency {
            ok: false,
            ms: f64::INFINITY,
        },
    });
}

fn pools_json(v4: &[(&str, &str)]) -> Vec<u8> {
    let node = |(ip, pop): &(&str, &str)| json!({ "ip": ip, "pop": pop, "ms": 2 });
    serde_json::to_vec(&json!({ "providers": { "cloudflare": {
        "v4": v4.iter().map(node).collect::<Vec<_>>(), "updatedAt": "2026-11-18T05:30:00.000Z"
    } } }))
    .unwrap()
}

fn up_pop(c: &Cdn, i: &str) -> Option<String> {
    let st = c.state();
    let d = &st.pools.p["cloudflare"];
    d.pool4
        .iter()
        .chain(&d.pool6)
        .find(|x| x.ip == ip(i))
        .and_then(|x| x.up_pop().map(String::from))
}

fn pop_of(c: &Cdn, i: &str) -> String {
    let st = c.state();
    st.pools.p["cloudflare"]
        .pool4
        .iter()
        .find(|x| x.ip == ip(i))
        .unwrap()
        .pop_str()
        .to_string()
}

// ============================================================ E3

#[tokio::test]
async fn wan_change_marks_stale_without_probing() {
    let (c, net) = setup(json!({}));
    set_pool(
        &c,
        "cloudflare",
        4,
        vec![node("192.0.2.1", "TPE", 3.0), node("198.51.100.1", "TPE", 4.0)],
    );
    health_net(&net, |_| Some(("TPE", 3.0)));
    c.health_check().await;
    let r = c.observe_json()["reach"].clone();
    assert_eq!((r["stale"].clone(), r["wanEpoch"].clone()), (json!(false), json!(0)));
    assert_eq!(r["v4"]["text"], "這條線目前只到得了台北機房");
    assert_eq!(r["v4"]["pops"][0]["nodes"], 2);
    let before = net.log.lock().unwrap().len();
    c.on_wan_changed();
    assert_eq!(net.log.lock().unwrap().len(), before, "WAN 變動不補任何探測");
    let r = c.observe_json()["reach"].clone();
    assert_eq!((r["stale"].clone(), r["wanEpoch"].clone()), (json!(true), json!(1)));
    assert_eq!(r["v4"]["pops"][0]["nodes"], 2, "沿用最後一次的結果");
    // 下一輪定時健檢自然更新
    c.health_check().await;
    assert_eq!(c.observe_json()["reach"]["stale"], false);
    // 串接中：這台不做健檢，reach 標過期
    c.set_line_env(|| crate::reach::LineEnv {
        chained: true,
        memory_normal: true,
    });
    assert_eq!(c.observe_json()["reach"]["stale"], true);
    assert_eq!(c.status_lite()["reach"]["stale"], true, "/api/status 的 cdn 帶同一份");
}

#[tokio::test]
async fn nearby_reads_pop_view_unchanged() {
    let (c, _) = setup(json!({}));
    let mut a = node("192.0.2.201", "NRT", 30.0);
    a.score = Num::V(30.0);
    let mut b = node("198.51.100.201", "HKG", 40.0);
    b.score = Num::V(40.0);
    set_pool(&c, "fastly", 4, vec![a, b]);
    // reach 只在節點池換過、健檢結束時重算（這裡直接改了節點池，標成換過）
    c.with_state(|st| st.pools.reach_dirty = true);
    let view = c.state().pools.pop_view("fastly");
    let r = c.observe_json()["reach"].clone();
    let nearby = r["nearby"].as_array().unwrap();
    assert_eq!(nearby.len(), view.pops.len());
    for (x, (pop, pfs)) in nearby.iter().zip(&view.pops) {
        assert_eq!((x["provider"].as_str(), x["pop"].as_str()), (Some("fastly"), Some(pop.as_str())));
        assert_eq!(x["prefixes"], pfs.len());
    }
    assert_eq!(c.state().pools.pop_view("fastly").pops, view.pops, "pop_view 不受影響");
    assert_eq!(r["v4"]["pops"], json!([]), "最近節點型不算進台灣機房");
}

// ============================================================ E4

#[test]
fn friend_node_pop_and_ms_never_reach_pool() {
    // 好友分享的節點：只收 IP 當候選（線上格式有 pop、ms，但只有 IP 交給 add_friend_nodes），節點池不變
    let (c, _) = setup(json!({}));
    set_pool(&c, "cloudflare", 4, vec![node("192.0.2.1", "TPE", 3.0)]);
    let before = c.state().pools.p["cloudflare"].pool4.clone();
    assert_eq!(c.add_friend_nodes([("cloudflare", ip("198.51.100.7"))]), 1);
    let st = c.state();
    assert_eq!(st.db.harvest_of("cloudflare", false), ips(&["198.51.100.7"]));
    assert_eq!(st.pools.p["cloudflare"].pool4, before);
    assert!(st.line.reach.v4.pops.iter().all(|p| p.pop != "KHH"));
}

#[test]
fn import_shared_records_up_pop() {
    let (c, _) = setup(json!({}));
    c.import_shared(Some(&pools_json(&[("192.0.2.1", "KHH"), ("198.51.100.1", "TPE")])), None, 48)
        .unwrap();
    assert_eq!(up_pop(&c, "192.0.2.1").as_deref(), Some("KHH"));
    assert_eq!(up_pop(&c, "198.51.100.1").as_deref(), Some("TPE"));
    let o = c.observe_json();
    assert_eq!(o["reach"]["unconfirmed"], 2, "還沒確認的不算到得了");
    assert_eq!(o["reach"]["v4"]["pops"], json!([]));
    assert_eq!(o["popAudit"]["pending"], 2);
    // 存在 pools.json（節點上的 upPop），/api/cdn/pools 也看得到
    let j: Value = serde_json::from_slice(&c.state().pools.to_json()).unwrap();
    assert_eq!(j["providers"]["cloudflare"]["v4"][0]["upPop"], "KHH");
    assert_eq!(c.pools_status()["cloudflare"]["v4"][0]["upPop"], "KHH");
    // 上游帶來的 upPop（上游自己的查核狀態）不收
    let mut v: Value = serde_json::from_slice(&pools_json(&[("192.0.2.9", "TPE")])).unwrap();
    v["providers"]["cloudflare"]["v4"][0]["upPop"] = json!("KHH");
    c.import_shared(Some(&serde_json::to_vec(&v).unwrap()), None, 48).unwrap();
    assert_eq!(up_pop(&c, "192.0.2.9").as_deref(), Some("TPE"));
}

#[test]
fn own_node_with_same_pop_has_no_up_pop() {
    let (c, _) = setup(json!({}));
    set_pool(
        &c,
        "cloudflare",
        4,
        vec![node("192.0.2.1", "TPE", 3.0), node("192.0.2.2", "KHH", 3.0)],
    );
    c.import_shared(
        Some(&pools_json(&[("192.0.2.1", "TPE"), ("192.0.2.2", "TPE"), ("198.51.100.1", "TPE")])),
        None,
        48,
    )
    .unwrap();
    assert_eq!(up_pop(&c, "192.0.2.1"), None, "這台原本就有、機房一樣");
    assert_eq!(up_pop(&c, "192.0.2.2"), None);
    assert_eq!(pop_of(&c, "192.0.2.2"), "KHH", "這台量過、機房不一樣：以本機為準");
    assert_eq!(up_pop(&c, "198.51.100.1").as_deref(), Some("TPE"));
}

#[test]
fn export_shared_strips_up_pop() {
    let (c, _) = setup(json!({}));
    c.import_shared(Some(&pools_json(&[("192.0.2.1", "KHH")])), None, 48).unwrap();
    assert!(up_pop(&c, "192.0.2.1").is_some());
    let e = c.export_shared();
    let j: Value = serde_json::from_slice(&e.pools.unwrap()).unwrap();
    let n = &j["providers"]["cloudflare"]["v4"][0];
    assert_eq!((n["ip"].as_str(), n["pop"].as_str()), (Some("192.0.2.1"), Some("KHH")));
    assert!(n.get("upPop").is_none(), "{n}");
    assert!(up_pop(&c, "192.0.2.1").is_some(), "這台自己的不動");
}

#[tokio::test]
async fn health_check_confirms_or_corrects_up_pop() {
    let (c, net) = setup(json!({}));
    c.import_shared(
        Some(&pools_json(&[
            ("192.0.2.1", "TPE"),
            ("192.0.2.2", "TPE"),
            ("198.51.100.1", "TPE"),
            ("198.51.100.2", "TPE"),
        ])),
        None,
        48,
    )
    .unwrap();
    // 一樣、不一樣但在台灣、不在台灣、連不上（量不到，留著等下一輪）
    health_net(&net, |i| match i {
        "192.0.2.1" => Some(("TPE", 3.0)),
        "192.0.2.2" => Some(("KHH", 5.0)),
        "198.51.100.1" => Some(("HKG", 40.0)),
        _ => None,
    });
    c.health_check().await;
    assert_eq!(up_pop(&c, "192.0.2.1"), None);
    assert_eq!((up_pop(&c, "192.0.2.2"), pop_of(&c, "192.0.2.2")), (None, "KHH".to_string()));
    assert_eq!(up_pop(&c, "198.51.100.1"), None);
    assert_eq!(
        c.state().pools.p["cloudflare"].bad[&ip("198.51.100.1")].reason,
        "POP=HKG",
        "照既有的流程標壞"
    );
    assert_eq!(up_pop(&c, "198.51.100.2").as_deref(), Some("TPE"));
    let k = c.observe_counters();
    assert_eq!((k.pop_confirmed, k.pop_mismatch), (1, 2));
    assert!(k.pop_mismatch_at > 0);
    let o = c.observe_json();
    assert_eq!(o["popAudit"]["pending"], 1);
    assert_eq!(o["popAudit"]["mismatch"], 2);
    let pops: Vec<&str> = o["reach"]["v4"]["pops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["pop"].as_str().unwrap())
        .collect();
    assert_eq!(pops, ["KHH", "TPE"], "用這台量到的");
}

#[tokio::test]
async fn own_v4_pool_is_already_one_per_24() {
    // 釘住現況：節點池工作的結果每個 /24 只留最快的一個（E6 不用再做 IPv4 自己建的節點池）。
    // 順便測 E4：節點池工作在本機量到上游宣稱機房的節點時比對、計數
    let (ctx, net, paths) = super::jobs::ctx_for(
        json!({ "cloudflare": {"enabled": true} }),
        json!({ "pool": { "candidatesPerProvider": 8, "poolSize": 6, "speedTop": 0 } }),
    );
    super::jobs::write(&paths, "scan/cloudflare-ipv4-TW.txt", "192.0.2.0/24\n198.51.100.0/24\n");
    ctx.cdn.with_state(|st| {
        let cf = st.pools.p.get_mut("cloudflare").unwrap();
        cf.range4 = cidr(&["192.0.2.0/24", "198.51.100.0/24"]);
        cf.tw = cidr(&["192.0.2.0/24", "198.51.100.0/24"]);
        cf.pool4.clear();
    });
    ctx.cdn
        .import_shared(Some(&pools_json(&[("192.0.2.1", "KHH"), ("198.51.100.1", "TPE")])), None, 48)
        .unwrap();
    net.on_ping(|i| match i {
        IpAddr::V4(v) => lat(1.0 + v.octets()[3] as f64 / 100.0),
        IpAddr::V6(_) => Latency {
            ok: false,
            ms: f64::INFINITY,
        },
    });
    net.on_http(|_, _| resp(200, &[], "colo=TPE"));
    net.on_quality(|_| Quality {
        ms: 2.0,
        jitter: 0.1,
        loss: 0.0,
        n: 5,
    });
    let r = crate::jobs::pool::run(&ctx).await.unwrap();
    let v4 = &r.providers[0].v4;
    let mut nets: Vec<Option<u32>> = v4.iter().map(|i| crate::util::prefix24(*i)).collect();
    let n = nets.len();
    nets.dedup();
    assert!(n >= 2 && nets.len() == n, "每個 /24 一個：{v4:?}");
    let k = ctx.cdn.observe_counters();
    assert_eq!((k.pop_confirmed, k.pop_mismatch), (1, 1), "本機量到 TPE：KHH 的不一樣、TPE 的一樣");
    assert_eq!(ctx.cdn.observe_json()["popAudit"]["pending"], 0);
}

#[test]
fn chained_pop_probe_uses_audit_slot_and_is_capped() {
    let (c, net) = setup(json!({}));
    c.import_shared(
        Some(&pools_json(&[("192.0.2.1", "KHH"), ("192.0.2.2", "TPE"), ("198.51.100.1", "TPE")])),
        None,
        48,
    )
    .unwrap();
    assert_eq!(c.pop_audit_wanted(ip("192.0.2.1")), Some("cloudflare"));
    assert_eq!(c.pop_audit_wanted(ip("192.0.2.1")), None, "每個節點一次");
    assert_eq!(c.pop_audit_wanted(ip("192.0.2.2")), None, "10 分鐘 1 個");
    assert_eq!(c.pop_audit_wanted(ip("198.51.100.99")), None, "不是等確認的節點");
    assert!(net.log.lock().unwrap().is_empty(), "只回要不要抽查，探測由呼叫端用既有的名額做");
    // 呼叫端量到的機房交回來：以本機為準
    c.note_local_pop("cloudflare", ip("192.0.2.1"), "TPE");
    assert_eq!((up_pop(&c, "192.0.2.1"), pop_of(&c, "192.0.2.1")), (None, "TPE".to_string()));
    let k = c.observe_counters();
    assert_eq!((k.pop_probes, k.pop_mismatch, k.pop_confirmed), (1, 1, 0));
    assert_eq!(c.observe_json()["popAudit"]["probes24h"], 1);
    // 時間過了 10 分鐘：下一個
    c.with_state(|st| st.line.age(crate::reach::AUDIT_GAP_MS));
    assert_eq!(c.pop_audit_wanted(ip("::ffff:192.0.2.2")), Some("cloudflare"), "IPv4-mapped 也認得");
    c.note_local_pop("cloudflare", ip("192.0.2.2"), "TPE");
    assert_eq!(c.observe_counters().pop_confirmed, 1);
    // 量到不是台灣機房：照既有的流程標壞
    c.with_state(|st| st.line.age(crate::reach::AUDIT_GAP_MS));
    assert!(c.pop_audit_wanted(ip("198.51.100.1")).is_some());
    c.note_local_pop("cloudflare", ip("198.51.100.1"), "HKG");
    assert!(c.state().pools.p["cloudflare"].bad.contains_key(&ip("198.51.100.1")));
    // 記憶體壓力、沒對時：不抽查
    c.import_shared(Some(&pools_json(&[("192.0.2.50", "KHH")])), None, 48).unwrap();
    c.with_state(|st| st.line.age(crate::reach::AUDIT_GAP_MS));
    c.set_line_env(|| crate::reach::LineEnv {
        chained: true,
        memory_normal: false,
    });
    assert_eq!(c.pop_audit_wanted(ip("192.0.2.50")), None);
    c.set_line_env(|| crate::reach::LineEnv {
        chained: true,
        memory_normal: true,
    });
    assert_eq!(c.pop_audit_wanted(ip("192.0.2.50")), Some("cloudflare"));
    // 一天的上限
    let (c, _) = setup(json!({}));
    let list: Vec<String> = (1..=40).map(|i| format!("192.0.2.{i}")).collect();
    let pairs: Vec<(&str, &str)> = list.iter().map(|s| (s.as_str(), "TPE")).collect();
    c.import_shared(Some(&pools_json(&pairs)), None, 48).unwrap();
    let mut n = 0;
    for s in &list {
        c.with_state(|st| st.line.age(crate::reach::AUDIT_GAP_MS));
        n += c.pop_audit_wanted(ip(s)).is_some() as usize;
    }
    assert_eq!(n, crate::reach::AUDIT_DAY_MAX);
    // cdn.lite：一天 8 個
    let (c, _) = setup(json!({ "lite": true }));
    c.import_shared(Some(&pools_json(&pairs)), None, 48).unwrap();
    let mut n = 0;
    for s in &list {
        c.with_state(|st| st.line.age(crate::reach::AUDIT_GAP_LITE_MS));
        n += c.pop_audit_wanted(ip(s)).is_some() as usize;
    }
    assert_eq!(n, crate::reach::AUDIT_DAY_MAX_LITE);
}

#[test]
fn pop_audit_off_matches_previous_behaviour() {
    let (c, net) = setup(json!({ "popAudit": false }));
    c.import_shared(Some(&pools_json(&[("192.0.2.1", "KHH")])), None, 48).unwrap();
    assert_eq!(up_pop(&c, "192.0.2.1"), None, "不記上游宣稱的機房");
    assert_eq!(pop_of(&c, "192.0.2.1"), "KHH", "照收上游的（3.4.x）");
    assert_eq!(c.pop_audit_wanted(ip("192.0.2.1")), None);
    assert!(net.log.lock().unwrap().is_empty());
    let o = c.observe_json();
    assert_eq!(o["popAudit"]["enabled"], false);
    assert_eq!(o["reach"]["v4"]["pops"][0]["pop"], "KHH");
}

#[test]
fn mismatch_never_counts_as_audit_suspicious() {
    // 機房不一樣是線路拓樸，不是上游不可信：節點留在池裡、不標壞、不解除串接（CDN 這一層沒有任何可疑計數會動）
    let (c, _) = setup(json!({}));
    let list: Vec<String> = (1..=6).map(|i| format!("192.0.2.{i}")).collect();
    let pairs: Vec<(&str, &str)> = list.iter().map(|s| (s.as_str(), "KHH")).collect();
    c.import_shared(Some(&pools_json(&pairs)), None, 48).unwrap();
    for s in &list {
        c.note_local_pop("cloudflare", ip(s), "TPE");
    }
    let st = c.state();
    let d = &st.pools.p["cloudflare"];
    assert_eq!(d.pool4.len(), 6);
    assert!(d.bad.is_empty());
    drop(st);
    let o = c.observe_json();
    assert_eq!(o["popAudit"]["mismatch"], 6);
    assert_eq!(o["popAudit"]["chainPopUnreliable"], true, "多數不一致：機房切換暫停");
    assert_eq!(o["popSwitch"]["reason"], "chain-pop-unreliable");
    c.with_state(|st| st.line.age(DAY_MS));
    assert_eq!(
        c.observe_json()["popAudit"]["chainPopUnreliable"],
        false,
        "24 小時沒有新的不一致：自己解除"
    );
}

// ============================================================ E5

/// 到得了台北、高雄兩個機房的線路：TPE 三個節點、KHH 兩個節點（各分在兩個 /24）
fn two_pop(c: &Cdn) {
    set_pool(
        c,
        "cloudflare",
        4,
        vec![
            node("192.0.2.1", "TPE", 3.0),
            node("198.51.100.1", "TPE", 3.0),
            node("192.0.2.2", "TPE", 3.0),
            node("192.0.2.101", "KHH", 8.0),
            node("198.51.100.101", "KHH", 8.0),
        ],
    );
}

/// TPE 的 192.0.2.2 連不上（失敗率 33%）；`khh_bad` 時 KHH 也壞一個；`khh_ms` 是 KHH 的延遲
fn degraded_net(net: &MockNet, khh_bad: bool, khh_ms: f64) {
    health_net(net, move |i| match i {
        "192.0.2.2" => None,
        "198.51.100.101" if khh_bad => None,
        "192.0.2.101" | "198.51.100.101" => Some(("KHH", khh_ms)),
        _ => Some(("TPE", 3.0)),
    });
}

async fn rounds(c: &Arc<Cdn>, n: usize) {
    for _ in 0..n {
        c.health_check().await;
    }
}

fn held(c: &Cdn) -> Value {
    c.observe_json()["popSwitch"]["holds"].clone()
}

#[tokio::test]
async fn hold_after_three_bad_rounds_when_other_pop_clean() {
    let (c, net) = setup(json!({}));
    two_pop(&c);
    degraded_net(&net, false, 8.0);
    rounds(&c, 2).await;
    assert_eq!(held(&c), json!([]), "兩輪還不夠");
    let o = c.observe_json();
    assert_eq!(o["popSwitch"]["eligibleFamilies"], json!([4]), "頭兩輪判斷資格：到得了兩個機房");
    rounds(&c, 1).await;
    let h = held(&c);
    assert_eq!(h[0]["pop"], "TPE", "{h}");
    assert_eq!(h[0]["other"], "KHH");
    let until = h[0]["until"].as_u64().unwrap();
    assert!(until > now_ms() + 4 * HOUR_MS - 60_000 && until <= now_ms() + 4 * HOUR_MS);
    let k = c.observe_counters();
    assert_eq!(k.pop_switches, 1);
    assert!(k.pop_switch_at > 0);
    let ph = c.observe_json()["popHealth"].clone();
    let tpe = ph.as_array().unwrap().iter().find(|x| x["pop"] == "TPE").unwrap().clone();
    assert_eq!(
        (tpe["held"].clone(), tpe["nodes"].clone(), tpe["bad"].clone()),
        (json!(true), json!(3), json!(1))
    );
}

#[tokio::test]
async fn held_nodes_sort_after_healthy_before_bad_and_still_serve_when_short() {
    let (c, net) = setup(json!({}));
    two_pop(&c);
    degraded_net(&net, false, 8.0);
    rounds(&c, 3).await;
    assert_eq!(
        pool_ips(&c, "cloudflare", 4),
        ["192.0.2.101", "198.51.100.101", "192.0.2.1", "198.51.100.1", "192.0.2.2"],
        "高雄 → 暫緩的台北 → 壞的"
    );
    // 其他機房的可用節點不到 serveCount（4）個：照樣往後取到暫緩的節點，不會沒有節點可回
    assert_eq!(
        c.state().pools.serve_ips("cloudflare", 4),
        ips(&["192.0.2.101", "198.51.100.101", "192.0.2.1", "198.51.100.1"])
    );
    assert!(c.state().pools.p["cloudflare"].pool4.len() == 5, "不移出節點池");
}

#[tokio::test]
async fn single_pop_line_never_holds() {
    let (c, net) = setup(json!({}));
    set_pool(
        &c,
        "cloudflare",
        4,
        vec![
            node("192.0.2.1", "TPE", 3.0),
            node("198.51.100.1", "TPE", 3.0),
            node("192.0.2.2", "TPE", 3.0),
            node("198.51.100.2", "TPE", 3.0),
        ],
    );
    // 一半連不上，再差也不暫緩（沒有別的機房可以換）
    health_net(&net, |i| if i.ends_with(".2") { None } else { Some(("TPE", 3.0)) });
    rounds(&c, 6).await;
    let o = c.observe_json();
    assert_eq!(o["popSwitch"]["holds"], json!([]));
    assert_eq!(o["popSwitch"]["reason"], "single-pop");
    assert_eq!(o["popHealth"][0]["badStreak"], 6, "照樣彙總");
    assert_eq!(c.observe_counters().pop_switches, 0);
}

#[tokio::test]
async fn no_hold_when_other_pop_also_bad() {
    let (c, net) = setup(json!({}));
    two_pop(&c);
    degraded_net(&net, true, 8.0);
    rounds(&c, 5).await;
    assert_eq!(held(&c), json!([]));
}

#[tokio::test]
async fn no_hold_when_other_pop_too_far() {
    let (c, net) = setup(json!({}));
    two_pop(&c);
    // 高雄比台北的可用節點慢 20 毫秒以上
    degraded_net(&net, false, 24.0);
    rounds(&c, 5).await;
    assert_eq!(held(&c), json!([]));
}

#[tokio::test]
async fn hold_expires_after_4h_and_needs_three_new_rounds() {
    let (c, net) = setup(json!({}));
    two_pop(&c);
    degraded_net(&net, false, 8.0);
    rounds(&c, 3).await;
    assert_eq!(held(&c)[0]["pop"], "TPE");
    rounds(&c, 1).await;
    assert_eq!(held(&c)[0]["pop"], "TPE", "不提早結束");
    c.with_state(|st| st.line.age(crate::reach::POP_HOLD_MS));
    rounds(&c, 1).await;
    assert_eq!(held(&c), json!([]), "4 小時到期");
    assert_eq!(pool_ips(&c, "cloudflare", 4)[0], "192.0.2.1", "回到依延遲的排序");
    rounds(&c, 2).await;
    assert_eq!(held(&c), json!([]), "要重新連續 3 輪");
    rounds(&c, 1).await;
    assert_eq!(held(&c)[0]["pop"], "TPE");
    assert_eq!(c.observe_counters().pop_switches, 2);
}

#[tokio::test]
async fn hold_cancelled_when_other_pop_degrades() {
    let (c, net) = setup(json!({}));
    two_pop(&c);
    degraded_net(&net, false, 8.0);
    rounds(&c, 3).await;
    assert_eq!(held(&c)[0]["pop"], "TPE");
    degraded_net(&net, true, 8.0);
    rounds(&c, 1).await;
    assert_eq!(held(&c), json!([]), "兩邊都差：立刻取消");
    assert_eq!(
        pool_ips(&c, "cloudflare", 4)[..2],
        ["192.0.2.1", "198.51.100.1"],
        "回到節點層級的排序"
    );
}

#[tokio::test]
async fn at_most_two_holds_per_day_then_flapping_finding() {
    let (c, net) = setup(json!({}));
    two_pop(&c);
    degraded_net(&net, false, 8.0);
    for _ in 0..2 {
        rounds(&c, 3).await;
        assert_eq!(held(&c)[0]["pop"], "TPE");
        c.with_state(|st| st.line.age(crate::reach::POP_HOLD_MS));
        rounds(&c, 1).await;
        assert_eq!(held(&c), json!([]));
    }
    // 24 小時內第 3 次：不切，只報
    rounds(&c, 3).await;
    assert_eq!(held(&c), json!([]));
    let k = c.observe_counters();
    assert_eq!((k.pop_switches, k.pop_flapping), (2, 1));
    assert!(k.pop_flapping_at > 0);
    assert_eq!(c.observe_json()["popSwitch"]["switches24h"], 2);
    // 一天之後又可以
    c.with_state(|st| st.line.age(DAY_MS));
    rounds(&c, 3).await;
    assert_eq!(held(&c)[0]["pop"], "TPE");
}

#[tokio::test]
async fn wan_change_clears_streaks_and_holds() {
    let (c, net) = setup(json!({}));
    two_pop(&c);
    degraded_net(&net, false, 8.0);
    rounds(&c, 3).await;
    assert_eq!(held(&c)[0]["pop"], "TPE");
    c.on_wan_changed();
    let o = c.observe_json();
    assert_eq!(o["popSwitch"]["holds"], json!([]));
    assert_eq!(o["popSwitch"]["eligibleFamilies"], json!([]), "資格重新判斷");
    assert!(o["popHealth"].as_array().unwrap().iter().all(|h| h["badStreak"] == 0));
    // 資格要再兩輪、變差要再三輪
    rounds(&c, 2).await;
    assert_eq!(held(&c), json!([]));
    rounds(&c, 1).await;
    assert_eq!(held(&c)[0]["pop"], "TPE");
}

#[tokio::test]
async fn pop_switch_off_only_aggregates() {
    let (c, net) = setup(json!({ "popSwitch": false }));
    two_pop(&c);
    degraded_net(&net, false, 8.0);
    rounds(&c, 5).await;
    let o = c.observe_json();
    assert_eq!(o["popSwitch"]["holds"], json!([]));
    assert_eq!(
        (o["popSwitch"]["enabled"].clone(), o["popSwitch"]["reason"].clone()),
        (json!(false), json!("disabled"))
    );
    assert_eq!(o["popHealth"].as_array().unwrap().len(), 2);
    assert_eq!(pool_ips(&c, "cloudflare", 4)[..2], ["192.0.2.1", "198.51.100.1"]);
    // 記憶體壓力、串接中也一樣不切
    for (env, why) in [((false, false), "memory"), ((true, true), "chained")] {
        let (c, net) = setup(json!({}));
        c.set_line_env(move || crate::reach::LineEnv {
            chained: env.0,
            memory_normal: env.1,
        });
        two_pop(&c);
        degraded_net(&net, false, 8.0);
        rounds(&c, 5).await;
        assert_eq!(held(&c), json!([]));
        assert_eq!(c.observe_json()["popSwitch"]["reason"], why);
    }
}

#[tokio::test]
async fn domain_verify_failures_do_not_count_against_pop() {
    // 網域驗證的失敗（mark_bad）不算進機房：下一輪健檢量到正常就是 0
    let (c, net) = setup(json!({}));
    two_pop(&c);
    health_net(&net, |i| Some((if i.ends_with(".101") { "KHH" } else { "TPE" }, 3.0)));
    for _ in 0..4 {
        c.with_state(|st| {
            st.pools.mark_bad("cloudflare", ip("192.0.2.1"), "驗證 x.example.com 時 ECONNRESET");
            st.pools
                .mark_bad("cloudflare", ip("198.51.100.1"), "驗證 x.example.com 時 ECONNRESET");
        });
        c.health_check().await;
    }
    let o = c.observe_json();
    assert_eq!(held(&c), json!([]));
    let tpe = o["popHealth"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["pop"] == "TPE")
        .unwrap()
        .clone();
    assert_eq!((tpe["bad"].clone(), tpe["badStreak"].clone()), (json!(0), json!(0)));
}

/// 最近節點型（Fastly）的節點池：前兩名同一個 /24
fn fastly_pool() -> Vec<PoolNode> {
    let mk = |i: &str, pop: &str, sc: f64| {
        let mut n = node(i, pop, sc);
        n.score = Num::V(sc);
        n
    };
    vec![
        mk("192.0.2.201", "NRT", 30.0),
        mk("192.0.2.202", "NRT", 31.0),
        mk("198.51.100.201", "HKG", 32.0),
        mk("198.51.100.202", "HKG", 60.0),
    ]
}

fn fastly_net(net: &MockNet) {
    net.on_http(|i, _| {
        let pop = if i.to_string().starts_with("192.0.2.") { "NRT" } else { "HKG" };
        resp(
            200,
            &[
                ("x-served-by", &format!("cache-{}1234-{pop}", pop.to_lowercase())),
                ("x-cache", "HIT"),
            ],
            "",
        )
    });
    net.on_ping(|_| lat(30.0));
    net.on_quality(|i| Quality {
        ms: if i.to_string().ends_with(".202") { 50.0 } else { 30.0 },
        jitter: 0.0,
        loss: 0.0,
        n: 3,
    });
}

async fn fastly_after(over: Value, quality: bool) -> (Vec<String>, Vec<(String, Vec<u32>)>, Value) {
    let (c, net) = setup(over);
    set_pool(&c, "fastly", 4, fastly_pool());
    fastly_net(&net);
    for _ in 0..4 {
        c.health_check().await;
        if quality {
            c.quality_check().await;
        }
    }
    let view = c.state().pools.pop_view("fastly").pops.clone();
    (pool_ips(&c, "fastly", 4), view, c.observe_json())
}

#[tokio::test]
async fn nearest_provider_untouched() {
    // Fastly（最近節點型）的 pop_view()、keep_pop() 結果跟沒有 E5／E6 時一樣
    let on = fastly_after(json!({}), true).await;
    let off = fastly_after(json!({ "popSwitch": false, "spreadPrefixes": false }), true).await;
    assert_eq!((&on.0, &on.1), (&off.0, &off.1));
    assert!(!on.1.is_empty());
    assert!(on.2["popHealth"].as_array().unwrap().iter().all(|h| h["provider"] != "fastly"));
    assert_eq!(
        on.2["popSwitch"]["excluded"],
        json!([{ "provider": "fastly", "reason": "nearest-provider" }])
    );
}

#[tokio::test]
async fn fastly_not_spread() {
    // 前兩名同一個 /24：最近節點型不套用網段分散（它的網段選擇在 PopView／map_ips）
    let (on, ..) = fastly_after(json!({}), false).await;
    let (off, ..) = fastly_after(json!({ "spreadPrefixes": false }), false).await;
    assert_eq!(on, off);
    assert_eq!(on[..2], ["192.0.2.201", "192.0.2.202"]);
}

// ============================================================ E6

#[tokio::test]
async fn spread_after_merge_shared_same_24() {
    // 串接：上游的節點與這台原本的同網段，健檢之後前幾名分散
    let (c, net) = setup(json!({ "providers": { "cloudflare": { "serveCount": 2 } } }));
    set_pool(
        &c,
        "cloudflare",
        4,
        vec![node("192.0.2.2", "TPE", 3.0), node("198.51.100.1", "TPE", 6.0)],
    );
    c.import_shared(Some(&pools_json(&[("192.0.2.1", "TPE")])), None, 48).unwrap();
    health_net(&net, |i| {
        Some((
            "TPE",
            match i {
                "192.0.2.1" => 3.0,
                "192.0.2.2" => 3.1,
                _ => 6.0,
            },
        ))
    });
    c.health_check().await;
    assert_eq!(c.state().pools.serve_ips("cloudflare", 4), ips(&["192.0.2.1", "198.51.100.1"]));
    // 開關關掉：照延遲
    let (c, net) = setup(json!({ "spreadPrefixes": false, "providers": { "cloudflare": { "serveCount": 2 } } }));
    set_pool(
        &c,
        "cloudflare",
        4,
        vec![node("192.0.2.2", "TPE", 3.0), node("198.51.100.1", "TPE", 6.0)],
    );
    c.import_shared(Some(&pools_json(&[("192.0.2.1", "TPE")])), None, 48).unwrap();
    health_net(&net, |i| Some(("TPE", if i == "198.51.100.1" { 6.0 } else { 3.0 })));
    c.health_check().await;
    assert_eq!(c.state().pools.serve_ips("cloudflare", 4), ips(&["192.0.2.1", "192.0.2.2"]));
}

#[tokio::test]
async fn spread_off_keeps_latency_order() {
    let v6 = |c: &Cdn| {
        set_pool(
            c,
            "cloudflare",
            6,
            vec![
                node("2001:db8:1::1", "TPE", 2.0),
                node("2001:db8:1::2", "TPE", 2.0),
                node("2001:db8:1::3", "TPE", 2.0),
                node("2001:db8:2::1", "TPE", 2.0),
            ],
        );
    };
    let lat_of = |i: &str| match i {
        "2001:db8:1::1" => 2.0,
        "2001:db8:1::2" => 2.1,
        "2001:db8:1::3" => 2.2,
        _ => 2.5,
    };
    for (spread, want) in [
        (true, ["2001:db8:1::1", "2001:db8:2::1", "2001:db8:1::2", "2001:db8:1::3"]),
        (false, ["2001:db8:1::1", "2001:db8:1::2", "2001:db8:1::3", "2001:db8:2::1"]),
    ] {
        let (c, net) = setup(json!({ "spreadPrefixes": spread }));
        *net.v6.lock().unwrap() = Some(true);
        v6(&c);
        health_net(&net, move |i| Some(("TPE", lat_of(i))));
        c.health_check().await;
        assert_eq!(pool_ips(&c, "cloudflare", 6), want, "spreadPrefixes = {spread}");
    }
}

// ============================================================ E7

/// 同一個網站的回應，帶分段時間（連線＋握手＋TTFB ≈ `ms`）
fn page(colo: &str, ms: f64) -> ProbeResult {
    let mut r = cf_ok(colo);
    r.timing = Timing {
        connect_ms: ms * 0.25,
        tls_ms: ms * 0.25,
        ttfb_ms: ms * 0.5,
    };
    r
}

/// 原站（`ORIG`）與台灣節點（192.0.2.1、198.51.100.1）的請求時間；每個 IP 依序回清單裡的值（最後一個重複）
fn e7(over: Value, orig: Vec<f64>, tw: Vec<f64>) -> (Arc<Cdn>, Arc<MockNet>) {
    let (c, net) = setup(over);
    set_pool(
        &c,
        "cloudflare",
        4,
        vec![node("192.0.2.1", "TPE", 3.0), node("198.51.100.1", "TPE", 4.0)],
    );
    c.with_state(|st| {
        st.db.touch(SITE, "cloudflare", "ip", &ips(&[ORIG]), &[], None);
    });
    set_times(&net, orig, tw);
    (c, net)
}

fn set_times(net: &MockNet, orig: Vec<f64>, tw: Vec<f64>) {
    let seq: Arc<Mutex<HashMap<IpAddr, Vec<f64>>>> = Arc::new(Mutex::new(HashMap::new()));
    seq.lock().unwrap().insert(ip(ORIG), orig);
    seq.lock().unwrap().insert(ip("192.0.2.1"), tw.clone());
    seq.lock().unwrap().insert(ip("198.51.100.1"), tw);
    net.on_https(move |i, _| {
        let mut m = seq.lock().unwrap();
        let Some(l) = m.get_mut(&i) else { return fail("ECONNREFUSED") };
        let ms = if l.len() > 1 { l.remove(0) } else { l[0] };
        page(if i == ip(ORIG) { "NRT" } else { "TPE" }, ms)
    });
}

async fn verify(c: &Arc<Cdn>) -> Option<&'static str> {
    c.verify(SITE, "cloudflare", 4, Some(ip(ORIG))).await
}

fn v4(c: &Cdn) -> crate::db::Verdict {
    c.state().db.get(SITE).unwrap().v4.as_deref().cloned().unwrap()
}

fn is_slower(v: &crate::db::Verdict) -> bool {
    v.extra.get("slower") == Some(&json!(true))
}

#[tokio::test]
async fn slower_needs_ratio_and_abs_and_second_sample() {
    // 第一次慢（200 > 100 × 1.5 + 30）、複測不慢（150）→ 照常換；兩邊各多一條連線
    let (c, net) = e7(json!({}), vec![100.0], vec![200.0, 150.0]);
    assert_eq!(verify(&c).await, Some("ok"));
    assert!(!is_slower(&v4(&c)));
    assert_eq!(net.calls(&format!("https {ORIG}")).len(), 2);
    assert_eq!(net.calls("https 192.0.2.1").len(), 2);
    // 在 1.5 倍＋30 毫秒以內：不複測
    let (c, net) = e7(json!({}), vec![100.0], vec![180.0]);
    assert_eq!(verify(&c).await, Some("ok"));
    assert_eq!(net.calls("https 192.0.2.1").len(), 1);
    // 倍數很大但絕對差不到 30 毫秒（快線路上的小差異）：不算
    let (c, _) = e7(json!({}), vec![10.0], vec![40.0]);
    assert_eq!(verify(&c).await, Some("ok"));
    // 兩次都慢：判「比原本慢」
    let (c, net) = e7(json!({}), vec![100.0], vec![250.0]);
    assert_eq!(verify(&c).await, Some("fail"));
    assert!(is_slower(&v4(&c)));
    assert_eq!(net.calls("https 198.51.100.1").len(), 0, "判慢之後其餘候選不必再確認");
}

#[tokio::test]
async fn slower_verdict_serves_original_and_retests_in_6h() {
    let (c, _) = e7(json!({}), vec![100.0], vec![250.0]);
    assert_eq!(verify(&c).await, Some("fail"));
    let v = v4(&c);
    assert_eq!(v.reason.as_deref(), Some("台灣節點實測比原本慢（250 毫秒對 100 毫秒）"));
    assert_eq!(
        (v.extra.get("score"), v.extra.get("origScore")),
        (Some(&json!(250.0)), Some(&json!(100.0)))
    );
    let until = v.until.unwrap();
    assert!(
        until > now_ms() + 6 * HOUR_MS - 60_000 && until <= now_ms() + 6 * HOUR_MS,
        "6 小時後重測（不走逐次拉長）"
    );
    // 查詢路徑走既有的「驗證失敗 → 原始」
    let mut m = msg(SITE, 1, &[ORIG], vec![]);
    let r = c.apply(&mut m, SITE, 1);
    assert_eq!(answer_ips(&m, 1), [ORIG]);
    assert!(r.tags.iter().any(|t| t.contains("驗證失敗→原始")), "{:?}", r.tags);
    assert!(
        c.take_tasks()
            .iter()
            .all(|t| !matches!(t, crate::cdn::Task::Verify { .. } | crate::cdn::Task::Cross { .. })),
        "不重驗、不排跨 CDN"
    );
    let k = c.observe_counters();
    assert_eq!((k.slower_fallback, k.verify_ok, k.verify_fail), (1, 0, 0));
    assert!(k.slower_fallback_at > 0);
    assert_eq!(c.stats().slower_fallback, 1);
    assert_eq!(c.stats().src_invalidated, 0, "不算來源變動");
}

#[tokio::test]
async fn slower_does_not_mark_node_bad_or_bump_fails() {
    let (c, _) = e7(json!({}), vec![100.0], vec![250.0]);
    c.with_state(|st| st.db.set_verdict(SITE, 4, |v| v.fails = Some(2)));
    assert_eq!(verify(&c).await, Some("fail"));
    assert_eq!(v4(&c).fails, Some(2), "失敗次數不加");
    let st = c.state();
    assert!(st.pools.p["cloudflare"].bad.is_empty(), "節點沒有壞");
    assert!(st.pools.zone_hit("cloudflare", ip("192.0.2.1")), "這個節點服務得了這個網站");
}

#[tokio::test]
async fn slower_hysteresis_needs_1_2x_to_return() {
    let (c, net) = e7(json!({}), vec![100.0], vec![250.0]);
    assert_eq!(verify(&c).await, Some("fail"));
    // 160：沒有超過 1.5 倍＋30，但上一次是慢的 → 要 ≤ 1.2 倍＋30（150）才換回來
    set_times(&net, vec![100.0], vec![160.0]);
    assert_eq!(verify(&c).await, Some("fail"));
    assert!(is_slower(&v4(&c)));
    set_times(&net, vec![100.0], vec![140.0]);
    assert_eq!(verify(&c).await, Some("ok"));
    let v = v4(&c);
    assert!(!is_slower(&v) && v.extra.get("score").is_none(), "換回來之後拿掉");
}

#[tokio::test]
async fn slower_skipped_for_v6_nearest_policy_always_and_unmeasured() {
    // 手動「一定換」
    let (c, _) = e7(json!({}), vec![100.0], vec![250.0]);
    c.set_policy(SITE, "always");
    assert_eq!(verify(&c).await, Some("ok"));
    // 沒量到分段時間
    let (c, net) = e7(json!({}), vec![100.0], vec![250.0]);
    net.on_https(|i, _| cf_ok(if i == ip(ORIG) { "NRT" } else { "TPE" }));
    assert_eq!(verify(&c).await, Some("ok"));
    // IPv6
    let (c, net) = setup(json!({}));
    set_pool(&c, "cloudflare", 6, vec![node("2001:db8:1::1", "TPE", 3.0)]);
    c.with_state(|st| {
        st.db.touch(SITE, "cloudflare", "ip", &[], &ips(&["2001:db8:9::1"]), None);
    });
    net.on_https(|i, _| page("TPE", if i == ip("2001:db8:9::1") { 100.0 } else { 250.0 }));
    assert_eq!(c.verify(SITE, "cloudflare", 6, Some(ip("2001:db8:9::1"))).await, Some("ok"));
    // 最近節點型（Fastly）
    let r = page("NRT", 250.0);
    let base = page("HKG", 100.0);
    assert_eq!(
        c.slower_check(
            SITE,
            "fastly",
            4,
            Some(ip(ORIG)),
            ip("192.0.2.1"),
            false,
            Some(&base),
            &r,
            false,
            false
        )
        .await,
        None
    );
    assert!(c
        .slower_check(
            SITE,
            "cloudflare",
            4,
            Some(ip(ORIG)),
            ip("192.0.2.1"),
            false,
            Some(&base),
            &r,
            false,
            false
        )
        .await
        .is_some());
}

#[tokio::test]
async fn slower_fuse_trips_above_30_percent_and_recovers() {
    let (c, net) = e7(json!({}), vec![100.0], vec![250.0]);
    let names: Vec<String> = (0..12).map(|i| format!("s{i}.example.com")).collect();
    c.with_state(|st| {
        for n in &names {
            st.db.touch(n, "cloudflare", "ip", &ips(&[ORIG]), &[], None);
        }
    });
    let mut got = Vec::new();
    for n in &names {
        got.push(c.verify(n, "cloudflare", 4, Some(ip(ORIG))).await.unwrap());
    }
    // 第 10 次跳保險絲（那一次也照驗證通過處理），之後 6 小時內不判
    assert_eq!(got.iter().filter(|r| **r == "fail").count(), 9, "{got:?}");
    assert_eq!(&got[9..], ["ok", "ok", "ok"]);
    let k = c.observe_counters();
    assert!(k.slower_fuse_until > k.slower_fallback_at);
    assert!(c.observe_json()["slowerFuseUntil"].as_u64().unwrap() > now_ms());
    // 保險絲期間連複測都不做
    let before = net.calls("https 192.0.2.1").len();
    assert_eq!(verify(&c).await, Some("ok"));
    assert_eq!(net.calls("https 192.0.2.1").len(), before + 1);
    // 6 小時後恢復
    c.with_state(|st| st.line.age(crate::reach::FUSE_MS));
    assert!(c.observe_json().get("slowerFuseUntil").is_none());
    assert_eq!(c.observe_counters().slower_fuse_until, 0);
    assert_eq!(c.verify(&names[0], "cloudflare", 4, Some(ip(ORIG))).await, Some("fail"));
}

#[tokio::test]
async fn slower_off_matches_previous_behaviour() {
    let (c, net) = e7(json!({ "slowerFallback": false }), vec![100.0], vec![250.0]);
    assert_eq!(verify(&c).await, Some("ok"));
    assert_eq!(net.calls("https 192.0.2.1").len(), 1, "不複測");
    let v = v4(&c);
    assert!(v.extra.is_empty());
    assert_eq!(v.ips, Some(ips(&["192.0.2.1", "198.51.100.1"])));
    assert_eq!(c.observe_counters().verify_ok, 1);
}

#[tokio::test]
async fn explain_reports_slower() {
    let (c, _) = e7(json!({}), vec![100.0], vec![250.0]);
    assert_eq!(verify(&c).await, Some("fail"));
    let v = c.explain(SITE, Context::default());
    assert_eq!(v["decision"], "slower", "{v}");
    assert_eq!(
        v["text"],
        "這個網域用 Cloudflare，台灣節點能用，但實測比原本的答案慢（250 對 100 毫秒），暫時用原本的答案；到期後重測。"
    );
    assert_eq!(v["steps"][0]["slower"], true);
    assert_eq!(
        (v["steps"][0]["score"].clone(), v["steps"][0]["origScore"].clone()),
        (json!(250.0), json!(100.0))
    );
    // /api/cdn/domain 也看得到
    assert_eq!(c.domain(SITE).unwrap()["v4"]["slower"], true);
}

struct OneHint(Mutex<Vec<(String, bool)>>);

impl Hints for OneHint {
    fn domain_hint(&self, _n: &str, _p: &str, _f: u8) -> Vec<HintIp> {
        vec![HintIp {
            ip: ip("198.51.100.1"),
            from: "friend".into(),
        }]
    }
    fn hint_result(&self, from: &str, _k: HintKind, ok: bool) {
        self.0.lock().unwrap().push((from.into(), ok));
    }
    fn cross_hint(&self, _n: &str) -> Option<CrossHint> {
        None
    }
}

#[tokio::test]
async fn slower_never_reports_friend_hint_failure() {
    let (c, _) = e7(json!({}), vec![100.0], vec![250.0]);
    let h = Arc::new(OneHint(Mutex::new(Vec::new())));
    c.set_hints(Some(h.clone()));
    assert_eq!(verify(&c).await, Some("fail"));
    assert!(is_slower(&v4(&c)));
    assert_eq!(
        h.0.lock().unwrap().as_slice(),
        [("friend".to_string(), true)],
        "好友給的節點服務得了這個網站"
    );
}

#[tokio::test]
async fn observe_json_shape() {
    let (c, net) = setup(json!({}));
    two_pop(&c);
    health_net(&net, |i| Some((if i.ends_with(".101") { "KHH" } else { "TPE" }, 3.0)));
    rounds(&c, 2).await;
    let o = c.observe_json();
    for k in ["reach", "popHealth", "popSwitch", "popAudit"] {
        assert!(o.get(k).is_some(), "{k}");
    }
    assert!(o.get("slowerFuseUntil").is_none(), "跳了才有");
    assert_eq!(o["reach"]["v4"]["text"], "這條線目前到得了台北、高雄機房");
    assert_eq!(o["reach"]["v4"]["multi"], true);
    assert_eq!(o["popSwitch"]["reason"], "ok");
    assert_eq!(o["popSwitch"]["eligible"], true);
    let s = c.status_lite();
    assert_eq!(s["reach"], o["reach"]);
    assert_eq!(s["stats"]["verifyOk"], 0);
    assert_eq!(c.reach_json(), o["reach"]);
}
