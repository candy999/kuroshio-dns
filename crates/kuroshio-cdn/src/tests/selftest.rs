//! 移植 2.x `legacy-node/test/selftest.js` 的 CDN 相關測試（名稱照抄，方便對照）

use super::*;
use crate::cdn::Task;
use crate::db::{Cross, Ecs, Policy, Verdict};
use crate::pools::{cidr, PoolNode};
use crate::svcb;
use crate::util::{intern, now_ms, Num};
use crate::Rewrite;
use kuroshio_proto::message::RData;

fn node(ipx: &str, ms: f64) -> PoolNode {
    let mut n = PoolNode::new(ip(ipx));
    n.ms = Num::V(ms);
    n
}

fn fnode(ipx: &str, pop: &str, ms: f64, jitter: f64, score: f64, speed: Option<f64>) -> PoolNode {
    let mut n = node(ipx, ms);
    n.pop = Some(intern(pop));
    n.jitter = Num::V(jitter);
    n.loss = Num::V(0.0);
    n.score = Num::V(score);
    if let Some(s) = speed {
        n.speed = Num::V(s);
    }
    n
}

pub fn base_cfg() -> Value {
    json!({
        "enabled": true, "trialTtl": 10, "v6Policy": "drop",
        "providers": {
            "cloudflare": { "enabled": true, "seedV4": ["104.16.161.36", "104.18.20.216"] },
            "akamai": { "enabled": true, "ecs": true },
            "fastly": { "enabled": true }
        },
        "ecs": { "twSubnets": [] }
    })
}

/// 同 2.x selftest 的 `opt`：Cloudflare 節點池與範圍固定，測試不受本機 state/ 影響
pub fn setup(over: Value) -> (Arc<Cdn>, Arc<MockNet>) {
    let net = MockNet::new();
    let mut cfg = base_cfg();
    kuroshio_config::merge(&mut cfg, &over);
    let c = cdn_with(cfg, paths_no_seed("selftest"), net.clone());
    c.with_state(|st| {
        let cf = st.pools.p.get_mut("cloudflare").unwrap();
        cf.pool4 = vec![node("104.16.161.36", 3.0), node("104.18.20.216", 4.0)];
        cf.pool6 = vec![];
        cf.bad.clear();
        cf.global = cidr(&["104.21.0.0/24", "172.67.0.0/24"]);
        cf.tw = cidr(&["104.16.161.0/24"]);
        cf.range4 = cidr(&["104.16.0.0/13", "172.64.0.0/13"]);
        cf.range6 = cidr(&["2606:4700::/32"]);
        let f = st.pools.p.get_mut("fastly").unwrap();
        f.pool4 = vec![];
        f.bad.clear();
    });
    (c, net)
}

fn verify_tasks(t: &[Task]) -> Vec<(String, String, u8, Option<IpAddr>)> {
    t.iter()
        .filter_map(|t| match t {
            Task::Verify {
                name,
                provider,
                family,
                orig,
            } => Some((name.clone(), provider.clone(), *family, *orig)),
            _ => None,
        })
        .collect()
}

fn set_ok(c: &Cdn, name: &str, fam: u8, ipx: &str, list: &[&str]) {
    c.with_state(|st| {
        if st.db.get(name).is_none() {
            st.db.touch(name, "cloudflare", "ip", &[], &[], None);
        }
        st.db.set_verdict(name, fam, |v| {
            v.verdict = Some(intern("ok"));
            v.until = Some(now_ms() + 3_600_000);
            v.ip = Some(ip(ipx));
            if !list.is_empty() {
                v.ips = Some(ips(list));
            }
        })
    });
}

fn https_rec(name: &str, v4: &[&str], v6: bool) -> Message {
    let mut m = Message::default();
    m.answers.push(Record {
        name: name.into(),
        rtype: 65,
        class: 1,
        ttl: 300,
        data: RData::Raw(svcb::build_test_rdata(v4, v6)),
    });
    m
}

fn hints_of(m: &Message) -> (Vec<String>, Vec<String>) {
    let RData::Raw(d) = &m.answers[0].data else { panic!() };
    let (a, b) = svcb::hints(d);
    (a.iter().map(|x| x.to_string()).collect(), b.iter().map(|x| x.to_string()).collect())
}

#[test]
fn cdn_rewrite() {
    let (opt, _net) = setup(json!({}));

    // 未驗證：先回原始（已知最快）結果、TTL 10、排入背景驗證
    let mut m = msg("site.test", 1, &["104.21.0.5", "172.67.0.9"], vec![]);
    let r = opt.apply(&mut m, "site.test", 1);
    assert_eq!(answer_ips(&m, 1), ["104.21.0.5", "172.67.0.9"]);
    assert_eq!(r.ttl_cap, Some(10));
    let t = verify_tasks(&opt.take_tasks());
    assert_eq!(t, vec![("site.test".into(), "cloudflare".into(), 4, Some(ip("104.21.0.5")))]);

    // 驗證通過：照換、使用原始 TTL
    set_ok(&opt, "site.test", 4, "104.16.161.36", &["104.16.161.36", "104.18.20.216"]);
    let mut m = msg("site.test", 1, &["104.21.0.5"], vec![]);
    let r = opt.apply(&mut m, "site.test", 1);
    assert_eq!(answer_ips(&m, 1), ["104.16.161.36", "104.18.20.216"]);
    assert_eq!(r.ttl_cap, None);
    assert_eq!(m.answers[0].ttl, 300);
    assert_eq!(r.rewritten, Some(Rewrite::Alias));

    // 驗證失敗：回原始 IP 與原始 TTL
    opt.with_state(|st| {
        st.db.set_verdict("site.test", 4, |v| {
            v.verdict = Some(intern("fail"));
            v.until = Some(now_ms() + 3_600_000);
        })
    });
    let mut m = msg("site.test", 1, &["104.21.0.5"], vec![]);
    let r = opt.apply(&mut m, "site.test", 1);
    assert_eq!(answer_ips(&m, 1), ["104.21.0.5"]);
    assert_eq!(r.ttl_cap, None);

    // 已在台灣的 IP 不動
    let mut m = msg("tw.test", 1, &["104.16.161.99"], vec![]);
    let r = opt.apply(&mut m, "tw.test", 1);
    assert_eq!(answer_ips(&m, 1), ["104.16.161.99"]);
    assert!(r.tags.iter().any(|t| t.contains("已是台灣")));

    // CNAME 保留，只換 A
    set_ok(&opt, "www.x.test", 4, "104.16.161.36", &["104.16.161.36", "104.18.20.216"]);
    let mut m = msg("site.test", 1, &["104.21.0.5"], vec![cname("www.x.test", "site.test", 300)]);
    opt.apply(&mut m, "www.x.test", 1);
    assert_eq!(m.answers[0].rtype, 5);
    assert_eq!(m.answers.iter().filter(|a| a.rtype == 1).count(), 2);

    // 沒有台灣 v6 節點：丟棄 CDN 的 AAAA
    let mut m = msg("v6.test", 28, &["2606:4700:3030::1", "2001:db8::1"], vec![]);
    let r = opt.apply(&mut m, "v6.test", 28);
    assert_eq!(answer_ips(&m, 28), ["2001:db8::1"]);
    assert!(r.tags.iter().any(|x| x.contains("V6")));

    // 有台灣 v6 節點：未驗證先原始，驗證通過後置換 AAAA
    opt.with_state(|st| st.pools.p.get_mut("cloudflare").unwrap().pool6 = vec![node("2606:4700:10::1", 3.0)]);
    let mut m = msg("v6b.test", 28, &["2606:4700:3030::1"], vec![]);
    let r = opt.apply(&mut m, "v6b.test", 28);
    assert_eq!(answer_ips(&m, 28), ["2606:4700:3030::1"]);
    assert_eq!(r.ttl_cap, Some(10));
    set_ok(&opt, "v6b.test", 6, "2606:4700:10::1", &[]);
    let mut m = msg("v6b.test", 28, &["2606:4700:3030::1"], vec![]);
    let r = opt.apply(&mut m, "v6b.test", 28);
    assert_eq!(answer_ips(&m, 28), ["2606:4700:10::1"]);
    assert_eq!(r.ttl_cap, None);
    opt.with_state(|st| st.pools.p.get_mut("cloudflare").unwrap().pool6 = vec![]);

    // HTTPS 記錄：未驗證不改提示（TTL 10），驗證通過後同步改寫
    let mut m = https_rec("h.test", &["104.21.0.7"], true);
    let r = opt.apply(&mut m, "h.test", 65);
    assert_eq!(hints_of(&m).0, ["104.21.0.7"]);
    assert_eq!(r.ttl_cap, Some(10));
    set_ok(&opt, "h.test", 4, "104.16.161.36", &["104.16.161.36", "104.18.20.216"]);
    let mut m = https_rec("h.test", &["104.21.0.7"], true);
    opt.apply(&mut m, "h.test", 65);
    let (h4, h6) = hints_of(&m);
    assert_eq!(h4, ["104.16.161.36", "104.18.20.216"]);
    assert!(h6.is_empty());

    // 手動策略 never：不置換
    opt.with_state(|st| {
        st.db.set_policy("never.test", Policy::Never);
    });
    let mut m = msg("never.test", 1, &["104.21.0.5"], vec![]);
    let r = opt.apply(&mut m, "never.test", 1);
    assert_eq!(answer_ips(&m, 1), ["104.21.0.5"]);
    assert_eq!(r.tags, ["CDN-略過"]);

    // Akamai（CNAME 辨識）排入 ECS 突破、登記網域
    opt.take_tasks();
    let mut m = msg(
        "e1.dscx.akamaiedge.net",
        1,
        &["23.1.1.1"],
        vec![cname("www.ak.test", "e1.dscx.akamaiedge.net", 60)],
    );
    opt.apply(&mut m, "www.ak.test", 1);
    assert!(opt
        .take_tasks()
        .iter()
        .any(|t| matches!(t, Task::Ecs { name, .. } if name == "www.ak.test")));
    assert_eq!(opt.state().db.get("www.ak.test").unwrap().provider(), Some("akamai"));

    // ECS 結果有效時置換
    opt.with_state(|st| {
        st.db.set_ecs(
            "www.ak.test",
            Ecs {
                verdict: Some(intern("ok")),
                ips4: Some(ips(&["23.2.2.2"])),
                until: Some(now_ms() + 3_600_000),
                ..Default::default()
            },
        )
    });
    let mut m = msg(
        "e1.dscx.akamaiedge.net",
        1,
        &["23.1.1.1"],
        vec![cname("www.ak.test", "e1.dscx.akamaiedge.net", 60)],
    );
    let r = opt.apply(&mut m, "www.ak.test", 1);
    assert_eq!(answer_ips(&m, 1), ["23.2.2.2"]);
    assert_eq!(r.rewritten, Some(Rewrite::Ecs));
    assert_eq!(m.answers[0].rtype, 5, "CNAME 保留");

    // 分析摘要與 CSV 匯出
    let s = opt.summary();
    assert!(s.as_array().unwrap().iter().any(|x| x["provider"] == "cloudflare"));
    assert!(opt.query_csv(&Default::default()).contains("site.test"));
}

#[test]
fn trial_mode_alias() {
    // trialMode=alias：未驗證時先換台灣 IP
    let (opt, _) = setup(json!({ "trialMode": "alias" }));
    let mut m = msg("alias-mode.test", 1, &["104.21.0.5"], vec![]);
    let r = opt.apply(&mut m, "alias-mode.test", 1);
    assert_eq!(answer_ips(&m, 1), ["104.16.161.36", "104.18.20.216"]);
    assert_eq!(r.ttl_cap, Some(10));
}

#[test]
fn restricted_ips_and_verified_only() {
    let (opt, _) = setup(json!({}));
    opt.with_state(|st| {
        st.pools.p.get_mut("cloudflare").unwrap().pool4 =
            vec![node("162.159.14.122", 2.0), node("104.16.123.206", 3.0), node("104.18.3.88", 4.0)];
    });
    // 特定產品專用 IP（多個網站失敗）排到最後
    assert_eq!(opt.state().pools.serve_ips("cloudflare", 4)[0], ip("162.159.14.122"));
    opt.with_state(|st| {
        st.pools.zone_note("cloudflare", ip("162.159.14.122"), false);
        st.pools.zone_note("cloudflare", ip("162.159.14.122"), false);
    });
    assert!(opt.state().pools.is_restricted("cloudflare", ip("162.159.14.122")));
    assert!(!opt.state().pools.serve_ips("cloudflare", 4).contains(&ip("162.159.14.122")));

    // 只回針對這個網站驗證過的 IP（池內其他 IP 可能 Error 1034）
    let pool = opt.state().pools.serve_ips("cloudflare", 4);
    let set_v4 = |v: Verdict, ips4: &[&str]| {
        opt.with_state(|st| {
            st.db.touch("z.test", "cloudflare", "ip", &ips(ips4), &[], None);
            st.db.get_mut("z.test").unwrap().v4 = Some(Box::new(v));
        })
    };
    let ok = |ipx: &str, list: Option<&[&str]>| Verdict {
        verdict: Some(intern("ok")),
        ip: Some(ip(ipx)),
        ips: list.map(ips),
        ..Default::default()
    };
    let serve = |c: &Arc<Cdn>| {
        let mut t = Vec::new();
        let st = c.state();
        let out = c.serve_pool(&st, "cloudflare", 4, "z.test", &pool, None, &mut t);
        (out, t.len())
    };
    set_v4(ok("104.18.3.88", None), &[]);
    assert_eq!(serve(&opt).0, ips(&["104.18.3.88"]));
    set_v4(ok("104.18.3.88", Some(&["104.18.3.88", "104.16.123.206", "9.9.9.9"])), &[]);
    assert_eq!(serve(&opt).0, ips(&["104.18.3.88", "104.16.123.206"]));
    // 驗證過的 IP 都已不在池內 → 不回池內未驗證的 IP、排入重新驗證
    set_v4(ok("1.2.3.4", None), &["104.21.0.5"]);
    assert_eq!(serve(&opt), (vec![], 1));
}

fn fastly_setup(opt: &Cdn) {
    opt.with_state(|st| {
        st.pools.zone.clear();
        let d = st.pools.p.get_mut("fastly").unwrap();
        d.bad.clear();
        d.bad24.clear();
        d.pool4 = vec![
            fnode("151.101.76.2", "HKG", 26.0, 1.0, 28.0, None),
            fnode("151.101.77.9", "HKG", 27.0, 1.0, 29.0, None),
            fnode("151.101.0.5", "NRT", 48.0, 2.0, 52.0, None),
        ];
        d.prefixes = [
            (
                "HKG".to_string(),
                ["151.101.76", "151.101.77", "151.101.78"]
                    .iter()
                    .map(|s| crate::util::parse_prefix24(s).unwrap())
                    .collect(),
            ),
            (
                "NRT".to_string(),
                ["151.101.0", "151.101.1"]
                    .iter()
                    .map(|s| crate::util::parse_prefix24(s).unwrap())
                    .collect(),
            ),
        ]
        .into_iter()
        .collect();
    });
}

#[test]
fn fastly_octet_and_quality() {
    let (opt, net) = setup(json!({}));
    fastly_setup(&opt);
    let p = |f: &dyn Fn(&crate::pools::Pools) -> Vec<IpAddr>| f(&opt.state().pools);

    // 這組憑證還沒找到可用網段：不換，驗證候選依序試最佳 POP 的每個網段，再試第二個 POP
    assert!(p(&|x| x.map_ips("fastly", 4, &ips(&["151.101.65.140"]))).is_empty());
    assert_eq!(
        p(&|x| x.verify_candidates("fastly", Some(ip("151.101.65.140")), &[])),
        ips(&[
            "151.101.76.140",
            "151.101.77.140",
            "151.101.78.140",
            "151.101.0.140",
            "151.101.1.140"
        ])
    );
    // 網域自己的 DNS 曾回過、且在最佳 POP 的 IP 優先驗證（Giphy 151.101.77.32）
    assert_eq!(
        p(&|x| x.verify_candidates("fastly", Some(ip("146.75.45.32")), &ips(&["146.75.45.32", "151.101.77.32"])))[0],
        ip("151.101.77.32")
    );
    // 驗證成功的網段記下來，同一組憑證的其他網域直接用、優先驗證
    opt.with_state(|st| st.pools.zone_note("fastly", ip("151.101.77.32"), true));
    assert_eq!(p(&|x| x.map_ips("fastly", 4, &ips(&["146.75.45.32"]))), ips(&["151.101.77.32"]));
    assert_eq!(
        p(&|x| x.verify_candidates("fastly", Some(ip("199.232.113.32")), &[]))[0],
        ip("151.101.77.32")
    );
    assert!(opt.state().pools.usable("fastly", ip("151.101.77.32")));
    assert!(!opt.state().pools.usable("fastly", ip("151.101.9.32")));

    // 驗證過的 IP 最後一段跟這次答案不同時不使用
    let serve_with = |vip: &str| {
        opt.with_state(|st| {
            st.db.touch("fx.test", "fastly", "ip", &[], &[], None);
            st.db.get_mut("fx.test").unwrap().v4 = Some(Box::new(Verdict {
                verdict: Some(intern("ok")),
                ip: Some(ip(vip)),
                ..Default::default()
            }));
        });
        let st = opt.state();
        opt.serve_pool(&st, "fastly", 4, "fx.test", &[], Some(&ips(&["151.101.65.140"])), &mut Vec::new())
    };
    assert!(serve_with("151.101.77.6").is_empty());
    assert_eq!(serve_with("151.101.77.140"), ips(&["151.101.77.140"]));

    // 某網段連不上：該網段暫停 30 分鐘，候選跳過它
    opt.with_state(|st| st.pools.mark_bad("fastly", ip("151.101.78.140"), "測試"));
    assert!(!p(&|x| x.verify_candidates("fastly", Some(ip("151.101.65.140")), &[])).contains(&ip("151.101.78.140")));
    opt.with_state(|st| st.pools.p.get_mut("fastly").unwrap().bad24.clear());

    // 多家 CDN：答案裡已有更快的別家（蘋果在中華電信的快取 6ms），拿掉較慢的 Fastly、不換節點
    net.set_cached("203.69.141.59", 6.0);
    net.set_cached("151.101.67.6", 64.0);
    let mut m = msg("amp-api-edge.apps.apple.com", 1, &["203.69.141.59", "151.101.67.6"], vec![]);
    let r = opt.apply(&mut m, "amp-api-edge.apps.apple.com", 1);
    assert_eq!(answer_ips(&m, 1), ["203.69.141.59"]);
    assert!(r.tags.iter().any(|t| t.contains("別家 CDN 更快")));

    // GitHub 下載點（185.199.108.0/22，Fastly 服務）也會被辨識
    let c = opt.classify(ip("185.199.110.133")).unwrap();
    assert!(c.provider == "fastly" && matches!(c.cls, crate::Cls::Unknown | crate::Cls::Global));
    assert_eq!(opt.classify(ip("2606:50c0:8000::133")).unwrap().provider, "fastly");

    // GitHub 下載：未驗證先原始、驗證後換成香港網段＋.133，並丟掉 AAAA
    net.set_cached("185.199.110.133", 63.0);
    net.set_cached("185.199.108.133", 63.0);
    let host = "release-assets.githubusercontent.com";
    opt.take_tasks();
    let mut m = msg(host, 1, &["185.199.110.133", "185.199.108.133"], vec![]);
    let r = opt.apply(&mut m, host, 1);
    assert_eq!(answer_ips(&m, 1), ["185.199.110.133", "185.199.108.133"]);
    assert_eq!(r.ttl_cap, Some(10));
    assert_eq!(
        verify_tasks(&opt.take_tasks())[0],
        (host.into(), "fastly".into(), 4, Some(ip("185.199.110.133")))
    );
    opt.with_state(|st| st.pools.zone_note("fastly", ip("151.101.76.133"), true));
    opt.with_state(|st| {
        st.db.set_verdict(host, 4, |v| {
            v.verdict = Some(intern("ok"));
            v.ip = Some(ip("151.101.76.133"));
            v.until = Some(now_ms() + 3_600_000);
        })
    });
    let mut m = msg(host, 1, &["185.199.110.133", "185.199.108.133"], vec![]);
    opt.apply(&mut m, host, 1);
    assert_eq!(answer_ips(&m, 1), ["151.101.76.133"]);
    let mut m = msg(host, 28, &["2606:50c0:8000::133"], vec![]);
    opt.apply(&mut m, host, 28);
    assert!(answer_ips(&m, 28).is_empty());

    // 香港延遲最低但下載只剩 0.09 MB/s：排除不用；之前驗證在香港的 GitHub 改成重新驗證
    let (keep4, keep_pf) = {
        let st = opt.state();
        let d = &st.pools.p["fastly"];
        (d.pool4.clone(), d.prefixes.clone())
    };
    opt.with_state(|st| {
        let d = st.pools.p.get_mut("fastly").unwrap();
        d.pool4 = vec![
            fnode("146.75.51.173", "ICN", 46.5, 1.7, 50.0, Some(25.96)),
            fnode("167.82.81.173", "ITM", 36.9, 20.0, 76.9, Some(40.96)),
            fnode("151.101.76.55", "HKG", 26.3, 0.8, 108.0, Some(0.09)),
        ];
        d.prefixes = [("ICN", "146.75.51"), ("ITM", "167.82.81"), ("HKG", "151.101.76")]
            .iter()
            .map(|(k, v)| (k.to_string(), vec![crate::util::parse_prefix24(v).unwrap()]))
            .collect();
    });
    assert_eq!(opt.state().pools.active_pops("fastly"), ["ICN", "ITM"], "HKG 下載太慢被排除");
    opt.with_state(|st| st.pools.zone_note("fastly", ip("151.101.76.133"), true));
    assert!(!opt.state().pools.usable("fastly", ip("151.101.76.133")));
    let host = "objects.githubusercontent.com";
    opt.with_state(|st| {
        st.db.touch(host, "fastly", "ip", &[], &[], None);
        st.db.set_verdict(host, 4, |v| {
            v.verdict = Some(intern("ok"));
            v.ip = Some(ip("151.101.76.133"));
            v.algo = Some(2);
            v.until = Some(now_ms() + 3_600_000);
        })
    });
    opt.take_tasks();
    let mut m = msg(host, 1, &["185.199.110.133"], vec![]);
    let r = opt.apply(&mut m, host, 1);
    assert_eq!(answer_ips(&m, 1), ["185.199.110.133"]);
    assert_eq!(r.ttl_cap, Some(10));
    assert_eq!(verify_tasks(&opt.take_tasks()).len(), 1);
    opt.with_state(|st| {
        let d = st.pools.p.get_mut("fastly").unwrap();
        d.pool4 = keep4;
        d.prefixes = keep_pf;
    });
}

#[tokio::test]
async fn fastly_quality_check_switches_pop() {
    // 海纜壅塞：香港掉包、抖動變大 → 自動改用東京（已知可用的網段）
    let (opt, net) = setup(json!({}));
    fastly_setup(&opt);
    net.on_quality(|ip| {
        if ip.to_string().starts_with("151.101.7") {
            kuroshio_net::iprank::Quality {
                ms: 30.0,
                jitter: 40.0,
                loss: 0.5,
                n: 6,
            }
        } else {
            kuroshio_net::iprank::Quality {
                ms: 50.0,
                jitter: 2.0,
                loss: 0.0,
                n: 6,
            }
        }
    });
    assert_eq!(opt.state().pools.best_pop("fastly").as_deref(), Some("HKG"));
    assert!(opt.quality_check().await);
    assert_eq!(opt.state().pools.best_pop("fastly").as_deref(), Some("NRT"));
    opt.with_state(|st| st.pools.zone_note("fastly", ip("151.101.0.140"), true));
    assert_eq!(
        opt.state().pools.map_ips("fastly", 4, &ips(&["151.101.65.140"])),
        ips(&["151.101.0.140"])
    );
}

/// 跨 CDN 用的設定：Cloudflare、CloudFront、Azure 的台北節點各一個
fn cross_setup() -> (Arc<Cdn>, Arc<MockNet>) {
    let net = MockNet::new();
    let cfg = json!({
        "providers": { "cloudflare": {"enabled": true}, "cloudfront": {"enabled": true}, "azure": {"enabled": true}, "fastly": {"enabled": true} },
        "ecs": { "twSubnets": [] }, "nearestMinGainMs": 8
    });
    let c = cdn_with(cfg, paths_no_seed("cross"), net.clone());
    c.with_state(|st| {
        for (p, i) in [("cloudflare", "104.16.1.1"), ("cloudfront", "65.9.1.1"), ("azure", "13.107.1.1")] {
            st.pools.p.get_mut(p).unwrap().pool4 = vec![node(i, 3.0)];
        }
    });
    let html = |t: &str, st: u16, h: &[(&str, &str)]| {
        let mut hh = vec![("content-type", "text/html; charset=utf-8")];
        hh.extend_from_slice(h);
        resp(st, &hh, &format!("<html><head><title>{t}</title></head></html>"))
    };
    net.on_https(move |i, name| match i.to_string().as_str() {
        "151.101.1.1" => html("X", 200, &[]),
        "104.16.1.1" => html(if name == "x.com" { "X" } else { "Other" }, 200, &[("cf-ray", "abc-TPE")]),
        "65.9.1.1" => ProbeResult::failed("ERR_TLS_CERT_ALTNAME_INVALID", true),
        _ => resp(400, &[("x-azure-ref", "r")], "x"),
    });
    net.on_quality(|i| kuroshio_net::iprank::Quality {
        ms: if i.to_string().starts_with("151.") { 62.0 } else { 4.0 },
        jitter: 0.0,
        loss: 0.0,
        n: 3,
    });
    (c, net)
}

#[tokio::test]
async fn cross_cdn_explore() {
    let (cx, _net) = cross_setup();
    for n in ["x.com", "y.example"] {
        cx.with_state(|st| {
            st.db.touch(n, "fastly", "ip", &ips(&["151.101.1.1"]), &[], None);
        });
    }
    // X 用 Fastly、但 Cloudflare 台北節點也有放：記錄成可用（4ms，原本 62ms）
    let r1 = cx.cross_explore("x.com", "fastly", ip("151.101.1.1")).await;
    assert_eq!(r1, "ok");
    let rec = cx.state().db.get("x.com").unwrap().cross4.clone().unwrap();
    assert_eq!(rec.to.as_deref(), Some("cloudflare"));
    assert_eq!(rec.ips, Some(ips(&["104.16.1.1"])));
    assert!(rec
        .tried
        .as_ref()
        .unwrap()
        .iter()
        .any(|x| &*x.to == "cloudfront" && x.reason.as_deref().unwrap_or("").contains("憑證不符")));
    assert!(rec
        .tried
        .as_ref()
        .unwrap()
        .iter()
        .any(|x| &*x.to == "akamai" && x.reason.as_deref() == Some("沒有 Akamai 設定")));
    // Cloudflare 回的是別的網站（標題不同）：不採用，記錄失敗 3 天後再試
    let r2 = cx.cross_explore("y.example", "fastly", ip("151.101.1.1")).await;
    assert_eq!(r2, "fail");
    let rec = cx.state().db.get("y.example").unwrap().cross4.clone().unwrap();
    assert!(rec.until.unwrap() > now_ms() + 2 * 86_400_000);
    assert_eq!(rec.reason.as_deref(), Some("其他 CDN 都沒有這個網站"));
}

#[test]
fn cross_cdn_rewrite() {
    // 已驗證跨 CDN 可用：Fastly 的 A 換成 Cloudflare 台北節點、AAAA 拿掉
    let (opt, _) = setup(json!({}));
    let host = "abs.twimg.example";
    opt.with_state(|st| {
        st.db.touch(host, "fastly", "ip", &ips(&["151.101.1.140"]), &[], None);
        st.db.set_cross(
            host,
            Cross {
                verdict: Some(intern("ok")),
                from: Some(intern("fastly")),
                to: Some(intern("cloudflare")),
                ips: Some(ips(&["104.16.161.36"])),
                ms: Num::V(4.0),
                orig_ms: Num::V(62.0),
                until: Some(now_ms() + 86_400_000),
                recheck_at: Some(now_ms() + 3_600_000),
                ..Default::default()
            },
        );
    });
    let mut m = msg(host, 1, &["151.101.1.140", "151.101.65.140"], vec![]);
    let r = opt.apply(&mut m, host, 1);
    assert_eq!(answer_ips(&m, 1), ["104.16.161.36"]);
    assert_eq!(r.rewritten, Some(Rewrite::Cross));
    assert_eq!(r.cross_to.as_deref(), Some("cloudflare"));
    assert_eq!(r.gain_ms, Some(58.0));
    let mut m = msg(host, 28, &["2a04:4e42::396"], vec![]);
    opt.apply(&mut m, host, 28);
    assert!(m.answers.is_empty());
    // 記住這個網站最好的策略（規格 06 第 3.5 節）
    assert_eq!(opt.state().db.get(host).unwrap().best, Some(crate::db::Strategy::Cross));
}

#[test]
fn pinned_upstream_alias() {
    // 路由器把 Cloudflare 網站換成未驗證的 IP（lexin.tw → Error 1034）：不當快速回應
    let (opt, _) = setup(json!({}));
    let ans = |l: &[&str]| msg("lexin.tw", 1, l, vec![]);
    assert_eq!(opt.pinned_alias(&ans(&["104.16.161.36", "104.18.20.216"]), 1, None).len(), 2);
    assert!(opt.pinned_alias(&ans(&["8.8.8.8"]), 1, None).is_empty(), "不是任播 CDN 的照常");
    // 有其他上游回答時，路由器換過的 Cloudflare IP 不採用
    let auto = ans(&["104.21.0.5"]);
    assert_eq!(
        opt.pinned_alias(&ans(&["104.16.161.36", "104.18.20.216"]), 1, Some(&[&auto])).len(),
        2
    );
    // 路由器給的 IP 跟其他上游一樣、或不是任播 CDN（ISP 快取節點）：照常採用
    assert!(opt.pinned_alias(&ans(&["104.21.0.5"]), 1, Some(&[&auto])).is_empty());
    assert!(opt
        .pinned_alias(&ans(&["203.66.1.1"]), 1, Some(&[&ans(&["142.250.1.1"])]))
        .is_empty());
    // 只有路由器回答（其他上游都失敗）：仍用它的答案
    assert!(opt.pinned_alias(&ans(&["104.16.161.36"]), 1, Some(&[])).is_empty());
}
