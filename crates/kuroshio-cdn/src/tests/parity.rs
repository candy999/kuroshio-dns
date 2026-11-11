//! 跟 node 版逐筆對照：tests/vectors/cdn/cases.json 由 tests/vectors/cdn/gen.js 用 legacy-node/lib/cdn/*.js 產生。
//! CNAME / 標頭 / 錯誤頁 / 同站判斷、IP 分類、改寫決策（答案、TTL、標記、背景工作）都必須相同。

use super::*;
use crate::cdn::Task;
use crate::cross::{cross_broken, same_site};
use crate::db::{Cross, Ecs, Policy};
use crate::pools::{cidr, PoolNode, Pools};
use crate::providers::{self, detect_from_headers, is_tw_pop, provider_by_cname};
use crate::util::{intern, now_ms, parse_prefix24, Num};
use crate::verifier::looks_broken_r;
use kuroshio_proto::message::RData;

fn cases() -> Value {
    serde_json::from_slice(&std::fs::read(repo().join("tests/vectors/cdn/cases.json")).unwrap()).unwrap()
}

fn headers(v: &Value) -> Vec<(String, String)> {
    v.as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
        .collect()
}

fn probe_of(v: &Value) -> ProbeResult {
    ProbeResult {
        ok: true,
        status: v["status"].as_u64().unwrap() as u16,
        headers: headers(&v["headers"]),
        body: v["body"].as_str().unwrap().to_string(),
        ms: 10.0,
        ..Default::default()
    }
}

fn opt_str(v: &Value) -> Option<String> {
    v.as_str().map(String::from)
}

#[test]
fn parity_pure_functions() {
    let c = cases();
    for x in c["cname"].as_array().unwrap() {
        let h = x["host"].as_str().unwrap();
        assert_eq!(provider_by_cname(h).map(String::from), opt_str(&x["provider"]), "CNAME {h}");
    }
    for x in c["twPop"].as_array().unwrap() {
        assert_eq!(
            is_tw_pop(x["pop"].as_str().unwrap()),
            x["tw"].as_bool().unwrap(),
            "POP {}",
            x["pop"]
        );
    }
    for x in c["headers"].as_array().unwrap() {
        let h = headers(&x["headers"]);
        let body = x["body"].as_str().unwrap();
        let d = detect_from_headers(&h, body);
        assert_eq!(
            d.provider.map(String::from),
            opt_str(&x["detect"]["provider"]),
            "判斷 {}",
            x["headers"]
        );
        assert_eq!(d.pop, x["detect"]["pop"].as_str().unwrap(), "POP {}", x["headers"]);
        for (name, per) in x["per"].as_object().unwrap() {
            let p = providers::get(name).unwrap();
            if !per["pop"].is_null() {
                assert_eq!(p.pop(&h, body), per["pop"].as_str().unwrap(), "{name}.pop {}", x["headers"]);
            }
            assert_eq!(p.is_provider(&h), per["is"].as_bool(), "{name}.isProvider {}", x["headers"]);
        }
    }
    for x in c["broken"].as_array().unwrap() {
        let p = x["provider"].as_str().unwrap();
        let r = probe_of(&x["r"]);
        assert_eq!(looks_broken_r(p, &r), opt_str(&x["looks"]), "looksBroken {p} {}", x["r"]);
        assert_eq!(cross_broken(p, &r), opt_str(&x["cross"]), "crossBroken {p} {}", x["r"]);
    }
    for x in c["sameSite"].as_array().unwrap() {
        assert_eq!(
            same_site(&probe_of(&x["a"]), &probe_of(&x["b"])),
            opt_str(&x["diff"]),
            "sameSite {x}"
        );
    }
}

#[test]
fn parity_classify() {
    let c = cases();
    let cfg = Arc::new(crate::CdnConfig::from_value(&json!({ "providers": {
        "cloudflare": {"enabled": true}, "cloudfront": {"enabled": true}, "fastly": {"enabled": true}, "gcore": {"enabled": true}, "azure": {"enabled": true}
    } })));
    let paths = paths_no_seed("parity");
    let reader = |rel: &str| paths.read_cdn_text(rel);
    let pools = Pools::load(cfg, &reader, None, &mut crate::v6store::V6Store::new(100));
    let mut n = 0;
    for x in c["classify"].as_array().unwrap() {
        let s = x["ip"].as_str().unwrap();
        let got = pools
            .classify(ip(s))
            .map(|c| json!({ "provider": c.provider, "cls": c.cls.as_str() }));
        assert_eq!(got.unwrap_or(Value::Null), x["c"], "分類 {s}");
        n += 1;
    }
    assert!(n > 100);
}

fn show(m: &Message) -> Vec<String> {
    m.answers
        .iter()
        .map(|a| match &a.data {
            RData::A(v) => format!("A {v} {}", a.ttl),
            RData::Aaaa(v) => format!("AAAA {v} {}", a.ttl),
            RData::Name(n) => format!("CNAME {n} {}", a.ttl),
            RData::Raw(d) => {
                let (v4, v6) = crate::svcb::hints(d);
                let s = |l: Vec<String>| l;
                format!(
                    "HTTPS {}",
                    json!({ "v4": s(v4.iter().map(|x| x.to_string()).collect()), "v6": s(v6.iter().map(|x| x.to_string()).collect()) })
                )
            }
            _ => unreachable!(),
        })
        .collect()
}

fn bg_json(t: &Task) -> Value {
    match t {
        Task::Verify {
            name,
            provider,
            family,
            orig,
        } => json!(["verify", name, provider, family, orig.map(|o| o.to_string())]),
        Task::Ecs { name, .. } => json!(["ecs", name]),
        Task::Cross { name, from, orig } => json!(["cross", name, from, orig.to_string()]),
        Task::TryV6 { provider, ip } => json!(["tryV6", provider, ip.to_string()]),
        Task::Latency(ip) => json!(["latency", ip.to_string()]),
    }
}

fn str_list(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect())
        .unwrap_or_default()
}

#[test]
fn parity_rewrite_decisions() {
    let c = cases();
    let p = &c["pools"];
    let mk = |mode: &str| {
        let net = MockNet::new();
        let cfg = json!({
            "enabled": true, "trialTtl": 10, "v6Policy": "drop", "trialMode": mode,
            "providers": { "cloudflare": {"enabled": true}, "akamai": {"enabled": true, "ecs": true}, "fastly": {"enabled": true} },
            "ecs": { "twSubnets": [] }
        });
        (cdn_with(cfg, paths_no_seed("parity-rw"), net.clone()), net)
    };
    let (orig, orig_net) = mk("original");
    let (alias, alias_net) = mk("alias");
    let node = |v: &Value| -> PoolNode { serde_json::from_value(v.clone()).unwrap() };
    let cs = |k: &str| -> Arc<crate::cidr::CidrSet> {
        let l = str_list(&p[k]);
        cidr(&l.iter().map(|s| s.as_str()).collect::<Vec<_>>())
    };
    for sc in c["scenarios"].as_array().unwrap() {
        let sname = sc["name"].as_str().unwrap();
        let (opt, net) = if sc["trialMode"] == "alias" {
            (&alias, &alias_net)
        } else {
            (&orig, &orig_net)
        };
        let name = format!("{sname}.test");
        // 節點池回到固定狀態
        opt.with_state(|st| {
            let cf = st.pools.p.get_mut("cloudflare").unwrap();
            cf.pool4 = p["cfPool4"].as_array().unwrap().iter().map(node).collect();
            cf.pool6 = str_list(&sc["cfPool6"])
                .iter()
                .map(|s| {
                    let mut n = PoolNode::new(ip(s));
                    n.ms = Num::V(3.0);
                    n
                })
                .collect();
            cf.bad.clear();
            cf.global = cs("cfGlobal");
            cf.tw = cs("cfTw");
            cf.dead = cs("cfDead");
            cf.range4 = cs("cfRange4");
            cf.range6 = cs("cfRange6");
            cf.tw48 = cidr(&[]);
            let f = st.pools.p.get_mut("fastly").unwrap();
            f.pool4 = p["fastlyPool4"].as_array().unwrap().iter().map(node).collect();
            f.pool6.clear();
            f.bad.clear();
            f.bad24.clear();
            f.prefixes = p["fastlyPrefixes"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), str_list(v).iter().map(|s| parse_prefix24(s).unwrap()).collect()))
                .collect();
            st.pools.zone.clear();
            for z in sc["zone"].as_array().into_iter().flatten() {
                st.pools
                    .zone_note(z[0].as_str().unwrap(), ip(z[1].as_str().unwrap()), z[2].as_bool().unwrap());
            }
        });
        net.cache.lock().unwrap().clear();
        for (k, v) in sc["cached"].as_object().into_iter().flatten() {
            net.set_cached(k, v.as_f64().unwrap());
        }
        let provider = if sname.starts_with("cf") {
            "cloudflare"
        } else if sname.starts_with("fastly") {
            "fastly"
        } else if sname.starts_with("ak") {
            "akamai"
        } else {
            "bunny"
        };
        let now = now_ms();
        opt.with_state(|st| {
            if ["v4", "v6", "policy", "ecs", "cross"].iter().any(|k| !sc[*k].is_null()) {
                st.db.touch(&name, provider, "ip", &[], &[], None);
            }
            for fam in [4u8, 6] {
                let v = &sc[format!("v{fam}")];
                if v.is_null() {
                    continue;
                }
                st.db.set_verdict(&name, fam, |x| {
                    x.verdict = v["verdict"].as_str().map(intern);
                    x.ip = v["ip"].as_str().map(ip);
                    x.ips = v["ips"]
                        .as_array()
                        .map(|_| ips(&str_list(&v["ips"]).iter().map(|s| s.as_str()).collect::<Vec<_>>()));
                    x.reason = opt_str(&v["reason"]);
                    x.algo = v["algo"].as_u64().map(|a| a as u32);
                    x.until = Some((now as i64 + (v["hours"].as_f64().unwrap_or(1.0) * 3_600_000.0) as i64) as u64);
                });
            }
            if let Some(pol) = sc["policy"].as_str() {
                st.db.set_policy(&name, Policy::parse(pol).unwrap());
            }
            if !sc["ecs"].is_null() {
                let e = &sc["ecs"];
                st.db.set_ecs(
                    &name,
                    Ecs {
                        verdict: e["verdict"].as_str().map(intern),
                        ips4: e["ips4"]
                            .as_array()
                            .map(|_| ips(&str_list(&e["ips4"]).iter().map(|s| s.as_str()).collect::<Vec<_>>())),
                        ips6: e["ips6"]
                            .as_array()
                            .map(|_| ips(&str_list(&e["ips6"]).iter().map(|s| s.as_str()).collect::<Vec<_>>())),
                        gain_ms: e["gainMs"].as_f64().map(Num::V).unwrap_or_default(),
                        until: Some(now + 3_600_000),
                        ..Default::default()
                    },
                );
            }
            if !sc["cross"].is_null() {
                let x = &sc["cross"];
                st.db.set_cross(
                    &name,
                    Cross {
                        verdict: x["verdict"].as_str().map(intern),
                        from: Some(intern(provider)),
                        to: x["to"].as_str().map(intern),
                        ips: x["ips"]
                            .as_array()
                            .map(|_| ips(&str_list(&x["ips"]).iter().map(|s| s.as_str()).collect::<Vec<_>>())),
                        ms: x["ms"].as_f64().map(Num::V).unwrap_or_default(),
                        orig_ms: x["origMs"].as_f64().map(Num::V).unwrap_or_default(),
                        until: Some(now + 86_400_000),
                        recheck_at: Some((now as i64 + (x["recheck"].as_f64().unwrap_or(1.0) * 3_600_000.0) as i64) as u64),
                        ..Default::default()
                    },
                );
            }
        });
        // 答案
        let mut m = Message::default();
        for a in sc["ans"].as_array().unwrap() {
            let t = a[0].as_str().unwrap();
            m.answers.push(match t {
                "A" => Record::a(&name, 300, a[1].as_str().unwrap().parse().unwrap()),
                "AAAA" => Record::aaaa(&name, 300, a[1].as_str().unwrap().parse().unwrap()),
                "CNAME" => cname(&name, a[1].as_str().unwrap(), 300),
                _ => Record {
                    name: name.clone(),
                    rtype: 65,
                    class: 1,
                    ttl: 300,
                    data: RData::Raw(crate::svcb::build_test_rdata(
                        &str_list(&a[1]).iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                        a[2].as_bool().unwrap(),
                    )),
                },
            });
        }
        let qt = match sc["q"].as_str().unwrap() {
            "A" => 1,
            "AAAA" => 28,
            _ => 65,
        };
        opt.take_tasks();
        let r = opt.apply(&mut m, &name, qt);
        let want = &sc["result"];
        assert_eq!(show(&m), str_list(&sc["answers"]), "{sname}：答案");
        assert_eq!(r.ttl_cap.map(|x| x as u64), want["ttlCap"].as_u64(), "{sname}：TTL");
        assert_eq!(r.tags, str_list(&want["tags"]), "{sname}：標記");
        assert_eq!(r.provider.map(String::from), opt_str(&want["provider"]), "{sname}：CDN");
        assert_eq!(
            r.rewritten.map(|x| x.as_str().to_string()),
            opt_str(&want["rewritten"]),
            "{sname}：改寫"
        );
        assert_eq!(r.cross_to, opt_str(&want["crossTo"]), "{sname}：跨 CDN");
        assert_eq!(r.gain_ms, want["gainMs"].as_f64(), "{sname}：省下的毫秒");
        let bg: Vec<Value> = opt.take_tasks().iter().map(bg_json).collect();
        assert_eq!(Value::Array(bg), sc["bg"], "{sname}：背景工作");
    }
}
