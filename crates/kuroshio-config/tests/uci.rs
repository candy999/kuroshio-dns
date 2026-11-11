//! UCI 轉換：對照 2.x 的 openwrt/tools/test-uci-config.js 逐條移植

use kuroshio_config::uci::{overrides, parse_text, Env};
use kuroshio_config::{build, defaults, get, Tier};
use serde_json::{json, Value};

const DEFAULT_RAW: &str = include_str!("fixtures/default.uci");

/// Windows 上的 git 可能把測試檔轉成 CRLF：統一成 LF 再做文字替換
fn default_text() -> String {
    DEFAULT_RAW.replace("\r\n", "\n")
}

fn env() -> Env {
    Env {
        etc: "/etc/kuroshio".into(),
        ..Default::default()
    }
}

fn load(text: &str, env: &Env) -> Value {
    build(Tier::Large, &overrides(&parse_text(text).unwrap(), env))
}

fn g<'a>(v: &'a Value, p: &str) -> &'a Value {
    get(v, p).unwrap_or(&Value::Null)
}

#[test]
fn defaults_dnsmasq_upstream() {
    let d = load(&default_text(), &env());
    assert_eq!(g(&d, "listen.plain.binds"), &json!(["127.0.0.1", "::1"]));
    assert_eq!(g(&d, "listen.plain.port"), &json!(5335));
    assert!(get(&d, "resolver.localForward").is_none());
    assert_eq!(g(&d, "upstream.pinned"), &json!([]), "固定上游清空（避免問路由器自己）");
    assert_eq!(g(&d, "listen.doh.port"), &json!(8443));
    assert_eq!(g(&d, "listen.doh.trustProxy"), &json!(false));
    assert_eq!(g(&d, "listen.doh.cert"), &json!("/etc/kuroshio/cert.pem"));
    assert_eq!(g(&d, "site.hostname"), &json!(""));
    assert_eq!(g(&d, "listen.doh.enabled"), &json!(false));
    assert_eq!(g(&d, "listen.dot.enabled"), &json!(false));
    assert_eq!(g(&d, "ddns.records"), &json!([]));
    assert_eq!(g(&d, "site.enabled"), &json!(false));
    assert_eq!(g(&d, "ddns.enabled"), &json!(false));
    // 數值參數沿用內建預設
    assert_eq!(g(&d, "resolver.cacheMax"), g(&defaults(), "resolver.cacheMax"));
    assert_eq!(g(&d, "cdn.cross"), g(&defaults(), "cdn.cross"));
    // 只帶入預設勾選的清單
    let on: Vec<Value> = g(&defaults(), "filter.lists")
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l.get("enabled") != Some(&json!(false)))
        .map(|l| json!({ "url": l["url"], "category": l["category"], "name": l["name"] }))
        .collect();
    assert_eq!(g(&d, "filter.lists"), &Value::Array(on));
    assert_eq!(g(&d, "filter.customRules"), &json!(["/etc/kuroshio/custom-rules.txt"]));
    assert_eq!(g(&d, "community.enabled"), &json!(false));
    assert_eq!(g(&d, "community.endpoints"), &json!({ "doh": null, "dot": null }));
}

#[test]
fn custom_values_exchange_mode() {
    let text = default_text()
        .replace("option redirect 'dnsmasq-upstream'", "option redirect 'exchange'")
        .replace("option listen_ipv6 '1'", "option listen_ipv6 '0'")
        .replace("config resolver 'resolver'", "config resolver 'resolver'\n\toption timeout_ms '2000'\n\toption fast_path '0'\n\toption cache_max ''")
        .replace("config cdn 'cdn'\n\toption enabled '1'", "config cdn 'cdn'\n\toption enabled '1'\n\toption trial_mode 'alias'\n\toption cross_min_orig_ms '30'\n\toption cross_enabled '0'")
        .replace("config cdn_provider 'fastly'\n\toption enabled '1'", "config cdn_provider 'fastly'\n\toption enabled '0'")
        .replacen("config filter_list\n\toption enabled '1'", "config filter_list\n\toption enabled '0'", 1)
        .replace(
            "config job 'cdn_scan'\n\toption enabled '1'\n\tlist at '03:20'\n\tlist weekday '0'",
            "config job 'cdn_scan'\n\toption enabled '0'\n\tlist at '02:00'\n\tlist at '14:00'\n\tlist weekday '3'\n\tlist weekday '6'",
        )
        .replace("config upstream 'upstream'", "config upstream 'upstream'\n\tlist pinned 'udp://168.95.1.1'\n\toption auto_max '3'")
        + "\nconfig filter_list\n\toption name 'My'\n\toption url 'https://example.com/my.txt'\n\toption category 'malware'\n";
    let c = load(&text, &env());
    assert_eq!(g(&c, "listen.plain.binds"), &json!(["0.0.0.0"]));
    assert_eq!(g(&c, "listen.plain.port"), &json!(53));
    assert_eq!(
        g(&c, "resolver.localForward"),
        &json!({ "server": "udp://127.0.0.1:5354", "domains": ["lan"] })
    );
    // 依預設型別轉換；空白沿用預設
    assert_eq!(g(&c, "resolver.timeoutMs"), &json!(2000));
    assert_eq!(g(&c, "resolver.fastPath"), &json!(false));
    assert_eq!(g(&c, "resolver.cacheMax"), g(&defaults(), "resolver.cacheMax"));
    assert_eq!(g(&c, "cdn.trialMode"), &json!("alias"));
    assert_eq!(g(&c, "cdn.cross.minOrigMs"), &json!(30));
    assert_eq!(g(&c, "cdn.cross.enabled"), &json!(false));
    assert_eq!(g(&c, "cdn.providers.fastly.enabled"), &json!(false));
    let lists = g(&c, "filter.lists").as_array().unwrap();
    assert_eq!(
        lists.last().unwrap(),
        &json!({ "url": "https://example.com/my.txt", "category": "malware", "name": "My" })
    );
    assert!(!lists.iter().any(|l| l["name"] == "EasyList China"), "停用的清單不載入");
    assert_eq!(g(&c, "jobs.cdn-scan.enabled"), &json!(false));
    assert_eq!(g(&c, "jobs.cdn-scan.at"), &json!(["02:00", "14:00"]));
    assert_eq!(g(&c, "jobs.cdn-scan.weekdays"), &json!([3, 6]));
    assert_eq!(g(&c, "upstream.pinned"), &json!(["udp://168.95.1.1"]));
    assert_eq!(g(&c, "upstream.autoMax"), &json!(3));
}

#[test]
fn takeover_modes() {
    let r = load(
        &default_text().replace("option redirect 'dnsmasq-upstream'", "option redirect 'redirect'"),
        &env(),
    );
    assert_eq!(g(&r, "listen.plain.binds"), &json!(["0.0.0.0", "::"]));
    assert_eq!(g(&r, "listen.plain.openBinds"), &json!([]));
    assert_eq!(g(&r, "resolver.localForward.server"), &json!("udp://127.0.0.1:53"));

    let lan = Env {
        etc: "/etc/kuroshio".into(),
        lan4: "10.0.0.1".into(),
        ula: "fd00::1".into(),
    };
    let h = load(
        &default_text().replace("option redirect 'dnsmasq-upstream'", "option redirect 'hijack'"),
        &lan,
    );
    assert_eq!(g(&h, "listen.plain.binds"), &json!(["127.0.0.1", "10.0.0.1", "::1", "fd00::1"]));
    assert_eq!(g(&h, "listen.plain.openBinds"), &json!(["fd00::1"]), "ULA 不檢查來源");
    assert_eq!(g(&h, "listen.plain.port"), &json!(5335));
    assert_eq!(g(&h, "resolver.localForward.server"), &json!("udp://127.0.0.1:53"));

    let x = load(
        &default_text().replace("option redirect 'dnsmasq-upstream'", "option redirect 'exchange'"),
        &lan,
    );
    assert_eq!(
        g(&x, "listen.plain.binds"),
        &json!(["0.0.0.0", "::1", "fd00::1"]),
        "不綁 :: 避免跟 ULA 衝突"
    );
    assert_eq!(g(&x, "listen.plain.port"), &json!(53));

    let h4 = load(
        &default_text()
            .replace("option redirect 'dnsmasq-upstream'", "option redirect 'hijack'")
            .replace("option listen_ipv6 '1'", "option listen_ipv6 '0'"),
        &lan,
    );
    assert_eq!(g(&h4, "listen.plain.binds"), &json!(["127.0.0.1", "10.0.0.1"]), "不處理 IPv6");

    let none = load(
        &default_text().replace("option redirect 'dnsmasq-upstream'", "option redirect 'hijack'"),
        &env(),
    );
    assert_eq!(
        g(&none, "listen.plain.binds"),
        &json!(["0.0.0.0", "::1"]),
        "沒有區網 IP 時綁全部 IPv4"
    );
}

#[test]
fn community_endpoints_and_rules() {
    let text = default_text()
        .replace("option domain ''", "option domain 'dns.example.com'")
        .replace(
            "config doh 'doh'\n\toption enabled '0'\n\toption port '8443'\n\toption open_wan '0'",
            "config doh 'doh'\n\toption enabled '1'\n\toption port '8443'\n\toption open_wan '1'",
        )
        .replace("config dot 'dot'\n\toption enabled '0'", "config dot 'dot'\n\toption enabled '1'")
        .replace("config community 'community'\n\toption enabled '0'", "config community 'community'\n\toption enabled '1'\n\toption stale_days '14'\n\toption sync_interval '30'")
        + "\nconfig community_rule\n\toption name '同業者'\n\toption action 'accept'\n\toption same_asn '1'\n\toption max_rtt_ms '30'\n\tlist colo 'TPE'\n";
    let cm = load(&text, &env());
    assert_eq!(g(&cm, "community.enabled"), &json!(true));
    assert_eq!(
        g(&cm, "community.endpoints"),
        &json!({ "doh": "https://dns.example.com/.well-known/kuroshio", "dot": "dot://dns.example.com:853" })
    );
    assert_eq!(g(&cm, "community.staleDays"), &json!(14));
    assert_eq!(g(&cm, "community.syncIntervalMin"), &json!(30));
    assert_eq!(
        g(&cm, "community.rules"),
        &json!([{ "enabled": true, "name": "同業者", "action": "accept", "colo": ["TPE"], "same_asn": "1", "max_rtt_ms": "30" }])
    );
    assert_eq!(g(&cm, "community.dir"), &json!("/etc/kuroshio/community"));
}

#[test]
fn tier_still_applies_and_user_wins() {
    let o = overrides(
        &parse_text(&default_text().replace(
            "config resolver 'resolver'",
            "config resolver 'resolver'\n\toption cache_max '7777'",
        ))
        .unwrap(),
        &env(),
    );
    let tiny = build(Tier::Tiny, &o);
    assert_eq!(g(&tiny, "resolver.cacheMax"), &json!(7777), "UCI 有填的以 UCI 為準");
    assert_eq!(g(&tiny, "resolver.parallel"), &json!(2), "沒填的由等級決定");
    let sys = overrides(
        &parse_text(&(default_text() + "\nconfig system 'system'\n\toption profile 'small'\n\toption allow_heavy '1'\n")).unwrap(),
        &env(),
    );
    assert_eq!(kuroshio_config::requested_tier(&sys), Some(Tier::Small));
    assert_eq!(g(&sys, "system.allowHeavy"), &json!(true));
    // 快照：最久未存（小時）、保留空間（KB）
    let ps = overrides(
        &parse_text(&(default_text() + "\nconfig system 'system'\n\toption persist_max_age_hours '6'\n\toption min_free_kb '2048'\n"))
            .unwrap(),
        &env(),
    );
    assert_eq!(g(&ps, "system.persistMaxAgeHours"), &json!(6));
    assert_eq!(g(&ps, "system.minFreeKB"), &json!(2048));
    // 記憶體控制（規格 09）：預算（MB）、開關；清單的保護旗標
    let mg = overrides(
        &parse_text(
            &(default_text()
                + "\nconfig system 'system'\n\toption memory_budget_mb '40'\n\toption memory_governor '0'\n\nconfig filter_list\n\toption url 'https://lists.example.com/a.txt'\n\toption category 'ads'\n\toption protect '1'\n"),
        )
        .unwrap(),
        &env(),
    );
    assert_eq!(g(&mg, "system.memoryBudgetMB"), &json!(40));
    assert_eq!(g(&mg, "system.memoryGovernor"), &json!(false));
    let lists = g(&mg, "filter.lists").as_array().unwrap();
    let a = lists.iter().find(|l| l["url"] == "https://lists.example.com/a.txt").unwrap();
    assert_eq!(a["protect"], json!(true));
    assert!(
        lists.iter().filter(|l| l["url"] != a["url"]).all(|l| l.get("protect").is_none()),
        "沒寫就不帶（由分類決定）"
    );
    let dd = overrides(
        &parse_text(&default_text().replace("option data_dir ''", "option data_dir '/mnt/usb/kuroshio'")).unwrap(),
        &env(),
    );
    assert_eq!(g(&dd, "system.persistDir"), &json!("/mnt/usb/kuroshio"));
}

#[test]
fn parser_edge_cases() {
    let v = parse_text("config a 'x'\n\toption q 'it'\\''s'\n\tlist l '1'\n\tlist l '2'\nconfig b\n\toption k \"v\"\n# comment\n").unwrap();
    assert_eq!(v["values"]["x"]["q"], "it's");
    assert_eq!(v["values"]["x"]["l"], json!(["1", "2"]));
    assert_eq!(v["values"]["cfg000000"]["k"], "v");
    assert!(parse_text("config a 'x'\nconfig b 'x'\n").is_err(), "同名不同型別");
}

// ---------------- 3.0 新增：綁定網域、共用憑證、多位址、多網卡 ----------------

fn existing_text() -> String {
    default_text()
        .replace("option domain ''", "option domain 'dns.example.com'")
        .replace(
            "option cert_mode 'acme'",
            "option cert_mode 'manual'\n\toption cert '/mnt/certs/fullchain.pem'\n\toption key '/mnt/certs/privkey.pem'",
        )
        .replace(
            "config ddns 'ddns'\n\toption enabled '0'",
            "config ddns 'ddns'\n\toption enabled '1'\n\tlist record 'dns.example.com'\n\toption iface4 'pppoe-wan'",
        )
        .replace("config doh 'doh'\n\toption enabled '0'", "config doh 'doh'\n\toption enabled '1'")
        .replace("config dot 'dot'\n\toption enabled '0'", "config dot 'dot'\n\toption enabled '1'")
}

/// 沒用到新選項的既有設定：轉換結果跟加新功能之前完全一樣（快照是用舊版程式產生的）
#[test]
fn existing_configs_convert_identically() {
    let snap = |s: &str| -> Value { serde_json::from_str(s).unwrap() };
    let d = overrides(&parse_text(&default_text()).unwrap(), &env());
    assert_eq!(d, snap(include_str!("fixtures/default.overrides.json")), "預設設定：輸出一字不差");

    // 有網域、自備憑證、DDNS 的設定：只多了 `domain` 與 `tls`，其他一字不差
    let mut e = overrides(&parse_text(&existing_text()).unwrap(), &env());
    let m = e.as_object_mut().unwrap();
    assert_eq!(m.remove("domain"), Some(json!("dns.example.com")));
    assert_eq!(
        m.remove("tls"),
        Some(json!({ "cert": "/mnt/certs/fullchain.pem", "key": "/mnt/certs/privkey.pem" }))
    );
    assert_eq!(e, snap(include_str!("fixtures/existing.overrides.json")));

    // 合併後的有效設定：監聽的憑證、網域、DDNS 都跟以前一樣
    let c = load(&existing_text(), &env());
    assert_eq!(g(&c, "listen.doh.cert"), &json!("/mnt/certs/fullchain.pem"));
    assert_eq!(g(&c, "listen.dot.key"), &json!("/mnt/certs/privkey.pem"));
    assert_eq!(g(&c, "listen.doh.host"), &json!("0.0.0.0"));
    assert_eq!(
        g(&c, "listen.doh.tls"),
        &json!("auto"),
        "有明確的憑證、不是 127.0.0.1：照舊是 HTTPS"
    );
    assert_eq!(g(&c, "listen.doh.binds"), &json!([]));
    assert_eq!(g(&c, "site.hostname"), &json!("dns.example.com"));
    assert_eq!(g(&c, "community.domain"), &json!("dns.example.com"));
    assert_eq!(g(&c, "ddns.records"), &json!(["dns.example.com"]));
    assert_eq!(g(&c, "ddns.iface4"), &json!("pppoe-wan"));
    assert_eq!(g(&c, "ddns.interfaces"), &json!([]));
    assert_eq!(g(&c, "ddns.ipv6"), &json!(false));
    assert_eq!(g(&c, "acme.enabled"), &json!(false), "OpenWrt 用 acme.sh，不啟用內建 ACME");
}

#[test]
fn bound_domain_without_ddns_records() {
    // 固定網域：只填 tls.domain，DDNS 關閉 → 不產生記錄；DDNS 開了沒寫記錄 → 更新綁定網域
    let fixed = load(
        &default_text().replace("option domain ''", "option domain 'dns.example.com'"),
        &env(),
    );
    assert_eq!(g(&fixed, "domain"), &json!("dns.example.com"));
    assert_eq!(g(&fixed, "site.hostname"), &json!("dns.example.com"));
    assert_eq!(g(&fixed, "ddns.enabled"), &json!(false));
    assert_eq!(g(&fixed, "ddns.records"), &json!([]));
    let dd = load(
        &default_text()
            .replace("option domain ''", "option domain 'dns.example.com'")
            .replace(
                "config ddns 'ddns'\n\toption enabled '0'",
                "config ddns 'ddns'\n\toption enabled '1'",
            ),
        &env(),
    );
    assert_eq!(g(&dd, "ddns.records"), &json!(["dns.example.com"]));
}

#[test]
fn new_options_map_to_json() {
    let text = default_text()
        .replace(
            "config ddns 'ddns'\n\toption enabled '0'\n\toption ipv4 '1'\n\toption ipv6 '0'",
            "config ddns 'ddns'\n\toption enabled '1'\n\toption ipv4 '1'\n\toption ipv6 '1'\n\tlist interfaces 'pppoe-wan'\n\tlist interfaces 'wanb'",
        )
        .replace(
            "config doh 'doh'\n\toption enabled '0'",
            "config doh 'doh'\n\toption enabled '1'\n\tlist binds '0.0.0.0'\n\tlist binds '::'\n\tlist http3_binds '0.0.0.0'\n\toption tls '0'",
        )
        .replace("config dot 'dot'\n\toption enabled '0'", "config dot 'dot'\n\toption enabled '1'\n\tlist binds '192.0.2.1'")
        // 2.x 的設定檔沒有 doq 區段：補在最後
        + "\nconfig doq 'doq'\n\toption enabled '1'\n\tlist binds '::'\n";
    let c = load(&text, &env());
    assert_eq!(g(&c, "ddns.interfaces"), &json!(["pppoe-wan", "wanb"]));
    assert_eq!(g(&c, "ddns.ipv6"), &json!(true));
    assert_eq!(g(&c, "listen.doh.binds"), &json!(["0.0.0.0", "::"]));
    assert_eq!(g(&c, "listen.doh.http3Binds"), &json!(["0.0.0.0"]));
    assert_eq!(g(&c, "listen.doh.tls"), &json!(false));
    assert_eq!(g(&c, "listen.dot.binds"), &json!(["192.0.2.1"]));
    assert_eq!(g(&c, "listen.doq.binds"), &json!(["::"]));
    for (v, want) in [("1", json!(true)), ("auto", json!("auto"))] {
        let c = load(
            &default_text().replace("config doh 'doh'", &format!("config doh 'doh'\n\toption tls '{v}'")),
            &env(),
        );
        assert_eq!(g(&c, "listen.doh.tls"), &want);
    }
    assert_eq!(kuroshio_config::uci::cert_mode(&parse_text(&default_text()).unwrap()), "acme");
    assert_eq!(kuroshio_config::uci::cert_mode(&parse_text(&existing_text()).unwrap()), "manual");
}

#[test]
fn access_section() {
    // 沒有 access 區段：內建預設（只開放台灣、全部群組）
    let d = load(&default_text(), &env());
    assert_eq!(g(&d, "access.mode"), &json!("taiwan"));
    assert_eq!(g(&d, "access.groups"), &json!(["*"]));
    assert_eq!(g(&d, "access.applyTo"), &json!(["dot", "doh", "doq", "doh3", "site"]));
    let text = default_text()
        + "\nconfig access 'access'\n\toption mode 'custom'\n\tlist groups 'cht'\n\tlist groups 'tanet'\n\tlist allow '203.0.113.0/24'\n\tlist deny '198.51.100.7'\n\tlist apply_to 'dot'\n\tlist apply_to 'plain'\n\toption log '0'\n\toption auto_update '1'\n";
    let c = load(&text, &env());
    assert_eq!(g(&c, "access.mode"), &json!("custom"));
    assert_eq!(g(&c, "access.groups"), &json!(["cht", "tanet"]));
    assert_eq!(g(&c, "access.allow"), &json!(["203.0.113.0/24"]));
    assert_eq!(g(&c, "access.deny"), &json!(["198.51.100.7"]));
    assert_eq!(g(&c, "access.applyTo"), &json!(["dot", "plain"]));
    assert_eq!(g(&c, "access.log"), &json!(false));
    assert_eq!(g(&c, "access.autoUpdate"), &json!(true));
    assert_eq!(g(&c, "access.updateUrl"), g(&defaults(), "access.updateUrl"));
    // option groups '' = 一組都不勾；全開放
    let c = load(
        &(default_text() + "\nconfig access 'access'\n\toption mode 'open'\n\toption groups ''\n"),
        &env(),
    );
    assert_eq!(g(&c, "access.mode"), &json!("open"));
    assert_eq!(g(&c, "access.groups"), &json!([]));
}
