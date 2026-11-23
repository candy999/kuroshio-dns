//! UCI 轉換：對照 2.x 的 openwrt/tools/test-uci-config.js 逐條移植

use kuroshio_config::uci::{overrides, parse_text, Env};
use kuroshio_config::{build, defaults, get};
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
    build(&overrides(&parse_text(text).unwrap(), env))
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
    assert!(
        !lists.iter().any(|l| l["url"] == "https://filter.futa.gg/TW165_abp.txt"),
        "停用的清單不載入"
    );
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
    // 開放外網、外網 443 轉到本機 8443：對外的 DoH 埠號是 443
    assert_eq!(g(&cm, "listen.doh.publicPort"), &json!(443));

    // DoH 不開放外網（只給區網用 8443）：社群網址帶埠號，沒有 publicPort
    let lan_only = text.replace("option open_wan '1'", "option open_wan '0'");
    let cm = load(&lan_only, &env());
    assert_eq!(
        g(&cm, "community.endpoints.doh"),
        &json!("https://dns.example.com:8443/.well-known/kuroshio")
    );
    assert_eq!(g(&cm, "listen.doh.publicPort"), &json!(0), "預設 0 = 跟監聽的埠號一樣");
    // 外網埠跟本機埠一樣（443 被占用，直接開 8443 給外面）：不用另外寫 publicPort
    let same = text.replace("option wan_port '443'", "option wan_port '8443'");
    let cm = load(&same, &env());
    assert_eq!(
        g(&cm, "community.endpoints.doh"),
        &json!("https://dns.example.com:8443/.well-known/kuroshio")
    );
    assert_eq!(g(&cm, "listen.doh.publicPort"), &json!(0), "預設 0 = 跟監聽的埠號一樣");
}

#[test]
fn old_tier_keys_ignored_and_user_wins() {
    let o = overrides(
        &parse_text(&default_text().replace(
            "config resolver 'resolver'",
            "config resolver 'resolver'\n\toption cache_max '7777'",
        ))
        .unwrap(),
        &env(),
    );
    let c = build(&o);
    assert_eq!(g(&c, "resolver.cacheMax"), &json!(7777), "UCI 有填的以 UCI 為準");
    assert!(g(&c, "resolver.parallel").is_u64(), "沒填的依 CPU 核心數換算");
    // 舊版的硬體等級、記憶體預算：接受、不帶進設定（也不會失敗）
    let sys = overrides(
        &parse_text(
            &(default_text()
                + "\nconfig system 'system'\n\toption profile 'small'\n\toption tier 'tiny'\n\toption memory_budget_mb '40'\n\toption allow_heavy '1'\n"),
        )
        .unwrap(),
        &env(),
    );
    assert!(get(&sys, "system.profile").is_none() && get(&sys, "system.tier").is_none());
    assert!(get(&sys, "system.memoryBudgetMB").is_none());
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
                + "\nconfig system 'system'\n\toption memory_reserve_mb '40'\n\toption memory_reserve_percent '7'\n\toption oom_score_adj '-300'\n\toption storage_reserve_mb '3'\n\toption storage_reserve_percent '12'\n\toption memory_governor '0'\n\nconfig filter_list\n\toption url 'https://lists.example.com/a.txt'\n\toption category 'ads'\n\toption protect '1'\n"),
        )
        .unwrap(),
        &env(),
    );
    assert_eq!(g(&mg, "system.memoryReserveMB"), &json!(40));
    assert_eq!(g(&mg, "system.memoryReservePercent"), &json!(7));
    assert_eq!(g(&mg, "system.oomScoreAdj"), &json!(-300));
    assert_eq!(g(&mg, "system.storageReserveMB"), &json!(3));
    assert_eq!(g(&mg, "system.storageReservePercent"), &json!(12));
    assert_eq!(g(&mg, "system.memoryGovernor"), &json!(false));
    assert!(get(&mg, "system.testHooks").is_none(), "沒寫就不帶（預設 false）");
    // 測試開關（3.5.0 C9）：UCI 也能開（只寫在測試文件裡，不放進範例設定）
    let th = overrides(
        &parse_text(&(default_text() + "\nconfig system 'system'\n\toption test_hooks '1'\n")).unwrap(),
        &env(),
    );
    assert_eq!(g(&th, "system.testHooks"), &json!(true));
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
        + "\nconfig access 'access'\n\toption mode 'custom'\n\tlist groups 'cht'\n\tlist groups 'tanet'\n\tlist allow '203.0.113.0/24'\n\tlist deny '198.51.100.7'\n\tlist apply_to 'dot'\n\tlist apply_to 'plain'\n\toption log '0'\n\toption auto_update '0'\n\toption local_update '1'\n";
    let c = load(&text, &env());
    assert_eq!(g(&c, "access.mode"), &json!("custom"));
    assert_eq!(g(&c, "access.groups"), &json!(["cht", "tanet"]));
    assert_eq!(g(&c, "access.allow"), &json!(["203.0.113.0/24"]));
    assert_eq!(g(&c, "access.deny"), &json!(["198.51.100.7"]));
    assert_eq!(g(&c, "access.applyTo"), &json!(["dot", "plain"]));
    assert_eq!(g(&c, "access.log"), &json!(false));
    assert_eq!(
        g(&c, "access.localUpdate"),
        &json!(true),
        "舊的 auto_update 不影響新的 local_update"
    );
    // 台灣 IP 清單改在本機每月產生，不再有下載網址
    assert!(kuroshio_config::get(&c, "access.updateUrl").is_none());
    // option groups '' = 一組都不勾；全開放
    let c = load(
        &(default_text() + "\nconfig access 'access'\n\toption mode 'open'\n\toption groups ''\n"),
        &env(),
    );
    assert_eq!(g(&c, "access.mode"), &json!("open"));
    assert_eq!(g(&c, "access.groups"), &json!([]));
}

fn load_warn(text: &str) -> (Value, Vec<String>) {
    let (over, warns) = kuroshio_config::uci::overrides_with_warnings(&parse_text(text).unwrap(), &env());
    (build(&over), warns)
}

/// 同名區段跟 libuci 一樣合併：後面的 option 蓋掉同名的、list 接在後面，前一段的其他選項不會不見
#[test]
fn duplicate_sections_are_merged() {
    let text = default_text()
        + "\nconfig candydns 'main'\n\toption dns_port '5400'\n\tlist local_domain 'home.arpa'\n"
        + "\nconfig resolver 'resolver'\n\toption timeout_ms '2000'\n"
        + "\nconfig resolver 'resolver'\n\toption fast_path '0'\n\toption timeout_ms '3000'\n";
    let c = load(&text, &env());
    // 第二段 main 只有 dns_port：第一段的 admin_port、redirect 還在
    assert_eq!(g(&c, "listen.plain.port"), &json!(5400));
    assert_eq!(g(&c, "admin.port"), &json!(8054));
    assert_eq!(g(&c, "listen.plain.binds"), &json!(["127.0.0.1", "::1"]), "redirect 沿用第一段");
    let raw = parse_text(&text).unwrap();
    assert_eq!(raw["values"]["main"]["local_domain"], json!(["lan", "home.arpa"]), "list 接在後面");
    assert_eq!(raw["values"]["main"][".index"], json!(0), "位置以第一次出現的為準");
    assert_eq!(g(&c, "resolver.timeoutMs"), &json!(3000), "同一個 option 取最後一個");
    assert_eq!(g(&c, "resolver.fastPath"), &json!(false));
    // 同名但類型不同：照樣是錯誤
    assert!(parse_text("config doh 'x'\nconfig dot 'x'\n").is_err());
}

/// 埠號超出範圍（0、> 65535）或不是數字：用預設值並警告，不會被截斷成 4464 / 0
#[test]
fn out_of_range_ports_use_defaults() {
    let text = default_text()
        .replace("\toption port '8443'", "\toption port '70000'")
        .replace("option dns_port '5335'", "option dns_port '65536'")
        .replace("option admin_port '8054'", "option admin_port '0'")
        .replace("option exchange_port '5354'", "option exchange_port 'abc'");
    assert!(text.contains("'70000'"), "測試資料要真的改到 doh.port");
    let (c, warns) = load_warn(&text);
    assert_eq!(g(&c, "listen.doh.port"), &json!(8443));
    assert_eq!(g(&c, "listen.plain.port"), &json!(5335));
    assert_eq!(g(&c, "admin.port"), &json!(8054));
    for w in [
        "UCI 選項 doh.port = '70000' 不是有效的埠號（1–65535），改用預設值 8443",
        "UCI 選項 main.dns_port = '65536' 不是有效的埠號（1–65535），改用預設值 5335",
        "UCI 選項 main.admin_port = '0' 不是有效的埠號（1–65535），改用預設值 8054",
    ] {
        assert!(warns.iter().any(|x| x == w), "少了「{w}」：{warns:?}");
    }
    // 同一個選項讀好幾次也只警告一次
    assert_eq!(warns.iter().filter(|x| x.starts_with("UCI 選項 doh.port")).count(), 1, "{warns:?}");
    // exchange_port 只有 exchange 模式才讀
    let (c, warns) = load_warn(&text.replace("option redirect 'dnsmasq-upstream'", "option redirect 'exchange'"));
    assert_eq!(g(&c, "resolver.localForward.server"), &json!("udp://127.0.0.1:5354"));
    assert!(warns.iter().any(|x| x.contains("main.exchange_port = 'abc'")), "{warns:?}");
    // 正常的設定沒有任何警告
    let (_, warns) = load_warn(&default_text());
    assert!(warns.is_empty(), "{warns:?}");
}

/// 數字填錯（5k、-1、1e5）：用預設值並警告（以前靜默改用預設值）
#[test]
fn bad_numbers_warn() {
    let d = defaults();
    for bad in ["5k", "-1x", "1e5", "inf", "0x10"] {
        let text = default_text().replace(
            "config resolver 'resolver'",
            &format!("config resolver 'resolver'\n\toption cache_max '{bad}'"),
        );
        let (c, warns) = load_warn(&text);
        assert_eq!(g(&c, "resolver.cacheMax"), g(&d, "resolver.cacheMax"), "{bad}");
        let want = format!(
            "UCI 選項 resolver.cache_max = '{bad}' 不是有效的數字，改用預設值 {}",
            g(&d, "resolver.cacheMax")
        );
        assert!(warns.contains(&want), "{bad}：{warns:?}");
    }
    // 小數照樣是數字
    let text = default_text().replace(
        "config resolver 'resolver'",
        "config resolver 'resolver'\n\toption timeout_ms '1500.5'",
    );
    let (c, warns) = load_warn(&text);
    assert_eq!(g(&c, "resolver.timeoutMs"), &json!(1500.5));
    assert!(warns.is_empty(), "{warns:?}");
    // DDNS 的數字（非負整數）
    let text = default_text().replace(
        "\toption ttl '1'\n\toption interval '5'",
        "\toption ttl '-1'\n\toption interval '5k'\n\toption force_hours '1e5'",
    );
    let (c, warns) = load_warn(&text);
    assert_eq!(
        (g(&c, "ddns.ttl"), g(&c, "ddns.intervalMin"), g(&c, "ddns.forceHours")),
        (&json!(1), &json!(5), &json!(24))
    );
    for w in [
        "UCI 選項 ddns.ttl = '-1' 不是有效的數字，改用預設值 1",
        "UCI 選項 ddns.interval = '5k' 不是有效的數字，改用預設值 5",
        "UCI 選項 ddns.force_hours = '1e5' 不是有效的數字，改用預設值 24",
    ] {
        assert!(warns.iter().any(|x| x == w), "少了「{w}」：{warns:?}");
    }
    // 數字清單裡填錯的項目略過
    let text = default_text().replace(
        "\tlist at '03:20'\n\tlist weekday '0'",
        "\tlist at '03:20'\n\tlist weekday '0'\n\tlist weekday 'x'",
    );
    let (c, warns) = load_warn(&text);
    assert_eq!(g(&c, "jobs.cdn-scan.weekdays"), &json!([0]));
    assert!(
        warns
            .iter()
            .any(|x| x == "UCI 選項 cdn_scan.weekday 的 'x' 不是有效的數字，略過這一項"),
        "{warns:?}"
    );
}

/// 好友資料的「用不用」開關（3.4.3）：`use_hints`、`use_upstreams`；沒寫 = 預設使用；品質分數下限預設 0.3
#[test]
fn community_use_switches_map_to_config() {
    let c = load(&default_text(), &env());
    assert_eq!(g(&c, "community.useHints"), &json!(true));
    assert_eq!(g(&c, "community.useUpstreams"), &json!(true));
    assert_eq!(g(&c, "community.minHitRate"), &json!(0.3));
    let text = default_text().replace(
        "config community 'community'\n\toption enabled '0'",
        "config community 'community'\n\toption enabled '0'\n\toption use_hints '0'\n\toption use_upstreams '0'",
    );
    let c = load(&text, &env());
    assert_eq!(g(&c, "community.useHints"), &json!(false));
    assert_eq!(g(&c, "community.useUpstreams"), &json!(false));
}

/// `community.max_bundle_mb` → `maxBundleMB`（駝峰式會轉成 maxBundleMb，社群模組讀不到）
#[test]
fn max_bundle_mb_maps_to_config_field() {
    let text = default_text().replace(
        "config community 'community'\n\toption enabled '0'",
        "config community 'community'\n\toption enabled '0'\n\toption max_bundle_mb '8'",
    );
    let c = load(&text, &env());
    assert_eq!(g(&c, "community.maxBundleMB"), &json!(8));
    assert!(get(&c, "community.maxBundleMb").is_none());
    // 其他縮寫結尾的選項也依預設值的欄位名稱對應（tw_ip 的 max_mem_kb → maxMemKB）
    let text = default_text() + "\nconfig job 'tw_ip'\n\toption max_mem_kb '4096'\n";
    let c = load(&text, &env());
    assert_eq!(g(&c, "jobs.tw-ip.maxMemKB"), &json!(4096));
    assert!(get(&c, "jobs.tw-ip.maxMemKb").is_none());
}

/// 自備憑證只填一半（只有 cert 或只有 key）：不跟 acme 位置的另一半配在一起，兩個都用 acme 的位置並警告
#[test]
fn manual_cert_needs_both_halves() {
    let text = default_text().replace(
        "option cert_mode 'acme'",
        "option cert_mode 'manual'\n\toption cert '/mnt/certs/fullchain.pem'",
    );
    let (c, warns) = load_warn(&text);
    assert_eq!(g(&c, "listen.dot.cert"), &json!("/etc/kuroshio/cert.pem"));
    assert_eq!(g(&c, "listen.dot.key"), &json!("/etc/kuroshio/key.pem"));
    assert!(warns.iter().any(|w| w.contains("只填了一個")), "{warns:?}");
    // 兩個都填：照用
    let (c, warns) = load_warn(&existing_text());
    assert_eq!(g(&c, "listen.dot.cert"), &json!("/mnt/certs/fullchain.pem"));
    assert_eq!(g(&c, "listen.dot.key"), &json!("/mnt/certs/privkey.pem"));
    assert!(!warns.iter().any(|w| w.contains("只填了一個")));
}

/// 3.3.6 路徑檢查的開關：UCI `upstream` 段的 ipv6 / intercept_policy / path_check
#[test]
fn path_check_options() {
    let d = load(&default_text(), &env());
    assert_eq!(g(&d, "upstream.ipv6"), &json!("auto"));
    assert_eq!(g(&d, "upstream.interceptPolicy"), &json!("skip-plain"));
    assert_eq!(g(&d, "upstream.pathCheck"), &json!(true));
    let text = default_text().replace(
        "config upstream 'upstream'\n",
        "config upstream 'upstream'\n\toption ipv6 '0'\n\toption intercept_policy 'warn'\n\toption path_check '0'\n",
    );
    assert_ne!(text, default_text(), "測試用的預設 UCI 要有 upstream 段");
    let c = load(&text, &env());
    // UCI 的 '0' 轉換後是數字 0：讀的地方用 V6Mode::from_value（字串、數字、布林都接受）
    assert_eq!(g(&c, "upstream.ipv6"), &json!(0));
    assert_eq!(g(&c, "upstream.interceptPolicy"), &json!("warn"));
    assert_eq!(g(&c, "upstream.pathCheck"), &json!(false));
}

// ---------------- 3.4.0 串接模式的設定（規格 10 第 10 節） ----------------

const SHIPPED: &str = include_str!("../../../openwrt/kuroshio/files/kuroshio.config");
const FIELDS: &str = include_str!("../../../data/admin/fields.json");
const L_BYPASS: &str = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh-vpn-proxy-bypass.txt";

fn shipped_text() -> String {
    SHIPPED.replace("\r\n", "\n")
}

/// 串接的兩個開關、背景補問、上游多樣性：靠 snake_case → camelCase 自動轉換，名稱與型別要對
#[test]
fn uci_chain_options_convert() {
    use kuroshio_config::chain::{backfill_of, coverage_region_of, Backfill, ChainSettings, CoverageRegion};
    let text = default_text()
        .replace(
            "config upstream 'upstream'\n",
            "config upstream 'upstream'\n\toption chain '0'\n\toption allow_downstream '0'\n",
        )
        .replace(
            "config resolver 'resolver'\n",
            "config resolver 'resolver'\n\toption backfill 'off'\n\toption backfill_sample '0'\n",
        )
        .replace(
            "config benchmark 'benchmark'\n",
            "config benchmark 'benchmark'\n\toption coverage_region 'any'\n\toption near_max_ms '80'\n\toption tiers 'a'\n\toption malware_probe '0'\n",
        );
    for opt in ["option chain", "option backfill_sample", "option near_max_ms"] {
        assert!(text.contains(opt), "測試用的預設 UCI 要有對應的區段：{opt}");
    }
    let (o, warns) = load_warn(&text);
    assert!(warns.is_empty(), "{warns:?}");
    let raw = overrides(&parse_text(&text).unwrap(), &env());
    assert_eq!(g(&raw, "upstream.chain"), &json!(false));
    assert_eq!(g(&raw, "upstream.allowDownstream"), &json!(false));
    assert!(get(&raw, "upstream.allow_downstream").is_none(), "不留 snake_case 的名稱");
    assert_eq!(g(&raw, "resolver.backfill"), &json!("off"));
    assert_eq!(g(&raw, "resolver.backfillSample"), &json!(0));
    assert_eq!(g(&raw, "benchmark.coverageRegion"), &json!("any"));
    assert_eq!(g(&raw, "benchmark.nearMaxMs"), &json!(80));
    assert_eq!(g(&raw, "benchmark.tiers"), &json!("a"), "分級評測（3.5.0 A3）");
    assert_eq!(g(&raw, "benchmark.malwareProbe"), &json!(false), "惡意網站探測（3.5.0 A5）");
    // 讀取函式讀得出來
    let s = ChainSettings::from_cfg(&o);
    assert!(!s.chain && !s.allow_downstream && !s.downstream_enabled());
    assert!(s.warnings.is_empty());
    assert_eq!(backfill_of(&o), (Backfill::Off, 0));
    assert_eq!(coverage_region_of(&o), (CoverageRegion::Any, 80.0));

    // '1'、空白（= 預設）、沒寫：開
    let on = default_text().replace(
        "config upstream 'upstream'\n",
        "config upstream 'upstream'\n\toption chain '1'\n\toption allow_downstream ''\n",
    );
    let c = load(&on, &env());
    assert_eq!(g(&c, "upstream.chain"), &json!(true));
    assert_eq!(g(&c, "upstream.allowDownstream"), &json!(true));
    let s = ChainSettings::from_cfg(&load(&default_text(), &env()));
    assert!(s.chain && s.allow_downstream && s.downstream_enabled());

    // 早期草稿的 'auto'、'ask'：不是合法的寫法 → 預設值（開）並記警告（一般的開關會把它當成關）
    let draft = default_text().replace(
        "config upstream 'upstream'\n",
        "config upstream 'upstream'\n\toption chain 'auto'\n\toption allow_downstream 'ask'\n",
    );
    let (c, warns) = load_warn(&draft);
    assert_eq!(g(&c, "upstream.chain"), &json!(true));
    assert_eq!(g(&c, "upstream.allowDownstream"), &json!(true));
    assert!(warns.iter().any(|w| w.contains("upstream.chain")), "{warns:?}");
    assert!(warns.iter().any(|w| w.contains("upstream.allow_downstream")), "{warns:?}");
}

/// `config filter_list` 的 `option bypass '1'` → `filter.lists[i].bypass`；沒寫就沒有這個鍵
#[test]
fn uci_filter_list_bypass() {
    let text = default_text()
        + "\nconfig filter_list\n\toption name 'B'\n\toption url 'https://example.com/bypass.txt'\n\toption category 'malware'\n\toption bypass '1'\n"
        + "\nconfig filter_list\n\toption name 'N'\n\toption url 'https://example.net/no.txt'\n\toption bypass '0'\n";
    let c = load(&text, &env());
    let lists = g(&c, "filter.lists").as_array().unwrap();
    let find = |u: &str| lists.iter().find(|l| l["url"] == u).unwrap_or_else(|| panic!("{u}"));
    assert_eq!(find("https://example.com/bypass.txt")["bypass"], json!(true));
    assert_eq!(find("https://example.net/no.txt")["bypass"], json!(false));
    assert!(
        lists
            .iter()
            .filter(|l| !l["url"].as_str().unwrap().starts_with("https://example."))
            .all(|l| l.get("bypass").is_none()),
        "沒寫 bypass 的清單：沒有這個鍵"
    );
    assert!(kuroshio_config::chain::is_bypass_list(find("https://example.com/bypass.txt")));
    assert!(!kuroshio_config::chain::is_bypass_list(&lists[0]));

    // 從 3.2 遷移時新加的 doh-vpn-proxy-bypass 那一段帶 bypass '1'
    let old = include_str!("fixtures/kuroshio-3.2.0.config").replace("\r\n", "\n");
    let m = kuroshio_config::uci_migrate::migrate(&old).unwrap();
    let v = parse_text(&m.text).unwrap();
    let sec = v["values"]
        .as_object()
        .unwrap()
        .values()
        .find(|s| s["url"] == L_BYPASS)
        .expect("遷移後有 doh-vpn-proxy-bypass");
    assert_eq!(sec["bypass"], json!("1"));
}

/// 附帶的 OpenWrt 預設設定檔：轉換後串接相關的值跟 defaults.json 一樣（防止兩邊不同步）
#[test]
fn shipped_uci_config_matches_defaults() {
    let shipped = shipped_text();
    let c = load(&shipped, &env());
    let d = defaults();
    for k in [
        "upstream.chain",
        "upstream.allowDownstream",
        "upstream.pathCheck",
        "resolver.backfill",
        "resolver.backfillSample",
        "benchmark.coverageRegion",
        "benchmark.nearMaxMs",
        "benchmark.tiers",
        "benchmark.malwareProbe",
    ] {
        assert!(get(&d, k).is_some(), "defaults.json 沒有 {k}");
        assert_eq!(g(&c, k), g(&d, k), "{k}");
    }
    // 預設檔裡有明確寫出來（不是靠沒寫 = 預設）
    let raw = overrides(&parse_text(&shipped).unwrap(), &env());
    for k in [
        "upstream.chain",
        "upstream.allowDownstream",
        "resolver.backfill",
        "resolver.backfillSample",
        "benchmark.coverageRegion",
        "benchmark.nearMaxMs",
        "benchmark.tiers",
        "benchmark.malwareProbe",
    ] {
        assert!(get(&raw, k).is_some(), "預設 UCI 沒寫 {k}");
    }
    // doh-vpn-proxy-bypass 那一筆：兩邊都標成 bypass（預設停用，所以轉換後不在清單裡，直接看 UCI 原文）
    let v = parse_text(&shipped).unwrap();
    let sec = v["values"].as_object().unwrap().values().find(|s| s["url"] == L_BYPASS).unwrap();
    assert_eq!(sec["bypass"], json!("1"));
    assert_eq!(sec["enabled"], json!("0"));
    let dl = g(&d, "filter.lists")
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["url"] == L_BYPASS)
        .unwrap();
    assert_eq!(dl["bypass"], json!(true));
    assert_eq!(dl["enabled"], json!(false));
}

/// 說明文字要寫出關掉的影響（重複使用網路）：設定頁與 UCI 預設檔的註解
#[test]
fn help_texts_mention_duplicate_work() {
    fn walk(v: &Value, out: &mut std::collections::HashMap<String, String>) {
        match v {
            Value::Object(m) => {
                if let (Some(Value::String(k)), Some(Value::String(h))) = (m.get("key"), m.get("help")) {
                    out.insert(k.clone(), h.clone());
                }
                m.values().for_each(|x| walk(x, out));
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let f: Value = serde_json::from_str(FIELDS).unwrap();
    let mut helps = std::collections::HashMap::new();
    walk(&f, &mut helps);
    for k in ["upstream.chain", "upstream.allowDownstream"] {
        let h = helps.get(k).unwrap_or_else(|| panic!("fields.json 沒有 {k} 的說明"));
        assert!(h.contains("重複"), "{k}：{h}");
    }
    assert!(helps["upstream.allowDownstream"].contains("頻寬"));
    assert!(helps["upstream.allowDownstream"].contains("繞過防護"));
    // UCI 預設檔：選項的前一行註解
    let shipped = shipped_text();
    let lines: Vec<&str> = shipped.lines().map(str::trim).collect();
    for opt in ["option chain ", "option allow_downstream "] {
        let i = lines
            .iter()
            .position(|l| l.starts_with(opt))
            .unwrap_or_else(|| panic!("預設 UCI 沒有 {opt}"));
        assert!(
            lines[i - 1].starts_with('#') && lines[i - 1].contains("重複"),
            "{opt} 的註解：{}",
            lines[i - 1]
        );
    }
}

/// 3.4.0 補跑時段：main.catchup_window → system.catchUpWindow；沒填就沒有這個鍵（跟以前一樣）
#[test]
fn catchup_window_option() {
    let d = load(&default_text(), &env());
    assert_eq!(g(&d, "system.catchUpWindow"), &json!(""));
    // 測試用的預設 UCI 是舊的寫法（section 類型不是 kuroshio），接在 data_dir 後面
    let text = default_text().replace(
        "\toption data_dir ''\n",
        "\toption data_dir ''\n\toption catchup_window '01:00-06:00'\n",
    );
    assert_ne!(text, default_text());
    let c = load(&text, &env());
    assert_eq!(g(&c, "system.catchUpWindow"), &json!("01:00-06:00"));
}

/// 3.4.2：`cdn.lite` 預設是 "auto"；UCI 的 `option lite '1'` 照樣帶到設定（CDN 端接受 "1"／"0"）
#[test]
fn cdn_lite_from_uci() {
    let c = load("config cdn 'cdn'\n\toption lite '1'\n", &env());
    let v = g(&c, "cdn.lite");
    assert!(v == &json!(1) || v == &json!("1") || v == &json!(true), "{v:?}");
    let c = load("config cdn 'cdn'\n", &env());
    assert_eq!(g(&c, "cdn.lite"), &json!("auto"));
}

/// 3.5.0 B8：`scan` 區段自動對應 snake_case → camelCase（`max_per_sec` → `scan.maxPerSec`）
#[test]
fn scan_max_per_sec_from_uci() {
    let text = "config kuroshio 'main'\n\toption enabled '1'\n\nconfig scan 'scan'\n\toption max_per_sec '80'\n";
    let raw = overrides(&parse_text(text).unwrap(), &env());
    assert_eq!(g(&raw, "scan.maxPerSec"), &json!(80));
    assert!(get(&raw, "scan.max_per_sec").is_none(), "不留 snake_case 的名稱");
}

/// 3.5.0 C5：`cdn.dbDiskBudgetKB` 預設是 "auto"；UCI 的 `option db_disk_budget_kb` 填數字就是數字（0 = 關）
#[test]
fn cdn_db_disk_budget_from_uci() {
    let c = load("config cdn 'cdn'\n\toption db_disk_budget_kb '3000'\n", &env());
    assert_eq!(g(&c, "cdn.dbDiskBudgetKB"), &json!(3000));
    let c = load("config cdn 'cdn'\n\toption db_disk_budget_kb '0'\n", &env());
    assert_eq!(g(&c, "cdn.dbDiskBudgetKB"), &json!(0));
    let c = load("config cdn 'cdn'\n", &env());
    assert_eq!(g(&c, "cdn.dbDiskBudgetKB"), &json!("auto"));
}
