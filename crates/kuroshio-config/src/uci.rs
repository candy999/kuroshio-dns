//! OpenWrt：`/etc/config/kuroshio`（UCI）→ 使用者設定（JSON）。逐條對照 2.x 的 `uci-config.js`。
//!
//! - 沒設定的選項沿用預設值（預設值只定義在一個地方）
//! - 數字 / 開關 / 清單依預設值的型別自動轉換；空白 = 用預設值
//! - 輸出的是「使用者設定」，之後照樣經過 內建預設 → 等級調整 → 使用者設定 的合併

use crate::{defaults, get};
use anyhow::{bail, Result};
use serde_json::{json, Map, Value};

/// 執行環境（init 腳本傳入）
#[derive(Debug, Clone, Default)]
pub struct Env {
    /// 設定與資料目錄，預設 /etc/kuroshio
    pub etc: String,
    /// 區網 IPv4（積極劫持、取代 dnsmasq 時綁定）
    pub lan4: String,
    /// 區網 ULA
    pub ula: String,
}

impl Env {
    pub fn from_process() -> Env {
        let v = |k: &str| std::env::var(k).unwrap_or_default();
        let etc = v("KUROSHIO_ETC");
        Env {
            etc: if etc.is_empty() { "/etc/kuroshio".into() } else { etc },
            lan4: v("KUROSHIO_LAN_IP4"),
            ula: v("KUROSHIO_LAN_ULA"),
        }
    }
}

/// 解析 UCI 設定檔文字，輸出跟 `ubus call uci get` 一樣的 `{ values: {...} }`
pub fn parse_text(text: &str) -> Result<Value> {
    let mut values = Map::new();
    let mut cur: Option<String> = None;
    let (mut anon, mut index) = (0u32, 0u32);
    let unq = |s: &str| -> String {
        let s = s.trim();
        let inner = if s.len() >= 2 && ((s.starts_with('\'') && s.ends_with('\'')) || (s.starts_with('"') && s.ends_with('"'))) {
            &s[1..s.len() - 1]
        } else {
            s
        };
        inner.replace("'\\''", "'")
    };
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(3, char::is_whitespace);
        let (kw, name, rest) = (it.next().unwrap_or(""), it.next().unwrap_or(""), it.next().map(str::trim));
        match kw {
            "config" => {
                let sec = match rest {
                    Some(r) if !r.is_empty() => unq(r),
                    _ => {
                        let n = format!("cfg{anon:06x}");
                        anon += 1;
                        n
                    }
                };
                if let Some(old) = values.get(&sec) {
                    if old[".type"] != name {
                        bail!("UCI 解析錯誤：區段 '{sec}' 同時是 {} 與 {name}", old[".type"]);
                    }
                }
                values.insert(
                    sec.clone(),
                    json!({ ".anonymous": rest.map(|r| r.is_empty()).unwrap_or(true), ".type": name, ".name": sec, ".index": index }),
                );
                index += 1;
                cur = Some(sec);
            }
            "option" | "list" => {
                let Some(sec) = cur.as_ref().and_then(|c| values.get_mut(c)).and_then(Value::as_object_mut) else {
                    continue;
                };
                let v = unq(rest.unwrap_or(""));
                if kw == "option" {
                    sec.insert(name.to_string(), Value::String(v));
                } else {
                    let e = sec.entry(name.to_string()).or_insert_with(|| json!([]));
                    if !e.is_array() {
                        *e = json!([]);
                    }
                    e.as_array_mut().unwrap().push(Value::String(v));
                }
            }
            _ => {}
        }
    }
    Ok(json!({ "values": values }))
}

fn camel(s: &str) -> String {
    let mut out = String::new();
    let mut up = false;
    for c in s.chars() {
        if c == '_' {
            up = true;
        } else if up {
            out.extend(c.to_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::String(s) => matches!(s.as_str(), "1" | "true" | "on" | "yes"),
        _ => false,
    }
}

fn list(v: Option<&Value>) -> Vec<String> {
    match v {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str())
            .filter(|x| !x.is_empty())
            .map(str::to_string)
            .collect(),
        Some(Value::String(s)) if s.is_empty() => vec![],
        Some(Value::String(s)) => vec![s.clone()],
        Some(other) => vec![other.to_string()],
    }
}

fn num(s: &str) -> Option<Value> {
    if let Ok(i) = s.trim().parse::<i64>() {
        return Some(json!(i));
    }
    s.trim().parse::<f64>().ok().filter(|f| f.is_finite()).map(|f| json!(f))
}

/// 依預設值的型別轉換 UCI 字串
fn coerce(v: &Value, like: Option<&Value>) -> Value {
    match like {
        Some(Value::Array(a)) => {
            let numeric = a.first().map(Value::is_number).unwrap_or(false);
            Value::Array(
                list(Some(v))
                    .into_iter()
                    .map(|x| {
                        if numeric {
                            num(&x).unwrap_or(Value::String(x))
                        } else {
                            Value::String(x)
                        }
                    })
                    .collect(),
            )
        }
        _ if v.is_array() => v.clone(),
        Some(Value::Bool(_)) => Value::Bool(truthy(v)),
        Some(Value::Number(_)) => v.as_str().and_then(num).unwrap_or_else(|| like.cloned().unwrap()),
        None => match v.as_str().and_then(|s| {
            (!s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '-'))
                .then(|| num(s))
                .flatten()
        }) {
            Some(n) => n,
            None => v.clone(),
        },
        _ => v.clone(),
    }
}

/// 把一個 UCI 區段的選項套到 `out`（snake_case → camelCase），`rename` 可改名或忽略（None）
fn apply(out: &mut Map<String, Value>, defaults: Option<&Value>, sec: Option<&Value>, rename: &[(&str, Option<&str>)]) {
    let Some(Value::Object(sec)) = sec else { return };
    for (k, v) in sec {
        if k.starts_with('.') {
            continue;
        }
        let key = match rename.iter().find(|(from, _)| *from == k) {
            Some((_, None)) => continue,
            Some((_, Some(to))) => to.to_string(),
            None => camel(k),
        };
        let like = out.get(&key).or_else(|| defaults.and_then(|d| d.get(&key)));
        if v.as_str() == Some("") && !like.map(Value::is_array).unwrap_or(false) {
            continue; // 空白 = 用預設值
        }
        let val = coerce(v, like);
        out.insert(key, val);
    }
}

/// UCI → 使用者設定
pub fn overrides(uci: &Value, env: &Env) -> Value {
    let d = defaults();
    let vals = uci.get("values").unwrap_or(uci);
    let sec = |n: &str| vals.get(n);
    let s = |n: &str, k: &str| vals.get(n).and_then(|x| x.get(k)).and_then(Value::as_str).unwrap_or("").to_string();
    let has = |n: &str, k: &str| vals.get(n).and_then(|x| x.get(k)).is_some();
    let flag = |n: &str, k: &str, dflt: bool| if has(n, k) { truthy(&vals[n][k]) } else { dflt };
    let mut by_type: Vec<&Value> = vals.as_object().map(|m| m.values().collect()).unwrap_or_default();
    by_type.sort_by_key(|x| x.get(".index").and_then(Value::as_u64).unwrap_or(0));
    let of_type = |t: &str| -> Vec<&Value> {
        by_type
            .iter()
            .copied()
            .filter(|x| x.get(".type").and_then(Value::as_str) == Some(t))
            .collect()
    };
    let etc = if env.etc.is_empty() { "/etc/kuroshio" } else { &env.etc };
    let mut out = Map::new();

    // ---------------- 監聽 ----------------
    let domain = s("tls", "domain");
    let manual = s("tls", "cert_mode") == "manual";
    let cert = if manual && !s("tls", "cert").is_empty() {
        s("tls", "cert")
    } else {
        format!("{etc}/cert.pem")
    };
    let key = if manual && !s("tls", "key").is_empty() {
        s("tls", "key")
    } else {
        format!("{etc}/key.pem")
    };
    let port_of = |n: &str, k: &str, dflt: u64| s(n, k).parse::<u64>().unwrap_or(dflt);
    let doh_on = flag("doh", "enabled", false);
    let dot_on = flag("dot", "enabled", false);
    let doq_on = flag("doq", "enabled", false);
    let mut listen = Map::new();
    listen.insert(
        "doh".into(),
        json!({ "enabled": doh_on, "host": if s("doh", "host").is_empty() { "0.0.0.0".into() } else { s("doh", "host") },
                "port": port_of("doh", "port", 8443), "trustProxy": flag("doh", "trust_proxy", false), "cert": cert, "key": key,
                "http3": flag("doh", "http3", false) }),
    );
    listen.insert(
        "dot".into(),
        json!({ "enabled": dot_on, "host": if s("dot", "host").is_empty() { "0.0.0.0".into() } else { s("dot", "host") },
                "port": port_of("dot", "port", 853), "cert": cert, "key": key }),
    );
    listen.insert(
        "doq".into(),
        json!({ "enabled": flag("doq", "enabled", false), "port": port_of("doq", "port", 853) }),
    );
    // 3.0 新增（沒寫這些選項時輸出跟以前完全一樣）：
    // - `list binds`：監聽多個位址（取代 host；要收 IPv6 就寫 0.0.0.0 與 ::）
    // - `doh.http3_binds`：DoH3 另外指定位址；`doh.tls`：auto / 1 / 0（DoH 的 TCP 要不要 TLS）
    for (uci_sec, opt, key) in [
        ("doh", "binds", "binds"),
        ("dot", "binds", "binds"),
        ("doq", "binds", "binds"),
        ("doh", "http3_binds", "http3Binds"),
    ] {
        let b = list(sec(uci_sec).and_then(|x| x.get(opt)));
        if !b.is_empty() {
            listen[uci_sec][key] = json!(b);
        }
    }
    match s("doh", "tls").as_str() {
        "" => {}
        "auto" => listen["doh"]["tls"] = json!("auto"),
        v => listen["doh"]["tls"] = json!(truthy(&json!(v))),
    }

    // 區網 DNS：依 DNS 接管模式決定綁定位址與埠
    let mode = {
        let m = s("main", "redirect");
        if m.is_empty() {
            "dnsmasq-upstream".to_string()
        } else {
            m
        }
    };
    let v6 = flag("main", "listen_ipv6", true);
    let port = port_of("main", "dns_port", 5335);
    let lan4 = env.lan4.clone();
    let ula = if v6 { env.ula.clone() } else { String::new() };
    let some = |x: &str| if x.is_empty() { vec![] } else { vec![x.to_string()] };
    let (binds, plain_port): (Vec<String>, u64) = match mode.as_str() {
        "dnsmasq-upstream" => (
            if v6 {
                vec!["127.0.0.1".into(), "::1".into()]
            } else {
                vec!["127.0.0.1".into()]
            },
            port,
        ),
        "hijack" => {
            let mut b = vec![if lan4.is_empty() {
                "0.0.0.0".to_string()
            } else {
                "127.0.0.1".to_string()
            }];
            b.extend(some(&lan4));
            if v6 {
                b.push("::1".into());
            }
            b.extend(some(&ula));
            (b, port)
        }
        "exchange" => {
            // 不綁 :: 萬用位址（會跟 ULA 的綁定衝突）；IPv6 裝置由 DHCP 拿到 ULA 來查
            let mut b = vec!["0.0.0.0".to_string()];
            if v6 {
                b.push("::1".into());
            }
            b.extend(some(&ula));
            (b, 53)
        }
        _ => (
            if v6 {
                vec!["0.0.0.0".into(), "::".into()]
            } else {
                vec!["0.0.0.0".into()]
            },
            port,
        ),
    };
    // ULA 從外網連不進來：綁在 ULA 上的連線不檢查來源
    let open_binds: Vec<String> = if !ula.is_empty() && binds.contains(&ula) {
        vec![ula.clone()]
    } else {
        vec![]
    };
    let mut plain = json!({ "enabled": true, "binds": binds, "port": plain_port, "openBinds": open_binds });
    if has("main", "allow_from") {
        plain["allowFrom"] = json!(list(vals["main"].get("allow_from")));
    }
    listen.insert("plain".into(), plain);
    listen.insert("ddr".into(), json!(flag("main", "ddr", false)));
    out.insert("listen".into(), Value::Object(listen));
    // 綁定網域（固定網域或 DDNS 名稱）：沿用 `tls.domain`；公開頁、社群、DDNS 記錄沒另外填時都用它
    if !domain.is_empty() {
        out.insert("domain".into(), json!(domain));
    }
    // 自備憑證（cert_mode = manual）：同時寫到共用憑證位置 `tls.cert / tls.key`（設定頁「存放位置」顯示用）
    if manual && !s("tls", "cert").is_empty() && !s("tls", "key").is_empty() {
        out.insert("tls".into(), json!({ "cert": cert, "key": key }));
    }

    // 接管 53 埠時，區網網域與私有 IP 反查交回 dnsmasq
    let local_domains = if has("main", "local_domain") {
        list(vals["main"].get("local_domain"))
    } else {
        vec!["lan".into()]
    };
    let mut resolver = Map::new();
    match mode.as_str() {
        "redirect" | "hijack" => {
            resolver.insert(
                "localForward".into(),
                json!({ "server": "udp://127.0.0.1:53", "domains": local_domains }),
            );
        }
        "exchange" => {
            resolver.insert(
                "localForward".into(),
                json!({ "server": format!("udp://127.0.0.1:{}", port_of("main", "exchange_port", 5354)), "domains": local_domains }),
            );
        }
        _ => {}
    }

    out.insert(
        "admin".into(),
        json!({ "enabled": true, "host": "127.0.0.1", "port": port_of("main", "admin_port", 8054) }),
    );
    out.insert("log".into(), json!({ "queryLog": flag("main", "query_log", false), "level": if s("main", "log_level").is_empty() { "info".into() } else { s("main", "log_level") }, "fileLog": false }));

    // 公開網頁（OpenWrt 預設關閉）
    let mut site = Map::new();
    site.insert("enabled".into(), json!(flag("site", "enabled", false)));
    site.insert("hostname".into(), json!(domain));
    apply(&mut site, d.get("site"), sec("site"), &[("enabled", None), ("hostname", None)]);
    let site_on = site["enabled"].clone();
    out.insert("site".into(), Value::Object(site));
    out.insert("check".into(), json!({ "enabled": site_on }));

    // ---------------- 上游 ----------------
    let mut up = Map::new();
    apply(
        &mut up,
        d.get("upstream"),
        sec("upstream"),
        &[("auto_type", Some("autoTypes")), ("last_resort", None)],
    );
    // 固定上游沒填 = 不用（路由器本身當上游會變成迴圈）
    up.insert("pinned".into(), json!(list(sec("upstream").and_then(|u| u.get("pinned")))));
    out.insert("upstream".into(), Value::Object(up));
    if has("upstream", "last_resort") {
        resolver.insert("lastResort".into(), json!(list(vals["upstream"].get("last_resort"))));
    }

    // ---------------- 解析 / 測速 ----------------
    apply(&mut resolver, d.get("resolver"), sec("resolver"), &[]);
    out.insert("resolver".into(), Value::Object(resolver));
    let mut iprank = Map::new();
    apply(&mut iprank, d.get("iprank"), sec("iprank"), &[]);
    out.insert("iprank".into(), Value::Object(iprank));

    // ---------------- 過濾 ----------------
    let mut filter = Map::new();
    apply(&mut filter, d.get("filter"), sec("filter"), &[("custom_rules", None)]);
    let custom = s("filter", "custom_rules");
    filter.insert(
        "customRules".into(),
        json!([if custom.is_empty() {
            format!("{etc}/custom-rules.txt")
        } else {
            custom
        }]),
    );
    let lists = of_type("filter_list");
    if !lists.is_empty() || sec("filter").is_some() {
        let ls: Vec<Value> = lists
            .iter()
            .filter(|l| l.get("enabled").map(truthy).unwrap_or(true))
            .filter(|l| l.get("url").and_then(Value::as_str).map(|u| !u.is_empty()).unwrap_or(false))
            .map(|l| {
                let cat = l.get("category").and_then(Value::as_str).unwrap_or("ads");
                let cat = if cat == "malware" || cat == "telemetry" { cat } else { "ads" };
                let url = l["url"].as_str().unwrap();
                let name = l.get("name").and_then(Value::as_str).filter(|n| !n.is_empty()).unwrap_or(url);
                let mut o = json!({ "url": url, "category": cat, "name": name });
                // 保護清單（記憶體不足也不停用）：沒寫時由分類決定（惡意 / 反詐騙是）
                if let Some(p) = l.get("protect") {
                    o["protect"] = json!(truthy(p));
                }
                o
            })
            .collect();
        filter.insert("lists".into(), Value::Array(ls));
    }
    out.insert("filter".into(), Value::Object(filter));

    // ---------------- CDN ----------------
    let mut cdn = Map::new();
    let mut cross_src = Map::new();
    let mut plain_src = Map::new();
    if let Some(Value::Object(c)) = sec("cdn") {
        for (k, v) in c {
            match k.strip_prefix("cross_") {
                Some(rest) => cross_src.insert(rest.to_string(), v.clone()),
                None => plain_src.insert(k.clone(), v.clone()),
            };
        }
    }
    let dcdn = d.get("cdn");
    apply(&mut cdn, dcdn, Some(&Value::Object(plain_src)), &[]);
    let mut cross = Map::new();
    apply(&mut cross, dcdn.and_then(|c| c.get("cross")), Some(&Value::Object(cross_src)), &[]);
    if !cross.is_empty() {
        cdn.insert("cross".into(), Value::Object(cross));
    }
    let mut providers = Map::new();
    for p in of_type("cdn_provider") {
        let name = p.get(".name").and_then(Value::as_str).unwrap_or("").to_string();
        let mut cur = Map::new();
        let dp = dcdn
            .and_then(|c| c.get("providers"))
            .and_then(|ps| ps.get(&name))
            .cloned()
            .unwrap_or(json!({ "enabled": true }));
        apply(&mut cur, Some(&dp), Some(p), &[("seed_v4", Some("seedV4"))]);
        providers.insert(name, Value::Object(cur));
    }
    if !providers.is_empty() {
        cdn.insert("providers".into(), Value::Object(providers));
    }
    let mut ecs = Map::new();
    apply(
        &mut ecs,
        dcdn.and_then(|c| c.get("ecs")),
        sec("ecs"),
        &[("resolver", Some("resolvers")), ("tw_subnet", Some("twSubnets"))],
    );
    if !ecs.is_empty() {
        cdn.insert("ecs".into(), Value::Object(ecs));
    }
    out.insert("cdn".into(), Value::Object(cdn));

    // ---------------- DDNS ----------------
    let dd = |k: &str| s("ddns", k);
    let mut ddns = json!({
        "enabled": flag("ddns", "enabled", false), "provider": "cloudflare", "apiToken": s("cf_account", "api_token"),
        "records": list(sec("ddns").and_then(|x| x.get("record"))), "zone": dd("zone"),
        "ipv4": flag("ddns", "ipv4", true), "ipv6": flag("ddns", "ipv6", false), "proxied": flag("ddns", "proxied", false),
        "ttl": dd("ttl").parse::<u64>().unwrap_or(1), "intervalMin": dd("interval").parse::<u64>().unwrap_or(5),
        "forceHours": dd("force_hours").parse::<u64>().unwrap_or(24),
        "ipSource": if dd("ip_source").is_empty() { "web".into() } else { dd("ip_source") }, "iface4": dd("iface4"), "iface6": dd("iface6"),
    });
    for k in ["url4", "url6"] {
        if !dd(k).is_empty() {
            ddns[k] = json!(dd(k));
        }
    }
    // 多網卡 / 多出口：`list interfaces 'pppoe-wan'`（沒寫 = 系統預設路由；舊的 iface4 / iface6 照樣有效）
    let ifaces = list(sec("ddns").and_then(|x| x.get("interfaces")));
    if !ifaces.is_empty() {
        ddns["interfaces"] = json!(ifaces);
    }
    out.insert("ddns".into(), ddns);

    // ---------------- 社群共享 ----------------
    // 對外網址：DoH 開放外網時用外網埠（443 就不寫埠），否則用本機埠
    let doh_wan = if flag("doh", "open_wan", false) {
        port_of("doh", "wan_port", 443)
    } else {
        port_of("doh", "port", 8443)
    };
    let endpoints = json!({
        "doh": if doh_on && !domain.is_empty() { json!(format!("https://{domain}{}/.well-known/kuroshio", if doh_wan == 443 { String::new() } else { format!(":{doh_wan}") })) } else { Value::Null },
        "dot": if dot_on && !domain.is_empty() { json!(format!("dot://{domain}:{}", port_of("dot", "port", 853))) } else { Value::Null },
    });
    // 3.0 新增：DoQ 開著時才加（關閉時跟 2.x 的輸出一樣）
    let mut endpoints = endpoints;
    if doq_on && !domain.is_empty() {
        endpoints["doq"] = json!(format!("doq://{domain}:{}", port_of("doq", "port", 853)));
    }
    let rules: Vec<Value> = of_type("community_rule")
        .iter()
        .map(|r| {
            let mut o = json!({ "enabled": r.get("enabled").map(truthy).unwrap_or(true), "name": r.get("name").and_then(Value::as_str).unwrap_or(""), "action": r.get("action").and_then(Value::as_str).unwrap_or("manual") });
            for k in ["domain_suffix", "asn", "colo"] {
                if r.get(k).is_some() {
                    o[k] = json!(list(r.get(k)));
                }
            }
            for k in ["same_asn", "require_ip_match", "has_txt", "max_rtt_ms", "max_jitter_ms", "max_loss", "min_age_days", "min_mutual", "max_friends"] {
                if let Some(v) = r.get(k).filter(|v| v.as_str() != Some("")) {
                    o[k] = v.clone();
                }
            }
            o
        })
        .collect();
    let mut cm = Map::new();
    cm.insert("enabled".into(), json!(flag("community", "enabled", false)));
    cm.insert("dir".into(), json!(format!("{etc}/community")));
    cm.insert("domain".into(), json!(domain));
    cm.insert("cert".into(), json!(cert));
    cm.insert("endpoints".into(), endpoints);
    cm.insert("rules".into(), Value::Array(rules));
    apply(
        &mut cm,
        d.get("community"),
        sec("community"),
        &[
            ("enabled", None),
            ("rules", None),
            ("dir", None),
            ("state_dir", None),
            ("endpoints", None),
            ("domain", None),
            ("cert", None),
            ("sync_interval", Some("syncIntervalMin")),
        ],
    );
    out.insert("community".into(), Value::Object(cm));

    // ---------------- 來源 IP 存取控制（規格 08） ----------------
    // `config access 'access'`：mode、list groups、list allow、list deny、list apply_to、log、auto_update。
    // 沒有這個區段 = 內建預設（只開放台灣）；`option groups ''` = 一組都不勾
    if sec("access").is_some() {
        let mut acc = Map::new();
        apply(&mut acc, d.get("access"), sec("access"), &[("apply_to", Some("applyTo"))]);
        out.insert("access".into(), Value::Object(acc));
    }

    // ---------------- 排程工作 ----------------
    let mut jobs = Map::new();
    for j in of_type("job") {
        let name = j.get(".name").and_then(Value::as_str).unwrap_or("").replace('_', "-");
        let dj = get(&d, &format!("jobs.{name}")).cloned();
        let mut cur = Map::new();
        if let Some(e) = j.get("enabled") {
            cur.insert("enabled".into(), json!(truthy(e)));
        }
        if j.get("at").is_some() {
            cur.insert("at".into(), json!(list(j.get("at"))));
        }
        if j.get("weekday").is_some() {
            let w: Vec<Value> = list(j.get("weekday")).iter().filter_map(|x| num(x)).collect();
            // 清單是空的 = 每天
            cur.insert("weekdays".into(), Value::Array(w));
        }
        apply(
            &mut cur,
            dj.as_ref(),
            Some(j),
            &[("enabled", None), ("at", None), ("weekday", None)],
        );
        jobs.insert(name, Value::Object(cur));
    }
    out.insert("jobs".into(), Value::Object(jobs));
    let mut bench = Map::new();
    apply(
        &mut bench,
        d.get("benchmark"),
        sec("benchmark"),
        &[("dir", None), ("out_dir", None), ("q_exe", None)],
    );
    bench.insert("dir".into(), json!(format!("{etc}/benchmark")));
    out.insert("benchmark".into(), Value::Object(bench));
    for name in ["scan", "pool", "system"] {
        let mut m = Map::new();
        // 大部分 UCI 選項自動轉成駝峰式（persist_max_age_hours → persistMaxAgeHours）；KB 結尾的另外對應
        apply(
            &mut m,
            d.get(name),
            sec(name),
            &[
                ("min_free_kb", Some("minFreeKB")),
                ("memory_budget_mb", Some("memoryBudgetMB")),
                ("flash_write_budget_kb", Some("flashWriteBudgetKB")),
            ],
        );
        if !m.is_empty() {
            out.insert(name.into(), Value::Object(m));
        }
    }
    // 資料目錄（main.data_dir，可以改到外接硬碟）
    let data_dir = s("main", "data_dir");
    if !data_dir.is_empty() {
        let sys = out.entry("system").or_insert_with(|| json!({}));
        sys["persistDir"] = json!(data_dir);
    }
    Value::Object(out)
}

/// 讀取 UCI：`KUROSHIO_UCI_JSON`（init 先存的 `ubus call uci get` 結果）或直接讀 /etc/config/kuroshio
pub fn load(env: &Env) -> Result<Value> {
    Ok(overrides(&load_raw()?, env))
}

/// UCI 設定檔的位置（`KUROSHIO_UCI_FILE`，預設 /etc/config/kuroshio）
pub fn file_path() -> String {
    std::env::var("KUROSHIO_UCI_FILE").unwrap_or_else(|_| "/etc/config/kuroshio".into())
}

/// 還沒轉換的 UCI 內容（`{ values: {...} }`）
pub fn load_raw() -> Result<Value> {
    if let Ok(f) = std::env::var("KUROSHIO_UCI_JSON") {
        if let Ok(b) = std::fs::read(&f) {
            return Ok(serde_json::from_slice(&b)?);
        }
    }
    let path = file_path();
    let text = std::fs::read_to_string(&path).map_err(|e| anyhow::anyhow!("讀不到 {path}：{e}"))?;
    parse_text(&text)
}

/// 憑證由誰管理：`acme`（acme.sh 申請、放在 `<etc>/cert.pem`）或 `manual`（使用者自備）
pub fn cert_mode(uci: &Value) -> &'static str {
    let vals = uci.get("values").unwrap_or(uci);
    match vals.get("tls").and_then(|t| t.get("cert_mode")).and_then(Value::as_str) {
        Some("manual") => "manual",
        _ => "acme",
    }
}
