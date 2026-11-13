//! 給其他平台（Docker、第三方路由器韌體、一般 Linux 的服務管理）用的穩定介面：
//! `kuroshio health`、`kuroshio status --json`、`kuroshio notify wan-changed`、`KUROSHIO_INIT_CONFIG`。
//! 完整說明見 `docs/integration.md`（那份是對外的約定，這裡改了要一起改）。
//!
//! # `kuroshio status --json` 的欄位
//!
//! 一行 JSON。服務在執行時（結束碼 0）：
//!
//! | 欄位 | 型別 | 說明 |
//! |---|---|---|
//! | `running` | bool | 一定是 `true` |
//! | `version` | string | 執行中服務的版本 |
//! | `uptimeSec` | number | 這一輪啟動以來的秒數（重新載入設定會歸零） |
//! | `mode` | string | `service`（Windows 服務）或 `cmd`（前景執行，含 procd / systemd / Docker） |
//! | `config` | string | 設定來源：`uci`（OpenWrt）或 `json` |
//! | `upstreams` | array | `{url, type, role, ok}`：`type` = udp/tcp/dot/doh/doh3/doq/dnscrypt；`role` = pinned/auto/fallback；`ok` = 沒有暫停而且不是「只失敗過」 |
//! | `cache.entries` | number | 快取筆數 |
//! | `cache.hitRate` | number \| null | 今天的快取命中率（0–1），今天還沒有查詢是 `null` |
//! | `filter.enabled` | bool | 過濾有沒有開 |
//! | `filter.rules` | number | 規則數（自訂 + 清單，去重後） |
//! | `filter.lists` | number | 已載入的清單數 |
//! | `storage.class` | string | 快照目錄的儲存類型：`flash` / `disk` / `ram` |
//! | `storage.dir` | string | 快照目錄 |
//! | `storage.oldestUnsavedSec` | number \| null | 還沒寫出的變動最久的有幾秒，沒有是 `null` |
//! | `memory.pressure` | string | `normal` / `low` / `critical` |
//! | `clock.synced` | bool | 系統時間有沒有對時（沒對時只用明文上游、背景工作延後） |
//! | `data.dir` | string | 唯讀資料（data/）的位置 |
//! | `data.format` | number \| null | data/manifest.json 的 `dataFormat` |
//! | `data.version` | string \| null | data/manifest.json 的 `version` |
//! | `data.ok` | bool | data/ 跟執行檔相容 |
//! | `data.warning` | string \| null | data/ 的問題（也會出現在 `warnings`） |
//! | `warnings` | array of string | 需要注意的事（data/ 不相容、時間沒對時、記憶體吃緊、清單被停用），沒有是 `[]` |
//!
//! 服務沒有回應（結束碼 1）或設定讀不到（結束碼 2）：`{"running": false, "error": "..."}`。
//! 之後只會加欄位，不會改名或改型別。

use crate::sysinfo::Pressure;
use kuroshio_config::get;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

/// `/api/status.warnings`：需要使用者注意的事
pub fn warnings(data: &crate::manifest::DataCheck, synced: bool, pressure: Pressure, filter: &Value) -> Vec<String> {
    let mut w = Vec::new();
    if let Some(d) = &data.warning {
        w.push(d.clone());
    }
    if !synced {
        w.push("系統時間還沒對時：暫時只用明文上游，需要 TLS 的背景工作延後".into());
    }
    match pressure {
        Pressure::Normal => {}
        Pressure::Low => w.push("記憶體接近保留量：背景工作延後".into()),
        Pressure::Critical => w.push("記憶體不足：已讓出記憶體、暫不接受新的加密連線".into()),
    }
    if let Some(n) = filter.get("notice").and_then(Value::as_str) {
        w.push(n.to_string());
    }
    w
}

/// `kuroshio health` 要問的位址：明文 DNS 的埠與第一個綁定位址（0.0.0.0 / :: / 沒寫 → 127.0.0.1 / ::1）。
/// 明文 DNS 關掉時回錯誤說明
pub fn health_target(cfg: &Value) -> Result<SocketAddr, String> {
    if get(cfg, "listen.plain.enabled").and_then(Value::as_bool) == Some(false) {
        return Err("明文 DNS 沒有開啟（listen.plain.enabled = false），無法用 DNS 查詢確認".into());
    }
    let port = get(cfg, "listen.plain.port").and_then(Value::as_u64).unwrap_or(53);
    let port = u16::try_from(port).map_err(|_| format!("listen.plain.port 不是有效的埠號：{port}"))?;
    let first = get(cfg, "listen.plain.binds")
        .and_then(Value::as_array)
        .and_then(|a| a.iter().filter_map(Value::as_str).map(str::trim).find(|s| !s.is_empty()));
    let ip = match first {
        None => IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some(s) => s.parse::<IpAddr>().map_err(|_| format!("listen.plain.binds 的位址格式錯誤：{s}"))?,
    };
    let ip = match ip {
        IpAddr::V4(a) if a.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(a) if a.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    Ok(SocketAddr::new(ip, port))
}

/// `kuroshio health --json` 的一行
pub fn health_json(server: SocketAddr, ms: Option<u64>, rcode: Option<u8>, error: Option<&str>) -> Value {
    json!({ "ok": error.is_none(), "server": server.to_string(), "ms": ms, "rcode": rcode, "error": error })
}

fn upstream_ok(u: &Value) -> bool {
    let n = |k: &str| u.get(k).and_then(Value::as_u64).unwrap_or(0);
    u.get("paused") != Some(&Value::Bool(true)) && !(n("fail") > 0 && n("ok") == 0)
}

/// `/api/status` → `kuroshio status --json` 的穩定格式（欄位見本模組說明）
pub fn summarize_status(api: &Value) -> Value {
    let today = &api["stats"]["today"];
    let (hit, miss) = (
        today.get("hit").and_then(Value::as_u64).unwrap_or(0),
        today.get("miss").and_then(Value::as_u64).unwrap_or(0),
    );
    let hit_rate = (hit + miss > 0).then(|| ((hit as f64 / (hit + miss) as f64) * 1000.0).round() / 1000.0);
    let upstreams: Vec<Value> = api["upstreams"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|u| json!({ "url": u["id"], "type": u["type"], "role": u["role"], "ok": upstream_ok(u) }))
                .collect()
        })
        .unwrap_or_default();
    let f = &api["filter"];
    let filter = if f.is_object() {
        let rules = f["custom"].as_u64().unwrap_or(0) + f["lists"].as_u64().unwrap_or(0);
        let lists = f["sources"]
            .as_array()
            .map(|a| a.iter().filter(|s| s["status"] == "loaded").count())
            .unwrap_or(0);
        json!({ "enabled": true, "rules": rules, "lists": lists })
    } else {
        json!({ "enabled": false, "rules": 0, "lists": 0 })
    };
    let p = &api["system"]["persist"];
    let d = &api["data"];
    json!({
        "running": true,
        "version": api["version"],
        "uptimeSec": api["stats"]["uptimeSec"],
        "mode": api.get("mode").cloned().unwrap_or(json!("cmd")),
        "config": if api["uci"] == true { "uci" } else { "json" },
        "upstreams": upstreams,
        "cache": { "entries": api["cacheEntries"], "hitRate": hit_rate },
        "filter": filter,
        "storage": { "class": p["class"], "dir": p["dir"], "oldestUnsavedSec": p["oldestUnsavedSec"] },
        "memory": { "pressure": api["system"]["pressure"] },
        "clock": { "synced": api["clock"]["synced"].as_bool().unwrap_or(true) },
        "data": { "dir": d["dir"], "format": d["format"], "version": d["version"], "ok": d["ok"].as_bool().unwrap_or(false), "warning": d["warning"] },
        "warnings": api.get("warnings").filter(|w| w.is_array()).cloned().unwrap_or(json!([])),
    })
}

/// `kuroshio status`（沒有 --json）：幾行給人看的摘要
pub fn status_text(s: &Value) -> String {
    let up = s["upstreams"].as_array().map(Vec::as_slice).unwrap_or_default();
    let ok = up.iter().filter(|u| u["ok"] == true).count();
    let secs = s["uptimeSec"].as_u64().unwrap_or(0);
    let mut out = format!(
        "黑潮 DNS {} 執行中（{}，已執行 {} 天 {} 小時 {} 分）\n上游：{ok} / {} 正常；快取 {} 筆{}；過濾：{}\n快照：{}（{}）；系統時間：{}；data/：{}",
        s["version"].as_str().unwrap_or("?"),
        if s["config"] == "uci" { "UCI 設定" } else { "JSON 設定" },
        secs / 86_400,
        secs % 86_400 / 3600,
        secs % 3600 / 60,
        up.len(),
        s["cache"]["entries"].as_u64().unwrap_or(0),
        s["cache"]["hitRate"]
            .as_f64()
            .map(|r| format!("，今天命中率 {:.1}%", r * 100.0))
            .unwrap_or_default(),
        if s["filter"]["enabled"] == true {
            format!("{} 條規則、{} 份清單", s["filter"]["rules"], s["filter"]["lists"])
        } else {
            "沒有開".into()
        },
        s["storage"]["dir"].as_str().unwrap_or("?"),
        s["storage"]["class"].as_str().unwrap_or("?"),
        if s["clock"]["synced"] == false { "還沒對時" } else { "已對時" },
        match (s["data"]["ok"] == true, s["data"]["version"].as_str()) {
            (true, Some(v)) => format!("{v} 版"),
            _ => "有問題".into(),
        },
    );
    for w in s["warnings"].as_array().into_iter().flatten() {
        out.push_str(&format!("\n注意：{}", w.as_str().unwrap_or("")));
    }
    out
}

/// 純函式：`KUROSHIO_INIT_CONFIG`（容器映像附的預設設定）要不要複製到 `-c` 的位置。
/// 只有設定檔不存在、而且預設設定存在時才複製；回傳來源
pub fn init_config_source(config: &Path, init: Option<&str>) -> Option<PathBuf> {
    let src = PathBuf::from(init.map(str::trim).filter(|s| !s.is_empty())?);
    (!config.exists() && src.is_file()).then_some(src)
}

/// `KUROSHIO_INIT_CONFIG`：需要時建立上層目錄並複製。回傳複製了的來源（沒複製是 None）
pub fn apply_init_config(config: &Path, init: Option<&str>) -> std::io::Result<Option<PathBuf>> {
    let Some(src) = init_config_source(config, init) else {
        return Ok(None);
    };
    if let Some(dir) = config.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::copy(&src, config)?;
    Ok(Some(src))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(over: Value) -> Value {
        kuroshio_config::with_overrides(&over)
    }

    #[test]
    fn health_target_from_config() {
        let t = |over: Value| health_target(&cfg(over));
        assert_eq!(
            t(json!({ "listen": { "plain": { "binds": ["0.0.0.0", "::"], "port": 5335 } } })),
            Ok("127.0.0.1:5335".parse().unwrap())
        );
        assert_eq!(
            t(json!({ "listen": { "plain": { "binds": ["::"], "port": 53 } } })),
            Ok("[::1]:53".parse().unwrap())
        );
        assert_eq!(
            t(json!({ "listen": { "plain": { "binds": [], "port": 5353 } } })),
            Ok("127.0.0.1:5353".parse().unwrap())
        );
        assert_eq!(
            t(json!({ "listen": { "plain": { "binds": ["192.0.2.1", "127.0.0.1"], "port": 53 } } })),
            Ok("192.0.2.1:53".parse().unwrap())
        );
        assert!(t(json!({ "listen": { "plain": { "enabled": false } } }))
            .unwrap_err()
            .contains("沒有開啟"));
        assert!(t(json!({ "listen": { "plain": { "binds": ["不是位址"] } } })).is_err());
        assert!(t(json!({ "listen": { "plain": { "port": 70000 } } })).is_err());
        // 預設設定：一定解得出一個位址
        assert!(health_target(&kuroshio_config::build(&json!({}))).is_ok());
    }

    /// OpenWrt：--uci 解出來的位址要跟 guard.sh 一樣（exchange 模式 53 埠，其他 main.dns_port），而且一律是 127.0.0.1
    #[test]
    fn health_target_matches_guard_script() {
        for (mode, lan4, port) in [
            ("dnsmasq-upstream", "", 5335),
            ("hijack", "", 5335),
            ("hijack", "192.0.2.1", 5335),
            ("redirect", "", 5335),
            ("exchange", "", 53),
        ] {
            let raw = json!({ "values": { "main": { ".type": "kuroshio", "redirect": mode, "dns_port": "5335" } } });
            let env = kuroshio_config::uci::Env {
                etc: "/etc/kuroshio".into(),
                lan4: lan4.into(),
                ula: String::new(),
            };
            let c = kuroshio_config::build(&kuroshio_config::uci::overrides(&raw, &env));
            assert_eq!(
                health_target(&c),
                Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
                "{mode} {lan4}"
            );
        }
    }

    #[test]
    fn status_summary_is_stable() {
        let api = json!({
            "version": "3.1.0", "mode": "cmd", "uci": false,
            "stats": { "uptimeSec": 3725, "today": { "hit": 3, "miss": 1 } },
            "cacheEntries": 42,
            "upstreams": [
                { "id": "udp://192.0.2.53:53", "type": "udp", "role": "pinned", "ok": 5, "fail": 1, "paused": false },
                { "id": "https://dns.example.net/dns-query", "type": "doh", "role": "auto", "ok": 0, "fail": 3, "paused": false },
                { "id": "tls://dns.example.com:853", "type": "dot", "role": "auto", "ok": 9, "fail": 0, "paused": true },
                { "id": "udp://198.51.100.1:53", "type": "udp", "role": "fallback", "ok": 0, "fail": 0, "paused": false }
            ],
            "filter": { "custom": 2, "lists": 100, "sources": [{ "status": "loaded" }, { "status": "unloaded" }], "notice": null },
            "system": { "pressure": "normal", "persist": { "class": "flash", "dir": "/etc/kuroshio/state", "oldestUnsavedSec": 12 } },
            "clock": { "synced": true },
            "data": { "dir": "/usr/share/kuroshio", "format": 1, "version": "3.1.0", "ok": true, "warning": null },
            "warnings": []
        });
        let s = summarize_status(&api);
        assert_eq!(s["running"], true);
        assert_eq!(s["version"], "3.1.0");
        assert_eq!(s["uptimeSec"], 3725);
        assert_eq!(s["mode"], "cmd");
        assert_eq!(s["config"], "json");
        let ok: Vec<bool> = s["upstreams"].as_array().unwrap().iter().map(|u| u["ok"] == true).collect();
        assert_eq!(ok, vec![true, false, false, true]);
        assert_eq!(s["upstreams"][0]["url"], "udp://192.0.2.53:53");
        assert_eq!(s["cache"], json!({ "entries": 42, "hitRate": 0.75 }));
        assert_eq!(s["filter"], json!({ "enabled": true, "rules": 102, "lists": 1 }));
        assert_eq!(s["storage"]["class"], "flash");
        assert_eq!(s["storage"]["oldestUnsavedSec"], 12);
        assert_eq!(s["clock"]["synced"], true);
        assert_eq!(s["data"]["ok"], true);
        assert_eq!(s["warnings"], json!([]));
        let text = status_text(&s);
        assert!(text.contains("3.1.0") && text.contains("2 / 4") && text.contains("75.0%"), "{text}");

        // 欄位缺少（舊版服務、過濾沒開）時也是同樣的形狀
        let s = summarize_status(&json!({ "version": "3.0.2" }));
        for k in [
            "running",
            "version",
            "uptimeSec",
            "mode",
            "config",
            "upstreams",
            "cache",
            "filter",
            "storage",
            "memory",
            "clock",
            "data",
            "warnings",
        ] {
            assert!(s.get(k).is_some(), "{k}");
        }
        assert_eq!(s["filter"]["enabled"], false);
        assert_eq!(s["cache"]["hitRate"], Value::Null);
        assert_eq!(s["warnings"], json!([]));
    }

    #[test]
    fn warning_list() {
        let ok = crate::manifest::evaluate(Path::new("d"), Some(r#"{"dataFormat":1,"version":"x"}"#), 1, "x");
        assert!(warnings(&ok, true, Pressure::Normal, &Value::Null).is_empty());
        let bad = crate::manifest::evaluate(Path::new("d"), None, 1, "x");
        let w = warnings(&bad, false, Pressure::Low, &json!({ "notice": "記憶體不足，暫時停用：ads 清單" }));
        assert_eq!(w.len(), 4);
        assert!(w[0].contains("沒有版本標記"));
        assert!(w[1].contains("對時"));
    }

    #[test]
    fn init_config_copy() {
        let dir = std::env::temp_dir().join(format!("kuroshio-initcfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("default.json");
        std::fs::write(&src, b"{\"domain\":\"dns.example.com\"}").unwrap();
        let dst = dir.join("config/sub/config.json");
        let s = src.to_str().unwrap();
        // 沒設定、來源不存在：不做
        assert_eq!(apply_init_config(&dst, None).unwrap(), None);
        assert_eq!(apply_init_config(&dst, Some("")).unwrap(), None);
        assert_eq!(
            apply_init_config(&dst, Some(dir.join("nope.json").to_str().unwrap())).unwrap(),
            None
        );
        assert!(!dst.exists());
        // 設定檔不存在：建立目錄並複製
        assert_eq!(apply_init_config(&dst, Some(s)).unwrap(), Some(src.clone()));
        assert_eq!(std::fs::read(&dst).unwrap(), std::fs::read(&src).unwrap());
        // 已經有了：不覆蓋使用者改過的
        std::fs::write(&dst, b"{}").unwrap();
        assert_eq!(apply_init_config(&dst, Some(s)).unwrap(), None);
        assert_eq!(std::fs::read(&dst).unwrap(), b"{}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
