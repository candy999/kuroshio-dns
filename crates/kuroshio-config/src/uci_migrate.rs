//! UCI 設定檔的升級遷移（`kuroshio uci-migrate`）：直接改 UCI 文字檔，不需要 `uci` 指令，給 Padavan 等第三方韌體用。
//!
//! 規則跟 OpenWrt 套件的 `openwrt/kuroshio/files/kuroshio.uci-defaults` 一樣（兩邊要一起改）：
//!
//! - **3.2**（`main.lists_version` 不是 3.2 / 3.3 時）：預設過濾清單更新。只動「跟 3.1.x 預設值完全相同」的
//!   `filter_list`（啟用、分類、網址、名稱都沒改，也沒有其他選項）；加上 TWNIC-RPZ、OISD small、HaGeZi Light（同網址不重複加）；
//!   清單順序沒被調整過的話，依新的預設順序排列
//! - **3.3**（`lists_version` 是 3.2 時）：最後加上四份預設不勾選的大清單（同網址不重複加）
//!
//! 做過的版本記在 `main.lists_version`，之後不再重做（使用者刪掉的清單不會被加回來）。
//! 檔案的其他內容（註解、其他區段、選項順序）原樣保留。

use anyhow::{bail, Result};

const L_EASYLIST: &str = "https://easylist-downloads.adblockplus.org/easylistchina.txt";
const L_ANTIAD: &str = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt";
const L_LOWTECH: &str = "https://filter.futa.gg/hosts_abp.txt";
const L_TRACKING: &str = "https://raw.githubusercontent.com/blocklistproject/Lists/master/tracking.txt";
const L_FARM: &str = "https://danny0838.github.io/content-farm-terminator/files/blocklist/content-farms.txt";
const L_DOVE_OLD: &str = "https://raw.githubusercontent.com/ignaciocastro/a-dove-is-dumb/main/list.txt";
const L_DOVE: &str = "https://a.dove.isdumb.one/cdn";
const L_RUDDER: &str = "https://raw.githubusercontent.com/Ruddernation-Designs/Adobe-URL-Block-List/master/hosts";
const L_SMARTTV: &str = "https://raw.githubusercontent.com/blocklistproject/Lists/master/smart-tv.txt";
const L_ADOBE: &str = "https://raw.githubusercontent.com/blocklistproject/Lists/master/adobe.txt";
const L_TW165: &str = "https://filter.futa.gg/TW165_abp.txt";
const L_TIF_FULL: &str = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt";
const L_TIF: &str = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt";
const L_NRD: &str = "https://filter.futa.gg/nrd/past-07day_abp.txt";
const L_TWNIC: &str = "https://filter.futa.gg/TWNIC-RPZ_abp.txt";
const L_OISD: &str = "https://small.oisd.nl/";
const L_LIGHT: &str = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/light.txt";
const L_PROPLUS: &str = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt";
const L_ADGUARD: &str = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt";
const L_TIF_BIG: &str = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt";
const L_BYPASS: &str = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh-vpn-proxy-bypass.txt";

/// 3.1.x 預設清單的順序（第幾份）
fn old_list_pos(url: &str) -> Option<u32> {
    [
        L_EASYLIST, L_ANTIAD, L_LOWTECH, L_TRACKING, L_FARM, L_DOVE_OLD, L_RUDDER, L_SMARTTV, L_ADOBE, L_TW165, L_TIF_FULL, L_NRD,
    ]
    .iter()
    .position(|u| *u == url)
    .map(|p| p as u32 + 1)
}

/// 一個區段（`config` 那一行到下一個 `config` 之前，含中間的註解與空行）
#[derive(Debug, Clone)]
struct Sec {
    typ: String,
    name: Option<String>,
    lines: Vec<String>,
}

fn unq(s: &str) -> String {
    let s = s.trim();
    let inner = if s.len() >= 2 && ((s.starts_with('\'') && s.ends_with('\'')) || (s.starts_with('"') && s.ends_with('"'))) {
        &s[1..s.len() - 1]
    } else {
        s
    };
    inner.replace("'\\''", "'")
}

fn quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\\''"))
}

impl Sec {
    fn new_list(enabled: bool, name: &str, url: &str, category: &str) -> Sec {
        Sec {
            typ: "filter_list".into(),
            name: None,
            lines: vec![
                String::new(),
                "config filter_list".into(),
                format!("\toption enabled {}", quote(if enabled { "1" } else { "0" })),
                format!("\toption name {}", quote(name)),
                format!("\toption url {}", quote(url)),
                format!("\toption category {}", quote(category)),
            ],
        }
    }

    /// （關鍵字, 名稱, 值）：只看 option / list 行
    fn entries(&self) -> Vec<(String, String, String)> {
        self.lines
            .iter()
            .filter_map(|l| {
                let t = l.trim();
                let mut it = t.splitn(3, char::is_whitespace);
                let (kw, k, v) = (it.next()?, it.next()?, it.next().unwrap_or(""));
                matches!(kw, "option" | "list").then(|| (kw.to_string(), k.to_string(), unq(v)))
            })
            .collect()
    }

    fn get(&self, key: &str) -> Option<String> {
        self.entries()
            .into_iter()
            .find(|(kw, k, _)| kw == "option" && k == key)
            .map(|e| e.2)
    }

    fn set(&mut self, key: &str, val: &str) {
        let line = format!("\toption {key} {}", quote(val));
        let found = self.lines.iter().position(|l| {
            let mut it = l.split_whitespace();
            it.next() == Some("option") && it.next() == Some(key)
        });
        match found {
            Some(i) => self.lines[i] = line,
            None => {
                // 放在最後一個 option / list 後面（後面的空行、註解屬於下一段之前）
                let last = self
                    .lines
                    .iter()
                    .rposition(|l| {
                        let t = l.trim_start();
                        t.starts_with("option ") || t.starts_with("list ") || t.starts_with("config ")
                    })
                    .unwrap_or(0);
                self.lines.insert(last + 1, line);
            }
        }
    }

    /// 只有 enabled / name / url / category 這幾個選項（使用者沒加其他東西）
    fn plain_list(&self) -> bool {
        self.entries()
            .iter()
            .all(|(kw, k, _)| kw == "option" && matches!(k.as_str(), "enabled" | "name" | "url" | "category"))
    }
}

fn parse(text: &str) -> Result<(Vec<String>, Vec<Sec>)> {
    let mut head = Vec::new();
    let mut secs: Vec<Sec> = Vec::new();
    for l in text.lines() {
        let t = l.trim();
        if t.starts_with("config ") || t == "config" {
            let mut it = t.splitn(3, char::is_whitespace);
            let _ = it.next();
            let typ = it.next().unwrap_or("").to_string();
            if typ.is_empty() {
                bail!("UCI 解析錯誤：config 後面沒有區段類型：{t}");
            }
            let name = it.next().map(unq).filter(|n| !n.is_empty());
            secs.push(Sec {
                typ,
                name,
                lines: vec![l.to_string()],
            });
        } else {
            match secs.last_mut() {
                Some(s) => s.lines.push(l.to_string()),
                None => head.push(l.to_string()),
            }
        }
    }
    Ok((head, secs))
}

/// 遷移的結果
#[derive(Debug, Clone)]
pub struct Migrated {
    /// 新的設定檔內容
    pub text: String,
    /// 做了什麼（給人看）；空的表示不需要改
    pub log: Vec<String>,
}

/// 依 `main.lists_version` 套用還沒做過的遷移
pub fn migrate(text: &str) -> Result<Migrated> {
    let (head, mut secs) = parse(text)?;
    let mut log = Vec::new();
    let main = secs
        .iter()
        .position(|s| s.typ == "kuroshio" && s.name.as_deref() == Some("main"))
        .ok_or_else(|| anyhow::anyhow!("找不到 `config kuroshio 'main'` 區段，這不是黑潮 DNS 的 UCI 設定檔"))?;
    let lists_version = secs[main].get("lists_version").unwrap_or_default();
    let by_url = |secs: &Vec<Sec>, url: &str| {
        secs.iter()
            .position(|s| s.typ == "filter_list" && s.get("url").as_deref() == Some(url))
    };
    let add = |secs: &mut Vec<Sec>, log: &mut Vec<String>, en: bool, name: &str, url: &str, cat: &str| {
        if by_url(secs, url).is_none() {
            secs.push(Sec::new_list(en, name, url, cat));
            log.push(format!("新增「{name}」"));
        }
    };

    if lists_version != "3.2" && lists_version != "3.3" {
        // 順序沒被調整過（舊預設清單維持原本的先後，自己加的都在它們後面）才重新排序
        let mut sorted = true;
        let (mut last, mut other) = (0u32, false);
        for s in secs.iter().filter(|s| s.typ == "filter_list") {
            match old_list_pos(&s.get("url").unwrap_or_default()) {
                None => other = true,
                Some(p) if other || p <= last => {
                    sorted = false;
                    break;
                }
                Some(p) => last = p,
            }
        }
        let mut i = 0;
        while i < secs.len() {
            let s = &secs[i];
            if s.typ != "filter_list" || !s.plain_list() {
                i += 1;
                continue;
            }
            let key = format!(
                "{}|{}|{}|{}",
                s.get("enabled").unwrap_or_else(|| "1".into()),
                s.get("category").unwrap_or_default(),
                s.get("url").unwrap_or_default(),
                s.get("name").unwrap_or_default()
            );
            let s = &mut secs[i];
            if key == format!("1|telemetry|{L_RUDDER}|Ruddernation（Adobe 驗證）") {
                s.set("enabled", "0");
                s.set("name", "Ruddernation（Adobe 驗證，會擋 Adobe 正版啟用）");
                log.push("Ruddernation 改成預設停用（會擋 Adobe 正版啟用）".into());
            } else if key == format!("1|telemetry|{L_DOVE_OLD}|a-dove-is-dumb（Adobe 遙測）") {
                s.set("url", L_DOVE);
                log.push("a-dove-is-dumb 改用官方 CDN 網址".into());
            } else if key == format!("0|malware|{L_TIF_FULL}|HaGeZi's Threat Intelligence Feeds") {
                s.set("enabled", "1");
                s.set("name", "HaGeZi TIF 精簡版（威脅情資）");
                s.set("url", L_TIF);
                log.push("HaGeZi TIF 完整版換成精簡版並啟用".into());
            } else if key == format!("0|ads|{L_TRACKING}|blocklistproject tracking") {
                secs.remove(i);
                log.push("移除 blocklistproject tracking".into());
                continue;
            } else if key == format!("0|telemetry|{L_ADOBE}|blocklistproject adobe（會擋 Adobe 登入）") {
                secs.remove(i);
                log.push("移除 blocklistproject adobe".into());
                continue;
            }
            i += 1;
        }
        add(
            &mut secs,
            &mut log,
            true,
            "FutaGuard TWNIC-RPZ（台灣網路資訊中心停止解析）",
            L_TWNIC,
            "malware",
        );
        add(&mut secs, &mut log, true, "OISD small", L_OISD, "ads");
        add(&mut secs, &mut log, true, "HaGeZi Light", L_LIGHT, "ads");
        if sorted {
            // 依新的預設順序排在原本第一份清單的位置；不是預設網址的清單照原本的相對順序接在後面
            if let Some(mut pos) = secs.iter().position(|s| s.typ == "filter_list") {
                for u in [
                    L_TW165, L_TWNIC, L_TIF, L_NRD, L_LOWTECH, L_ANTIAD, L_EASYLIST, L_OISD, L_LIGHT, L_FARM, L_DOVE, L_SMARTTV, L_RUDDER,
                ] {
                    if let Some(k) = by_url(&secs, u) {
                        let s = secs.remove(k);
                        let at = pos.min(secs.len());
                        secs.insert(at, s);
                        pos += 1;
                    }
                }
            }
        } else {
            log.push("清單順序是自己調整過的，不重新排序".into());
        }
        let m = secs
            .iter()
            .position(|s| s.typ == "kuroshio" && s.name.as_deref() == Some("main"))
            .unwrap();
        secs[m].set("lists_version", "3.2");
    }

    let m = secs
        .iter()
        .position(|s| s.typ == "kuroshio" && s.name.as_deref() == Some("main"))
        .unwrap();
    if secs[m].get("lists_version").as_deref() == Some("3.2") {
        // 3.3：最後加上預設不勾選的大清單
        add(
            &mut secs,
            &mut log,
            false,
            "HaGeZi Pro++（廣告追蹤加強版，約 27 萬條）",
            L_PROPLUS,
            "ads",
        );
        add(&mut secs, &mut log, false, "AdGuard DNS filter（約 19 萬條）", L_ADGUARD, "ads");
        add(
            &mut secs,
            &mut log,
            false,
            "HaGeZi TIF 完整版（威脅情資，約 146 萬條、15 MB 記憶體）",
            L_TIF_BIG,
            "malware",
        );
        add(
            &mut secs,
            &mut log,
            false,
            "HaGeZi 加密 DNS／VPN／代理繞過（企業用：裝置無法自己改用其他 DNS）",
            L_BYPASS,
            "malware",
        );
        secs[m].set("lists_version", "3.3");
    }

    let mut out: Vec<String> = head;
    for s in &secs {
        out.extend(s.lines.iter().cloned());
    }
    let mut text_out = out.join("\n");
    text_out.push('\n');
    let new_version = secs[m].get("lists_version").unwrap_or_default();
    if new_version != lists_version {
        log.push(format!(
            "lists_version：{} → {new_version}",
            if lists_version.is_empty() { "（沒有）" } else { &lists_version }
        ));
    }
    if log.is_empty() && secs_unchanged(text, &text_out) {
        return Ok(Migrated {
            text: text.to_string(),
            log,
        });
    }
    Ok(Migrated { text: text_out, log })
}

fn secs_unchanged(a: &str, b: &str) -> bool {
    a.trim_end() == b.trim_end()
}
