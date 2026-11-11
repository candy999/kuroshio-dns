//! CDNtest Step1（對齊 2.x `jobs/cdn-ranges.js`）：抓取各家 CDN 官方 IP 範圍 →
//! `state/cdn/ranges/<cdn>-ipv4.txt` / `-ipv6.txt`。內容沒變不寫；抓取失敗保留舊資料。

use super::JobCtx;
use crate::util::{self, write_if_changed};
use anyhow::{anyhow, bail, Context, Result};
use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;
use tracing::{info, warn};

/// 有官方清單的 CDN（順序同 2.x）
pub const SOURCES: [&str; 5] = ["cloudflare", "cloudfront", "fastly", "gcore", "azure"];

const TIMEOUT: Duration = Duration::from_secs(60);
const MAX_JSON: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub provider: String,
    /// （IPv4 筆數，IPv6 筆數，檔案有沒有變）或失敗原因
    pub result: Result<(usize, usize, bool), String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    pub providers: Vec<Outcome>,
    /// 有任何檔案更新
    pub changed: bool,
}

async fn text(ctx: &JobCtx, url: &str) -> Result<String> {
    ctx.cdn.net().fetch_text(url, MAX_JSON, TIMEOUT).await
}

async fn json(ctx: &JobCtx, url: &str) -> Result<Value> {
    let t = text(ctx, url).await?;
    serde_json::from_str(t.trim_start_matches('\u{feff}')).context("JSON 格式錯誤")
}

fn strs(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

/// Azure ServiceTags：只留 AzureFrontDoor.Frontend 與 AzureCDN 的網段（其他項目略過不展開，省記憶體）
struct AzureTags(Vec<String>);

impl<'de> Deserialize<'de> for AzureTags {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Root;
        impl<'de> Visitor<'de> for Root {
            type Value = AzureTags;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("ServiceTags")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<AzureTags, A::Error> {
                let mut out = Vec::new();
                while let Some(k) = m.next_key::<String>()? {
                    if k == "values" {
                        out = m.next_value::<Values>()?.0;
                    } else {
                        m.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(AzureTags(out))
            }
        }
        struct Values(Vec<String>);
        impl<'de> Deserialize<'de> for Values {
            fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl<'de> Visitor<'de> for V {
                    type Value = Values;
                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        f.write_str("values")
                    }
                    fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Values, A::Error> {
                        let mut out = Vec::new();
                        while let Some(t) = s.next_element::<Tag>()? {
                            out.extend(t.0);
                        }
                        Ok(Values(out))
                    }
                }
                d.deserialize_seq(V)
            }
        }
        struct Tag(Vec<String>);
        impl<'de> Deserialize<'de> for Tag {
            fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl<'de> Visitor<'de> for V {
                    type Value = Tag;
                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        f.write_str("tag")
                    }
                    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Tag, A::Error> {
                        let mut name: Option<String> = None;
                        let mut prefixes: Option<Vec<String>> = None;
                        while let Some(k) = m.next_key::<String>()? {
                            match k.as_str() {
                                "name" => name = Some(m.next_value()?),
                                // 名稱已知而且不需要：不展開
                                "properties" if name.as_deref().map(wanted).unwrap_or(true) => {
                                    prefixes = Some(m.next_value::<Props>()?.0);
                                }
                                _ => {
                                    m.next_value::<IgnoredAny>()?;
                                }
                            }
                        }
                        Ok(Tag(if name.as_deref().map(wanted).unwrap_or(false) {
                            prefixes.unwrap_or_default()
                        } else {
                            vec![]
                        }))
                    }
                }
                d.deserialize_map(V)
            }
        }
        #[derive(Deserialize)]
        struct PropsRaw {
            #[serde(default, rename = "addressPrefixes")]
            address_prefixes: Vec<String>,
        }
        struct Props(Vec<String>);
        impl<'de> Deserialize<'de> for Props {
            fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Ok(Props(PropsRaw::deserialize(d)?.address_prefixes))
            }
        }
        fn wanted(n: &str) -> bool {
            n == "AzureFrontDoor.Frontend" || n == "AzureCDN"
        }
        d.deserialize_map(Root)
    }
}

/// 解析 Azure ServiceTags JSON
pub fn parse_azure(b: &[u8]) -> Result<(Vec<String>, Vec<String>)> {
    let b = b.strip_prefix("\u{feff}".as_bytes()).unwrap_or(b);
    let t: AzureTags = serde_json::from_slice(b)?;
    let (v6, v4): (Vec<String>, Vec<String>) = t.0.into_iter().partition(|x| x.contains(':'));
    Ok((v4, v6))
}

fn find_service_tags_url(html: &str) -> Option<String> {
    let start = "https://download.microsoft.com/";
    let mut from = 0;
    while let Some(p) = html[from..].find(start) {
        let s = from + p;
        let end = html[s..].find(['"', '\'']).map(|e| s + e).unwrap_or(html.len());
        let u = &html[s..end];
        if let Some(i) = u.rfind("ServiceTags_Public_") {
            let tail = &u[i + "ServiceTags_Public_".len()..];
            if let Some(d) = tail.strip_suffix(".json") {
                if !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit()) {
                    return Some(u.to_string());
                }
            }
        }
        from = s + 1;
    }
    None
}

async fn fetch(ctx: &JobCtx, name: &str) -> Result<(Vec<String>, Vec<String>)> {
    match name {
        "cloudflare" => {
            let v4 = text(ctx, "https://www.cloudflare.com/ips-v4").await?;
            let v6 = text(ctx, "https://www.cloudflare.com/ips-v6").await?;
            Ok((
                v4.split_whitespace()
                    .filter(|l| l.bytes().any(|c| c.is_ascii_digit()))
                    .map(String::from)
                    .collect(),
                v6.split_whitespace().filter(|l| l.contains(':')).map(String::from).collect(),
            ))
        }
        "cloudfront" => {
            let j = json(ctx, "https://ip-ranges.amazonaws.com/ip-ranges.json").await?;
            let pick = |arr: &str, k: &str| -> Vec<String> {
                j.get(arr)
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter(|p| p.get("service").and_then(Value::as_str) == Some("CLOUDFRONT"))
                            .filter_map(|p| p.get(k).and_then(Value::as_str).map(String::from))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            Ok((pick("prefixes", "ip_prefix"), pick("ipv6_prefixes", "ipv6_prefix")))
        }
        "fastly" => {
            let j = json(ctx, "https://api.fastly.com/public-ip-list").await?;
            Ok((strs(&j, "addresses"), strs(&j, "ipv6_addresses")))
        }
        "gcore" => {
            let j = json(ctx, "https://api.gcore.com/cdn/public-ip-list").await?;
            Ok((strs(&j, "addresses"), strs(&j, "addresses_v6")))
        }
        "azure" => {
            // 先從下載頁找 ServiceTags_Public_*.json；失敗則找本地手動下載的檔案
            let online = async {
                let html = text(ctx, "https://www.microsoft.com/en-us/download/details.aspx?id=56519").await?;
                let url = find_service_tags_url(&html).ok_or_else(|| anyhow!("下載頁找不到 ServiceTags"))?;
                let body = ctx.cdn.net().fetch_text(&url, MAX_JSON, TIMEOUT).await?;
                parse_azure(body.as_bytes())
            }
            .await;
            match online {
                Ok(r) => Ok(r),
                Err(e) => {
                    let dir = &ctx.cdn.paths.cdn_data_dir;
                    let mut files: Vec<String> = std::fs::read_dir(dir)
                        .map(|rd| {
                            rd.filter_map(|e| e.ok())
                                .map(|e| e.file_name().to_string_lossy().into_owned())
                                .filter(|f| f.starts_with("ServiceTags_Public_") && f.ends_with(".json"))
                                .collect()
                        })
                        .unwrap_or_default();
                    files.sort();
                    let Some(f) = files.pop() else {
                        bail!("Azure 下載失敗（{e}），請手動下載 ServiceTags_Public_*.json 放到 {}", dir.display());
                    };
                    parse_azure(&std::fs::read(dir.join(f))?)
                }
            }
        }
        other => bail!("{other} 沒有官方 IP 範圍來源"),
    }
}

/// 執行：回傳每家的結果；全部失敗回錯誤
pub async fn run(ctx: &JobCtx) -> Result<Report> {
    let out = ctx.cdn.paths.state_dir.join("cdn").join("ranges");
    let mut report = Report::default();
    let mut ok = 0;
    for name in SOURCES {
        if !ctx.wants(name) {
            continue;
        }
        info!("[{name}] 抓取中…");
        let r = async {
            let (v4, v6) = fetch(ctx, name).await?;
            if v4.is_empty() {
                bail!("v4 範圍為空");
            }
            let c4 = write_if_changed(&out.join(format!("{name}-ipv4.txt")), format!("{}\n", v4.join("\n")).as_bytes())?;
            let c6 = write_if_changed(&out.join(format!("{name}-ipv6.txt")), format!("{}\n", v6.join("\n")).as_bytes())?;
            Ok((v4.len(), v6.len(), c4 || c6))
        }
        .await;
        match &r {
            Ok((n4, n6, changed)) => {
                info!(
                    "[{name}] 成功 IPv4 {n4} 筆 / IPv6 {n6} 筆{}",
                    if *changed { "（已更新）" } else { "（沒有變動）" }
                );
                report.changed |= changed;
                ok += 1;
            }
            Err(e) => warn!("[{name}] 失敗：{e}（保留舊資料）"),
        }
        report.providers.push(Outcome {
            provider: name.to_string(),
            result: r.map_err(|e| e.to_string()),
        });
    }
    let done = out.join(".done");
    if report.changed || !done.exists() {
        write_if_changed(&done, util::iso(util::now_ms()).as_bytes())?;
    }
    if report.changed {
        ctx.cdn.reload_ranges();
    }
    if ok == 0 {
        bail!("所有 CDN 範圍都抓取失敗");
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azure_tags_and_url() {
        let j = br#"{"changeNumber":1,"values":[
            {"name":"AzureCloud","id":"x","properties":{"addressPrefixes":["1.1.1.0/24"]}},
            {"name":"AzureFrontDoor.Frontend","properties":{"region":"","addressPrefixes":["13.107.246.0/24","2620:1ec:bdf::/48"]}},
            {"properties":{"addressPrefixes":["9.9.9.0/24"]},"name":"AzureCDN"}
        ]}"#;
        let (v4, v6) = parse_azure(j).unwrap();
        assert_eq!(v4, vec!["13.107.246.0/24", "9.9.9.0/24"]);
        assert_eq!(v6, vec!["2620:1ec:bdf::/48"]);
        let html = r#"<a href="https://download.microsoft.com/x/y/ServiceTags_Public_20261102.json">dl</a>"#;
        assert_eq!(
            find_service_tags_url(html).as_deref(),
            Some("https://download.microsoft.com/x/y/ServiceTags_Public_20261102.json")
        );
        assert_eq!(find_service_tags_url("https://download.microsoft.com/a.json"), None);
    }
}
