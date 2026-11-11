//! 產生台灣 IP 清單 `data/geo/tw-ip.json`（依 ISP 分組，規格 08）
//!
//! 資料來源（全部是公開資料，不用金鑰）：
//! - 五個 RIR 的 `delegated-*-extended-latest`：國別 TW 的 IPv4 / IPv6 配發（主要是 APNIC / TWNIC）。
//!   注意這是「登記國別」，不是地理位置。
//! - RIPEstat `announced-prefixes`：每個 ASN 目前在 BGP 宣告的網段。
//!
//! 做法：
//! 1. 台灣網段 = 所有 RIR 裡 cc=TW 的配發（合併）
//! 2. 每個 ISP 群組 = 它的 ASN 宣告的網段 ∩ 台灣網段（ISP 在國外宣告的網段不收，報表列出被排除的量）
//! 3. 「其他台灣網段」= 台灣網段 − 所有 ISP 群組 → 全部勾選 == 整個台灣
//! 4. 輸出排序、合併成最少的 CIDR；同樣的輸入一定得到同樣的輸出
//!
//! 用法（需要網路，GitHub Actions 每月跑一次）：
//!   cargo run --release -p kuroshio-jobs --bin tw-ip -- data/geo/tw-ip.json [報表.md]
//! 選項：
//!   --cache DIR   下載的原始資料存到 DIR；DIR 裡已經有的檔案直接用（離線重跑、或先用 curl 下載好）
//!   --offline     只用 --cache 裡的檔案，缺檔就失敗
//!   --date D      generatedAt 用 D（預設今天，UTC）

use anyhow::{bail, Context, Result};
use kuroshio_jobs::geo::{Dual, Net};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// 五個 RIR 的配發統計
const RIRS: [(&str, &str); 5] = [
    ("apnic", "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest"),
    ("arin", "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"),
    (
        "ripencc",
        "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    ),
    ("lacnic", "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest"),
    (
        "afrinic",
        "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
    ),
];

fn ripestat_url(asn: u32) -> String {
    format!("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}&min_peers_seeing=3")
}

/// ISP 群組。ASN 與持有者名稱對照 RIPE NCC 的 ASN 名稱表（ftp.ripe.net/ripe/asnames/asn.txt，來自各 RIR 的 whois）
/// 與 RIPEstat whois；只放「一般用戶上網」的 ASN，機房、CDN、國際轉接的 ASN 留在「其他台灣網段」。
struct GroupDef {
    id: &'static str,
    name: &'static str,
    note: &'static str,
    asns: &'static [u32],
}

const GROUPS: &[GroupDef] = &[
    GroupDef {
        id: "cht",
        name: "中華電信（HiNet、行動上網）",
        note: "AS3462 HINET、AS17421 EMOME-NET（行動）、AS17419 HINET-IPV6、AS131598 HILINK（企業專線）",
        asns: &[3462, 17421, 17419, 131598],
    },
    GroupDef {
        id: "twm",
        name: "台灣大哥大／台灣固網",
        note: "AS24158、AS131614、AS131647–131650 Taiwan Mobile；AS9924、AS4636、AS4747 Taiwan Fixed Network",
        asns: &[24158, 131614, 131647, 131648, 131649, 131650, 9924, 4636, 4747],
    },
    GroupDef {
        id: "tstar",
        name: "台灣之星（已併入台灣大哥大）",
        note: "AS24157 VIBO-NET-AS（Taiwan Star Telecom）。2023 年底與台灣大哥大合併，網段陸續移到台灣大的 ASN（大小是 0 表示已全部移過去）；兩組都勾才不會漏",
        asns: &[24157],
    },
    GroupDef {
        id: "fet",
        name: "遠傳電信／新世紀資通（Seednet）",
        note: "AS9674 FET-TW、AS18412 FEG-MPLS；AS4780 SEEDNET（數位聯合）、AS9919 與 AS24161 NCIC-TW（新世紀資通）",
        asns: &[9674, 18412, 4780, 9919, 24161],
    },
    GroupDef {
        id: "aptg",
        name: "亞太電信（已併入遠傳）",
        note: "AS17709 APT、AS24154 APBT、AS24155 APBW、AS7482 與 AS131142 APOL。2023 年底與遠傳合併，網段陸續移到遠傳的 ASN（大小是 0 表示已全部移過去）；兩組都勾才不會漏",
        asns: &[17709, 24154, 24155, 7482, 131142],
    },
    GroupDef {
        id: "kbro",
        name: "凱擘大寬頻",
        note: "AS38841 kbro-AS-TW",
        asns: &[38841],
    },
    GroupDef {
        id: "cns",
        name: "中嘉寬頻（bb 寬頻）",
        note: "AS9416、AS18042 KBT（Koos Broadband Telecom／和信超媒體）",
        asns: &[9416, 18042],
    },
    GroupDef {
        id: "tbc",
        name: "台灣寬頻通訊（TBC）",
        note: "AS131596 TBCOM-NET",
        asns: &[131596],
    },
    GroupDef {
        id: "cable",
        name: "其他有線電視與地區寬頻",
        note: "AS24159 東亞、AS131602 新永安、AS131607 大屯、AS131611 三大、AS131625 北視、AS131627 佳聯、AS132738 世新、AS18413 大台北寬頻、AS9922 新高雄寬頻、AS17809 威達、AS18419 DaDa、AS24163–24165 UBB、AS18182 So-net",
        asns: &[24159, 131602, 131607, 131611, 131625, 131627, 132738, 18413, 9922, 17809, 18419, 24163, 24164, 24165, 18182],
    },
    GroupDef {
        id: "tanet",
        name: "TANet／TWAREN 學術網路（學校、中研院）",
        note: "AS1659 TANet、AS17713 與 AS17717 教育部電算中心、AS131150 高雄市教育局、AS18043 新竹市教育處、AS7539 與 AS18414 TWAREN（國網中心）、AS9264／18217／24167 中研院、各大學 AS9916／17711／17712／17716／18047／18177／18420／38844／38847／38848／63899",
        asns: &[1659, 17713, 17717, 131150, 18043, 7539, 18414, 9264, 18217, 24167, 9916, 17711, 17712, 17716, 18047, 18177, 18420, 38844, 38847, 38848, 63899],
    },
    GroupDef {
        id: "gsn",
        name: "政府網路（GSN）",
        note: "AS4782 GSNET（政府骨幹網路，由中華電信數據分公司維運）",
        asns: &[4782],
    },
];

const OTHER_ID: &str = "other";
const OTHER_NAME: &str = "其他台灣網段";
const OTHER_NOTE: &str = "登記在台灣、但不屬於上面任何一組的網段（機房、雲端、企業、小型業者）。全部勾選 = 整個台灣";

/// IPv4、IPv6 的區間清單
type Ranges = (Vec<(u32, u32)>, Vec<(u128, u128)>);

/// RIR 統計檔：cc=TW 的 IPv4 / IPv6 配發
fn parse_delegated(text: &str) -> Ranges {
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('|').collect();
        if f.len() < 7 || f[1] != "TW" || !matches!(f[6], "allocated" | "assigned") {
            continue;
        }
        match f[2] {
            "ipv4" => {
                let (Ok(ip), Ok(n)) = (f[3].parse::<std::net::Ipv4Addr>(), f[4].parse::<u64>()) else {
                    continue;
                };
                let s = u32::from(ip) as u64;
                if n == 0 || s + n - 1 > u32::MAX as u64 {
                    continue;
                }
                v4.push((s as u32, (s + n - 1) as u32));
            }
            "ipv6" => {
                if let Some(Net::V6(a, b)) = kuroshio_jobs::geo::parse_cidr(&format!("{}/{}", f[3], f[4])) {
                    v6.push((a, b));
                }
            }
            _ => {}
        }
    }
    (v4, v6)
}

/// RIPEstat announced-prefixes 的回應 → 網段清單
fn parse_ripestat(body: &[u8]) -> Result<Vec<String>> {
    let v: Value = serde_json::from_slice(body).context("RIPEstat 回應不是 JSON")?;
    if v.get("status").and_then(Value::as_str) != Some("ok") {
        bail!("RIPEstat 狀態不是 ok：{}", v.get("status").unwrap_or(&Value::Null));
    }
    let ps = v
        .pointer("/data/prefixes")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("RIPEstat 回應缺少 data.prefixes"))?;
    Ok(ps
        .iter()
        .filter_map(|p| p.get("prefix").and_then(Value::as_str).map(str::to_string))
        .collect())
}

struct Source {
    cache: Option<PathBuf>,
    offline: bool,
}

impl Source {
    async fn get(&self, name: &str, url: &str, max: u64) -> Result<Vec<u8>> {
        if let Some(dir) = &self.cache {
            if let Ok(b) = std::fs::read(dir.join(name)) {
                return Ok(b);
            }
        }
        if self.offline {
            bail!("離線模式：快取裡沒有 {name}");
        }
        let mut last = None;
        for i in 0..3 {
            if i > 0 {
                tokio::time::sleep(Duration::from_secs(5 * i)).await;
            }
            let req = kuroshio_net::fetch::Request {
                method: "GET",
                ..Default::default()
            };
            match kuroshio_net::fetch::request(url, &req, max, Duration::from_secs(120)).await {
                Ok((200, body)) => {
                    if let Some(dir) = &self.cache {
                        std::fs::create_dir_all(dir)?;
                        std::fs::write(dir.join(name), &body)?;
                    }
                    return Ok(body);
                }
                Ok((code, _)) => last = Some(anyhow::anyhow!("{url}：HTTP {code}")),
                Err(e) => last = Some(e.context(url.to_string())),
            }
        }
        Err(last.unwrap())
    }
}

/// 組出 tw-ip.json 與報表（純函式，方便測試）
fn build(tw: &Dual, announced: &BTreeMap<u32, Vec<String>>, date: &str, sources: Value) -> (Value, String) {
    let mut report = format!("# 台灣 IP 清單（{date}）\n\n");
    let tsize = tw.size_json();
    report += &format!(
        "台灣網段（RIR cc=TW）：IPv4 {} 個位址、IPv6 {} 個 /48\n\n| 群組 | IPv4 位址 | IPv6 /48 | CIDR 數（v4/v6） | 國外宣告被排除（v4 位址） |\n|---|---:|---:|---:|---:|\n",
        tsize["v4"], tsize["v6_48"]
    );
    let mut groups = Vec::new();
    let mut claimed = Dual::default();
    let mut empty_asns = Vec::new();
    for g in GROUPS {
        let mut list = Vec::new();
        for a in g.asns {
            let ps = announced.get(a).cloned().unwrap_or_default();
            if ps.is_empty() {
                empty_asns.push(*a);
            }
            list.extend(ps);
        }
        let (ann, _) = Dual::parse(list.iter().map(String::as_str));
        let nets = ann.intersect(tw);
        let foreign = ann.subtract(tw);
        claimed = claimed.union(&nets);
        let (v4, v6) = (nets.v4_cidrs(), nets.v6_cidrs());
        let size = nets.size_json();
        report += &format!(
            "| {} `{}` | {} | {} | {}/{} | {} |\n",
            g.name,
            g.id,
            size["v4"],
            size["v6_48"],
            v4.len(),
            v6.len(),
            foreign.v4.size()
        );
        groups.push(json!({ "id": g.id, "name": g.name, "note": g.note, "asns": g.asns, "size": size, "v4": v4, "v6": v6 }));
    }
    let other = tw.subtract(&claimed);
    let (v4, v6) = (other.v4_cidrs(), other.v6_cidrs());
    let size = other.size_json();
    report += &format!(
        "| {OTHER_NAME} `{OTHER_ID}` | {} | {} | {}/{} | - |\n",
        size["v4"],
        size["v6_48"],
        v4.len(),
        v6.len()
    );
    groups.push(json!({ "id": OTHER_ID, "name": OTHER_NAME, "note": OTHER_NOTE, "asns": [], "size": size, "v4": v4, "v6": v6 }));
    if !empty_asns.is_empty() {
        report += &format!(
            "\n沒有宣告任何網段的 ASN（可能已停用或併入別的 ASN）：{}\n",
            empty_asns.iter().map(|a| format!("AS{a}")).collect::<Vec<_>>().join("、")
        );
    }
    let out = json!({
        "version": 1,
        "generatedAt": date,
        "sources": sources,
        "total": tsize,
        "groups": groups,
    });
    (out, report)
}

fn today() -> String {
    let days = (kuroshio_net::fetch::now_ms() / 86_400_000) as i64;
    // 公曆換算（Howard Hinnant 的 civil_from_days）
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let (mut cache, mut offline, mut date, mut pos) = (None, false, None, Vec::new());
    while let Some(a) = args.next() {
        match a.as_str() {
            "--cache" => cache = args.next().map(PathBuf::from),
            "--offline" => offline = true,
            "--date" => date = args.next(),
            _ => pos.push(a),
        }
    }
    let out = PathBuf::from(pos.first().map(String::as_str).unwrap_or("data/geo/tw-ip.json"));
    let src = Source { cache, offline };
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    let mut sources = Vec::new();
    for (rir, url) in RIRS {
        let name = format!("delegated-{rir}-extended-latest");
        let body = src.get(&name, url, 128 << 20).await?;
        let (a, b) = parse_delegated(&String::from_utf8_lossy(&body));
        eprintln!("{rir}：TW IPv4 {} 筆、IPv6 {} 筆", a.len(), b.len());
        v4.extend(a);
        v6.extend(b);
        sources.push(json!({ "name": format!("{rir} delegated (cc=TW)"), "url": url }));
    }
    let tw = Dual::from_ranges(v4, v6);
    // 下載壞掉（例如只拿到一半）時不要產生錯的清單：台灣 IPv4 大約 3,500 萬個位址
    if tw.v4.size() < 20_000_000 {
        bail!("台灣 IPv4 總量只有 {}，資料來源可能不完整", tw.v4.size());
    }
    let mut announced = BTreeMap::new();
    for g in GROUPS {
        for &a in g.asns {
            let body = src.get(&format!("ripestat-AS{a}.json"), &ripestat_url(a), 32 << 20).await?;
            let ps = parse_ripestat(&body).with_context(|| format!("AS{a}"))?;
            announced.insert(a, ps);
        }
    }
    sources.push(
        json!({ "name": "RIPEstat announced-prefixes", "url": "https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes" }),
    );
    let date = date.unwrap_or_else(today);
    let (json, report) = build(&tw, &announced, &date, Value::Array(sources));
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&out, compact(&json))?;
    eprintln!("{report}");
    if let Some(r) = pos.get(1) {
        std::fs::write(Path::new(r), report)?;
    }
    Ok(())
}

/// 一個群組一行（方便看 diff），網段清單不換行
fn compact(v: &Value) -> String {
    let mut s = String::from("{\n");
    let obj = v.as_object().unwrap();
    let n = obj.len();
    for (i, (k, val)) in obj.iter().enumerate() {
        let sep = if i + 1 < n { "," } else { "" };
        if k == "groups" {
            s += "  \"groups\": [\n";
            let gs = val.as_array().unwrap();
            for (j, g) in gs.iter().enumerate() {
                s += &format!("    {}{}\n", g, if j + 1 < gs.len() { "," } else { "" });
            }
            s += &format!("  ]{sep}\n");
        } else {
            s += &format!("  {}: {}{sep}\n", Value::String(k.clone()), val);
        }
    }
    s += "}\n";
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuroshio_jobs::geo::TwIp;

    #[test]
    fn delegated_parsing() {
        let t = "2|apnic|20261110|1|19830613|20261110|+1000\napnic|*|ipv4|*|1|summary\n\
                 apnic|TW|ipv4|1.160.0.0|1048576|20090908|allocated|A91A\n\
                 apnic|TW|ipv4|10.0.0.0|768|20090908|assigned|X\n\
                 apnic|JP|ipv4|1.0.16.0|4096|20110412|allocated|Y\n\
                 apnic|TW|ipv4|9.9.9.0|256|20110412|available|\n\
                 apnic|TW|ipv6|2001:b000::|20|20030115|allocated|Z\n\
                 apnic|TW|asn|3462|1|19950101|allocated|Z\n";
        let (v4, v6) = parse_delegated(t);
        let d = Dual::from_ranges(v4, v6);
        assert_eq!(d.v4_cidrs(), vec!["1.160.0.0/12", "10.0.0.0/23", "10.0.2.0/24"]);
        assert_eq!(d.v6_cidrs(), vec!["2001:b000::/20"]);
    }

    #[test]
    fn groups_are_clipped_to_tw_and_other_fills_the_rest() {
        let (tw, _) = Dual::parse(["1.160.0.0/12", "61.216.0.0/14", "2001:b000::/20"]);
        let mut ann = BTreeMap::new();
        // HiNet：台灣網段內的、跨出台灣網段的、完全在國外的
        ann.insert(
            3462,
            vec![
                "1.160.0.0/13".into(),
                "61.216.0.0/13".into(),
                "8.8.8.0/24".into(),
                "2001:b000::/24".into(),
            ],
        );
        ann.insert(38841, vec!["1.168.0.0/16".into()]);
        let (out, report) = build(&tw, &ann, "2026-11-11", json!([]));
        let t = TwIp::parse(compact(&out).as_bytes()).unwrap();
        let cht = t.group("cht").unwrap();
        assert_eq!(cht.nets.v4_cidrs(), vec!["1.160.0.0/13", "61.216.0.0/14"], "只留台灣網段內的部分");
        assert_eq!(t.group("kbro").unwrap().nets.v4_cidrs(), vec!["1.168.0.0/16"]);
        let other = t.group("other").unwrap();
        assert_eq!(other.nets.v4_cidrs(), vec!["1.169.0.0/16", "1.170.0.0/15", "1.172.0.0/14"]);
        assert_eq!(other.nets.v6_cidrs().len(), 4, "/20 − /24 = 4 個 CIDR（/21 /22 /23 /24）");
        assert_eq!(t.all(), tw, "全部勾選 == 整個台灣");
        assert!(!t.all().contains("8.8.8.8".parse().unwrap()));
        assert!(report.contains("AS9674"), "沒資料的 ASN 列在報表");
        assert_eq!(out["groups"].as_array().unwrap().len(), GROUPS.len() + 1);
        // 同樣的輸入 → 同樣的輸出
        assert_eq!(compact(&out), compact(&build(&tw, &ann, "2026-11-11", json!([])).0));
    }

    #[test]
    fn ripestat_shape() {
        let ok = br#"{"status":"ok","data":{"prefixes":[{"prefix":"1.160.0.0/12"},{"prefix":"2001:b000::/20"}]}}"#;
        assert_eq!(parse_ripestat(ok).unwrap(), vec!["1.160.0.0/12", "2001:b000::/20"]);
        assert!(parse_ripestat(br#"{"status":"error"}"#).is_err());
        assert!(parse_ripestat(br#"{"status":"ok","data":{}}"#).is_err());
    }

    #[test]
    fn group_ids_unique_and_asns_not_shared() {
        let mut seen = std::collections::HashSet::new();
        for g in GROUPS {
            assert!(seen.insert(g.id), "{}", g.id);
            for a in g.asns {
                assert!(seen.insert(Box::leak(format!("AS{a}").into_boxed_str())), "AS{a} 出現在兩個群組");
            }
        }
        assert!(!seen.contains(OTHER_ID));
        assert!(today().len() == 10);
    }
}
