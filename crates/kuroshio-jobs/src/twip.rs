//! 台灣 IP 清單 `tw-ip.json` 的產生（規格 08）：指令列 `tw-ip` 與排程工作 `tw-ip` 共用
//!
//! 資料來源（全部是公開資料，不用金鑰，也不經過本專案的任何伺服器）：
//! - 五個 RIR 的 `delegated-*-extended-latest`：國別 TW 的 IPv4 / IPv6 配發（主要是 APNIC / TWNIC）。
//!   注意這是「登記國別」，不是地理位置。
//! - RIPEstat `announced-prefixes`：每個 ASN 目前在 BGP 宣告的網段。
//!
//! 做法：
//! 1. 台灣網段 = 所有 RIR 裡 cc=TW 的配發（合併）
//! 2. 每個 ISP 群組 = 它的 ASN 宣告的網段 ∩ 台灣網段（ISP 在國外宣告的網段不收）
//! 3. 「其他台灣網段」= 台灣網段 − 所有 ISP 群組 → 全部勾選 == 整個台灣
//! 4. 輸出排序、合併成最少的 CIDR；同樣的輸入一定得到同樣的輸出
//!
//! 記憶體：RIR 檔一個好幾 MB，一律邊下載邊一行一行解析（`DelegatedParser`），只留 cc=TW 的紀錄；
//! RIPEstat 的回應也邊收邊掃（`PrefixScanner`），只留網段。整份檔案不會放進記憶體。
//!
//! 排程工作（`TwIpJob`）慢慢跑、有禮貌：一次抓一個檔、每個 ASN 之間隨機停 5–30 秒、照 429 的 Retry-After 等；
//! 進度放記憶體（不寫 Flash），資源不夠就暫停稍後續跑，超過期限或一直失敗就放棄、繼續用目前的清單。

use crate::geo::{parse_cidr, Dual, Net, TwIp};
use crate::scheduler::{BoxFuture, Job, JobCtx};
use anyhow::{anyhow, bail, Context, Result};
use kuroshio_config::get;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// 五個 RIR 的配發統計
pub const RIRS: [(&str, &str); 5] = [
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

/// RIPEstat Data API
pub const RIPESTAT: &str = "https://stat.ripe.net";
/// RIPEstat 要求 API 使用者帶上的 `sourceapp`
pub const SOURCEAPP: &str = "kuroshio-dns";
/// RIR 檔的大小上限（目前最大的 ripencc 約 18 MB；只是防呆，不會整份放記憶體）
pub const RIR_MAX: u64 = 256 << 20;
/// RIPEstat 回應的大小上限（HiNet 約 40 KB）
pub const ASN_MAX: u64 = 32 << 20;

/// 資料來源網址（測試換成本機的假伺服器）
#[derive(Debug, Clone)]
pub struct Sources {
    /// (RIR 名稱, 網址)
    pub rirs: Vec<(String, String)>,
    /// RIPEstat 的網址開頭（`https://stat.ripe.net`）
    pub ripestat: String,
}

impl Default for Sources {
    fn default() -> Self {
        Sources {
            rirs: RIRS.iter().map(|(n, u)| (n.to_string(), u.to_string())).collect(),
            ripestat: RIPESTAT.to_string(),
        }
    }
}

impl Sources {
    /// 全部指到同一個網址開頭：`{base}/delegated-{rir}-extended-latest`、`{base}/data/announced-prefixes/...`（測試用）
    pub fn with_base(base: &str) -> Sources {
        let base = base.trim_end_matches('/');
        Sources {
            rirs: RIRS
                .iter()
                .map(|(n, _)| (n.to_string(), format!("{base}/delegated-{n}-extended-latest")))
                .collect(),
            ripestat: base.to_string(),
        }
    }

    pub fn ripestat_url(&self, asn: u32) -> String {
        format!(
            "{}/data/announced-prefixes/data.json?resource=AS{asn}&min_peers_seeing=3&sourceapp={SOURCEAPP}",
            self.ripestat.trim_end_matches('/')
        )
    }

    /// 輸出檔的 `sources` 欄位
    pub fn json(&self) -> Value {
        let mut v: Vec<Value> = self
            .rirs
            .iter()
            .map(|(n, u)| json!({ "name": format!("{n} delegated (cc=TW)"), "url": u }))
            .collect();
        v.push(
            json!({ "name": "RIPEstat announced-prefixes", "url": "https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes" }),
        );
        Value::Array(v)
    }
}

/// ISP 群組。ASN 與持有者名稱對照 RIPE NCC 的 ASN 名稱表（ftp.ripe.net/ripe/asnames/asn.txt，來自各 RIR 的 whois）
/// 與 RIPEstat whois；只放「一般用戶上網」的 ASN，機房、CDN、國際轉接的 ASN 留在「其他台灣網段」。
pub struct GroupDef {
    pub id: &'static str,
    pub name: &'static str,
    pub note: &'static str,
    pub asns: &'static [u32],
}

pub const GROUPS: &[GroupDef] = &[
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

pub const OTHER_ID: &str = "other";
pub const OTHER_NAME: &str = "其他台灣網段";
pub const OTHER_NOTE: &str = "登記在台灣、但不屬於上面任何一組的網段（機房、雲端、企業、小型業者）。全部勾選 = 整個台灣";

/// 全部 ASN（依群組順序）
pub fn all_asns() -> Vec<u32> {
    GROUPS.iter().flat_map(|g| g.asns.iter().copied()).collect()
}

// ---------------- RIR 統計檔：邊收邊解析 ----------------

/// 一行最長多少位元組（正常的紀錄不到 100；更長的是壞資料，整行丟掉）
const MAX_LINE: usize = 512;

/// RIR `delegated-*-extended` 檔的串流解析：資料一段一段餵進來（段落邊界可以在一行的中間），
/// 只留 cc=TW 的 IPv4 / IPv6 配發。最後用標頭的筆數確認檔案完整（下載到一半斷掉不會被當成完整的）
#[derive(Debug, Default)]
pub struct DelegatedParser {
    line: Vec<u8>,
    /// 目前這行太長，丟到換行為止
    skipping: bool,
    seen_header: bool,
    header_records: Option<u64>,
    records: u64,
    bad_lines: u64,
    pub v4: Vec<(u32, u32)>,
    pub v6: Vec<(u128, u128)>,
}

impl DelegatedParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// 餵一段資料
    pub fn feed(&mut self, mut chunk: &[u8]) {
        while !chunk.is_empty() {
            match chunk.iter().position(|b| *b == b'\n') {
                Some(i) => {
                    if !self.skipping {
                        if self.line.len() + i <= MAX_LINE {
                            self.line.extend_from_slice(&chunk[..i]);
                            let line = std::mem::take(&mut self.line);
                            self.process(&line);
                            self.line = line;
                        } else {
                            self.bad_lines += 1;
                        }
                    }
                    self.line.clear();
                    self.skipping = false;
                    chunk = &chunk[i + 1..];
                }
                None => {
                    if !self.skipping {
                        if self.line.len() + chunk.len() > MAX_LINE {
                            self.skipping = true;
                            self.bad_lines += 1;
                            self.line.clear();
                        } else {
                            self.line.extend_from_slice(chunk);
                        }
                    }
                    break;
                }
            }
        }
    }

    fn process(&mut self, raw: &[u8]) {
        let Ok(l) = std::str::from_utf8(raw) else {
            self.bad_lines += 1;
            return;
        };
        let l = l.trim_end_matches('\r');
        if l.is_empty() || l.starts_with('#') {
            return;
        }
        let f: Vec<&str> = l.split('|').collect();
        if !self.seen_header {
            // 第一行：版本|登記機構|序號|紀錄筆數|起日|迄日|時區
            self.seen_header = true;
            if f.len() >= 4 && f[0].parse::<f32>().is_ok() {
                self.header_records = f[3].trim().parse().ok();
                return;
            }
        }
        if f.len() >= 6 && f[1] == "*" && f[5] == "summary" {
            return;
        }
        self.records += 1;
        if f.len() < 7 || f[1] != "TW" || !matches!(f[6], "allocated" | "assigned") {
            return;
        }
        match f[2] {
            "ipv4" => {
                let (Ok(ip), Ok(n)) = (f[3].parse::<std::net::Ipv4Addr>(), f[4].parse::<u64>()) else {
                    return;
                };
                let s = u32::from(ip) as u64;
                if n == 0 || s + n - 1 > u32::MAX as u64 {
                    return;
                }
                self.v4.push((s as u32, (s + n - 1) as u32));
            }
            "ipv6" => {
                if let Some(Net::V6(a, b)) = parse_cidr(&format!("{}/{}", f[3], f[4])) {
                    self.v6.push((a, b));
                }
            }
            _ => {}
        }
    }

    /// 資料結束：最後一行沒有換行也算；標頭的筆數要跟實際的一樣
    pub fn finish(mut self) -> Result<Dual> {
        if !self.skipping && !self.line.is_empty() {
            let line = std::mem::take(&mut self.line);
            self.process(&line);
        }
        let Some(n) = self.header_records else {
            bail!("不是 RIR 統計檔（缺少標頭）");
        };
        if n != self.records {
            bail!(
                "檔案不完整：標頭寫 {n} 筆，實際讀到 {} 筆（另有 {} 行格式錯誤）",
                self.records,
                self.bad_lines
            );
        }
        Ok(Dual::from_ranges(self.v4, self.v6))
    }
}

// ---------------- RIPEstat：邊收邊掃 ----------------

/// 字串最長留多少（網段字串不到 50 個字元）
const MAX_STR: usize = 128;

/// RIPEstat `announced-prefixes` 回應的串流掃描：只認 `data.prefixes[].prefix` 與最外層的 `status`，
/// 不建整份 JSON。最後檢查括號有對上（沒被截斷）、`status` 是 `ok`
#[derive(Debug, Default)]
pub struct PrefixScanner {
    depth: u32,
    started: bool,
    broken: bool,
    in_str: bool,
    esc: bool,
    s: Vec<u8>,
    s_over: bool,
    /// 上一個字串（可能是鍵）、目前的鍵
    pending: Vec<u8>,
    key: Vec<u8>,
    expect_value: bool,
    status: Option<String>,
    bad: Vec<String>,
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
    pub prefixes: usize,
}

impl PrefixScanner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, chunk: &[u8]) {
        for &b in chunk {
            if self.in_str {
                if self.esc {
                    self.esc = false;
                    self.push(b);
                } else if b == b'\\' {
                    self.esc = true;
                    self.push(b);
                } else if b == b'"' {
                    self.in_str = false;
                    self.string_done();
                } else {
                    self.push(b);
                }
                continue;
            }
            match b {
                b'"' => {
                    self.in_str = true;
                    self.s.clear();
                    self.s_over = false;
                }
                b'{' | b'[' => {
                    self.depth += 1;
                    self.started = true;
                    self.expect_value = false;
                }
                b'}' | b']' => {
                    if self.depth == 0 {
                        self.broken = true;
                    } else {
                        self.depth -= 1;
                    }
                    self.expect_value = false;
                }
                b':' => {
                    std::mem::swap(&mut self.key, &mut self.pending);
                    self.pending.clear();
                    self.expect_value = true;
                }
                b',' => self.expect_value = false,
                _ => {}
            }
        }
    }

    fn push(&mut self, b: u8) {
        if self.s.len() < MAX_STR {
            self.s.push(b);
        } else {
            self.s_over = true;
        }
    }

    fn string_done(&mut self) {
        if !self.expect_value {
            self.pending.clear();
            if !self.s_over {
                self.pending.extend_from_slice(&self.s);
            }
            return;
        }
        self.expect_value = false;
        match (self.key.as_slice(), self.depth) {
            (b"prefix", 4) => {
                let txt = String::from_utf8_lossy(&self.s);
                match (self.s_over, parse_cidr(&txt)) {
                    (false, Some(Net::V4(a, b))) => self.v4.push((a, b)),
                    (false, Some(Net::V6(a, b))) => self.v6.push((a, b)),
                    _ => {
                        if self.bad.len() < 5 {
                            self.bad.push(txt.into_owned());
                        }
                        return;
                    }
                }
                self.prefixes += 1;
            }
            (b"status", 1) => self.status = Some(String::from_utf8_lossy(&self.s).into_owned()),
            _ => {}
        }
    }

    /// 回應結束：完整、狀態 ok → 宣告的網段
    pub fn finish(self) -> Result<Dual> {
        if !self.started || self.depth != 0 || self.in_str || self.broken {
            bail!("RIPEstat 回應不完整或不是 JSON");
        }
        if self.status.as_deref() != Some("ok") {
            bail!("RIPEstat 狀態不是 ok：{}", self.status.as_deref().unwrap_or("（沒有）"));
        }
        if !self.bad.is_empty() {
            bail!("RIPEstat 回應有格式錯誤的網段：{}", self.bad.join(", "));
        }
        Ok(Dual::from_ranges(self.v4, self.v6))
    }
}

// ---------------- 下載 ----------------

/// 下載結果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Got {
    Ok,
    /// 429 / 503：對方要求等一下（Retry-After，沒寫就 60 秒）
    RateLimited(Duration),
}

/// `Retry-After`：秒數；HTTP 日期或沒寫 → 60 秒。限制在 1 秒到 6 小時
pub fn retry_after(v: Option<&str>) -> Duration {
    let s = v.and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(60);
    Duration::from_secs(s.clamp(1, 6 * 3600))
}

/// 下載，每收到一段就交給 `on_chunk`（不是 200 的內容不會交出去）
pub async fn fetch_into(url: &str, max: u64, timeout: Duration, on_chunk: impl FnMut(&[u8]) -> Result<()>) -> Result<Got> {
    let st = kuroshio_net::fetch::get_status(url, &[], max, timeout, on_chunk).await?;
    match st.code {
        200 => Ok(Got::Ok),
        429 | 503 => Ok(Got::RateLimited(retry_after(st.retry_after.as_deref()))),
        c => bail!("HTTP {c}"),
    }
}

// ---------------- 組出 tw-ip.json ----------------

/// 組出 tw-ip.json 與報表（純函式）。`announced`：每個 ASN 宣告的網段（查過但沒有宣告的是空的）
pub fn build(tw: &Dual, announced: &BTreeMap<u32, Dual>, date: &str, sources: Value) -> (Value, String) {
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
        let mut ann = Dual::default();
        for a in g.asns {
            match announced.get(a) {
                Some(d) if !d.is_empty() => ann = ann.union(d),
                _ => empty_asns.push(*a),
            }
        }
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

/// 一個群組一行（方便看 diff），網段清單不換行
pub fn compact(v: &Value) -> String {
    let mut s = String::from("{\n");
    let Some(obj) = v.as_object() else {
        return v.to_string();
    };
    let n = obj.len();
    for (i, (k, val)) in obj.iter().enumerate() {
        let sep = if i + 1 < n { "," } else { "" };
        match (k.as_str(), val.as_array()) {
            ("groups", Some(gs)) => {
                s += "  \"groups\": [\n";
                for (j, g) in gs.iter().enumerate() {
                    s += &format!("    {}{}\n", g, if j + 1 < gs.len() { "," } else { "" });
                }
                s += &format!("  ]{sep}\n");
            }
            _ => s += &format!("  {}: {}{sep}\n", Value::String(k.clone()), val),
        }
    }
    s += "}\n";
    s
}

/// 今天（UTC）`YYYY-MM-DD`
pub fn today() -> String {
    date_of(kuroshio_net::fetch::now_ms())
}

/// Unix 毫秒 → `YYYY-MM-DD`（UTC）
pub fn date_of(ms: u64) -> String {
    let (y, m, d) = crate::time::civil_from_days((ms / 86_400_000) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DD` 到 `now_ms` 過了幾天（格式錯誤 → None）
pub fn age_days(date: &str, now_ms: u64) -> Option<i64> {
    let t = crate::time::parse_date_utc(date)?;
    Some((now_ms as i64 - t as i64).div_euclid(86_400_000))
}

// ---------------- 指令列：一次跑完 ----------------

/// 指令列（GitHub Actions 每月）用：照順序一次跑完，不暫停
pub struct Simple {
    pub sources: Sources,
    /// 下載的原始資料存到這裡；已經有的檔案直接用
    pub cache: Option<PathBuf>,
    /// 只用快取，缺檔就失敗
    pub offline: bool,
    /// 每個 RIPEstat 請求之間停多久
    pub pause: Duration,
    /// 台灣 IPv4 總量下限（資料來源壞掉時不要產生錯的清單）
    pub min_v4: u128,
}

/// 邊收邊處理的解析器（每次重試都重新建一個）
pub trait Feed: Default {
    fn feed(&mut self, chunk: &[u8]);
}

impl Feed for DelegatedParser {
    fn feed(&mut self, chunk: &[u8]) {
        DelegatedParser::feed(self, chunk)
    }
}

impl Feed for PrefixScanner {
    fn feed(&mut self, chunk: &[u8]) {
        PrefixScanner::feed(self, chunk)
    }
}

impl Simple {
    /// 先看快取，沒有再下載（同時寫進快取的暫存檔，成功才改名）；失敗重試 3 次，429 照 Retry-After 等
    async fn get<P: Feed>(&self, name: &str, url: &str, max: u64) -> Result<P> {
        if let Some(dir) = &self.cache {
            if let Ok(f) = std::fs::File::open(dir.join(name)) {
                let mut p = P::default();
                let mut r = std::io::BufReader::with_capacity(64 << 10, f);
                let mut buf = vec![0u8; 64 << 10];
                loop {
                    let n = std::io::Read::read(&mut r, &mut buf)?;
                    if n == 0 {
                        return Ok(p);
                    }
                    p.feed(&buf[..n]);
                }
            }
        }
        if self.offline {
            bail!("離線模式：快取裡沒有 {name}");
        }
        let mut last = None;
        for i in 0..4u64 {
            if i > 0 {
                tokio::time::sleep(Duration::from_secs(5 * i)).await;
            }
            let mut tee = match &self.cache {
                Some(dir) => {
                    std::fs::create_dir_all(dir)?;
                    let part = dir.join(format!("{name}.part"));
                    Some((std::io::BufWriter::new(std::fs::File::create(&part)?), part, dir.join(name)))
                }
                None => None,
            };
            let mut p = P::default();
            let res = fetch_into(url, max, Duration::from_secs(120), |c| {
                if let Some((w, ..)) = tee.as_mut() {
                    w.write_all(c)?;
                }
                p.feed(c);
                Ok(())
            })
            .await;
            match res {
                Ok(Got::Ok) => {
                    if let Some((mut w, part, path)) = tee {
                        w.flush()?;
                        drop(w);
                        std::fs::rename(part, path)?;
                    }
                    return Ok(p);
                }
                Ok(Got::RateLimited(d)) => {
                    eprintln!("{url}：對方要求等 {} 秒", d.as_secs());
                    tokio::time::sleep(d).await;
                    last = Some(anyhow!("{url}：HTTP 429"));
                }
                Err(e) => last = Some(e.context(url.to_string())),
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("{url}：下載失敗")))
    }

    /// 跑完全部來源 → (tw-ip.json 內容, 報表)
    pub async fn run(&self, date: &str) -> Result<(Value, String)> {
        let mut tw = Dual::default();
        for (rir, url) in &self.sources.rirs {
            let name = format!("delegated-{rir}-extended-latest");
            let p: DelegatedParser = self.get(&name, url, RIR_MAX).await?;
            let d = p.finish().with_context(|| name.clone())?;
            eprintln!("{rir}：TW IPv4 {} 個區間、IPv6 {} 個區間", d.v4.len(), d.v6.len());
            tw = tw.union(&d);
        }
        // 下載壞掉（例如只拿到一半）時不要產生錯的清單：台灣 IPv4 大約 3,500 萬個位址
        if tw.v4.size() < self.min_v4 {
            bail!("台灣 IPv4 總量只有 {}，資料來源可能不完整", tw.v4.size());
        }
        let mut announced = BTreeMap::new();
        for (i, a) in all_asns().into_iter().enumerate() {
            if i > 0 && !self.pause.is_zero() {
                tokio::time::sleep(self.pause).await;
            }
            let s: PrefixScanner = self
                .get(&format!("ripestat-AS{a}.json"), &self.sources.ripestat_url(a), ASN_MAX)
                .await?;
            announced.insert(a, s.finish().with_context(|| format!("AS{a}"))?);
        }
        Ok(build(&tw, &announced, date, self.sources.json()))
    }
}

// ---------------- 驗證 ----------------

/// 換上新清單之前的檢查：格式正確、台灣 IPv4 總量跟目前的差在 ±20% 以內、每個 ISP 群組都有網段
/// （目前就是空的群組除外，例如已併入別家的台灣之星）、日期比目前的新。不通過回傳原因
pub fn validate(cur: Option<&TwIp>, new: &TwIp) -> std::result::Result<(), String> {
    for g in GROUPS.iter().map(|g| g.id).chain([OTHER_ID]) {
        if new.group(g).is_none() {
            return Err(format!("缺少群組 {g}"));
        }
    }
    let Some(cur) = cur else { return Ok(()) };
    if new.generated_at <= cur.generated_at {
        return Err(format!(
            "新清單的日期（{}）沒有比目前的（{}）新",
            new.generated_at, cur.generated_at
        ));
    }
    let (a, b) = (cur.all().v4.size() as f64, new.all().v4.size() as f64);
    if a > 0.0 && (b - a).abs() > a * 0.2 {
        return Err(format!("台灣 IPv4 總量跟目前的差超過 20%（{} → {}）", a as u128, b as u128));
    }
    for g in GROUPS {
        let n = new.group(g.id).map(|x| x.nets.is_empty()).unwrap_or(true);
        let was_empty = cur.group(g.id).map(|x| x.nets.is_empty()).unwrap_or(true);
        if n && !was_empty {
            return Err(format!("群組 {}（{}）變成空的", g.id, g.name));
        }
    }
    Ok(())
}

/// 兩份清單的網段完全一樣（只差日期）：不必寫 Flash
pub fn same_nets(a: &TwIp, b: &TwIp) -> bool {
    a.groups.len() == b.groups.len() && a.groups.iter().zip(&b.groups).all(|(x, y)| x.id == y.id && x.nets == y.nets)
}

// ---------------- 排程工作 ----------------

/// 續跑時排程器用的原因（沒有進行中的進度時，這個原因的執行什麼都不做）
pub const RESUME_REASON: &str = "續跑（台灣 IP 清單）";

/// 跟主程式的接點
#[derive(Clone)]
pub struct Hooks {
    /// 目前使用中的清單，以及是不是本機產生的（false = 公版，隨程式附帶）
    pub current: Arc<dyn Fn() -> (Option<Arc<TwIp>>, bool) + Send + Sync>,
    /// 記憶體不夠時回傳原因（主程式的記憶體壓力）
    pub memory_short: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    /// 目前的 1 分鐘平均負載與核心數；讀不到回 None（不檢查）
    pub load: Arc<dyn Fn() -> Option<(f64, usize)> + Send + Sync>,
    /// 換上新清單（套用規則、經快照寫入器存檔、通知防火牆）
    pub install: Arc<dyn Fn(TwIp, Vec<u8>) -> Result<()> + Send + Sync>,
}

/// `/proc/loadavg` 的 1 分鐘平均負載與 CPU 核心數（Windows 沒有 → None）
pub fn system_load() -> Option<(f64, usize)> {
    let s = std::fs::read_to_string("/proc/loadavg").ok()?;
    let l: f64 = s.split_whitespace().next()?.parse().ok()?;
    Some((l, std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)))
}

/// `jobs.tw-ip.*` 的設定
#[derive(Debug, Clone)]
pub struct Conf {
    /// 每個 RIPEstat 請求之間隨機停的秒數（下限、上限）
    pub pause: (f64, f64),
    /// 第一次失敗或資源不夠後多久再試（秒），之後每次加倍
    pub retry: f64,
    /// 從開始算多久還沒完成就放棄（小時）
    pub deadline_h: f64,
    /// 連續失敗幾次就放棄
    pub max_failures: u32,
    /// 進度資料最多用多少記憶體（KB），超過就放棄
    pub max_mem_kb: u64,
    /// 每個核心的平均負載超過這個就暫停
    pub max_load_per_core: f64,
    /// 排程（不是手動）時：目前的清單不到這麼多天就不更新
    pub min_age_days: i64,
    /// 下載一個 RIR 檔最多多久（秒）
    pub rir_timeout: f64,
    /// 一個 RIPEstat 請求最多多久（秒）
    pub asn_timeout: f64,
}

impl Conf {
    pub fn from_cfg(cfg: &Value) -> Conf {
        let n = |k: &str, d: f64| {
            get(cfg, &format!("jobs.tw-ip.{k}"))
                .and_then(Value::as_f64)
                .filter(|v| *v >= 0.0)
                .unwrap_or(d)
        };
        let pause = get(cfg, "jobs.tw-ip.pauseSec")
            .and_then(Value::as_array)
            .and_then(|a| Some((a.first()?.as_f64()?, a.get(1)?.as_f64()?)))
            .filter(|(a, b)| *a >= 0.0 && b >= a)
            .unwrap_or((5.0, 30.0));
        Conf {
            pause,
            retry: n("retrySec", 300.0),
            deadline_h: n("deadlineHours", 72.0),
            max_failures: n("maxFailures", 6.0).max(1.0) as u32,
            max_mem_kb: n("maxMemKB", 2048.0) as u64,
            max_load_per_core: n("maxLoadPerCore", 2.0),
            min_age_days: n("minAgeDays", 20.0) as i64,
            rir_timeout: n("rirTimeoutSec", 120.0).max(1.0),
            asn_timeout: n("asnTimeoutSec", 60.0).max(1.0),
        }
    }
}

/// 進度（記憶體裡，不寫 Flash）：暫停後在同一次開機內接著做，重開機就等下次排程從頭來
#[derive(Debug, Default)]
struct Progress {
    cycle_start: u64,
    rir_done: usize,
    tw: Dual,
    asn_done: usize,
    announced: BTreeMap<u32, Dual>,
    /// 連續失敗次數、連續因資源不夠暫停的次數
    failures: u32,
    res_pauses: u32,
    /// 實際花在 RIR、ASN 的時間（毫秒，估計剩餘時間用）
    rir_ms: u64,
    asn_ms: u64,
}

impl Progress {
    /// 進度資料大約占用多少記憶體（位元組）
    fn heap_bytes(&self) -> usize {
        self.tw.heap_bytes() + self.announced.values().map(|d| d.heap_bytes() + 64).sum::<usize>()
    }
}

/// 對外顯示的狀態
#[derive(Debug, Clone, Default)]
struct Status {
    /// idle / running / paused / aborted / done / skipped
    state: &'static str,
    reason: String,
    phase: &'static str,
    done: usize,
    total: usize,
    started_at: Option<u64>,
    resume_at: Option<u64>,
    eta: Option<u64>,
    last_end: Option<u64>,
    last_success: Option<u64>,
    last_result: String,
    peak_mem: usize,
    /// 這一輪的進度資料最多用了多少
    cycle_peak: usize,
}

struct Inner {
    sources: Sources,
    hooks: Hooks,
    st: Mutex<(Status, Option<Progress>)>,
}

/// 排程工作 `tw-ip`
#[derive(Clone)]
pub struct TwIpJob {
    inner: Arc<Inner>,
}

/// 這一次執行結束的方式
enum Exit {
    /// 暫停（原因、多久後續跑）
    Pause(String, Duration),
    /// 放棄這一輪（原因）
    Abort(String),
}

/// 執行中途被丟掉（例如排程器逾時）時把進度放回去、稍後續跑
struct Guard {
    inner: Arc<Inner>,
    ctx: JobCtx,
    prog: Option<Progress>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(p) = self.prog.take() {
            let mut st = self.inner.st.lock().unwrap();
            st.0.state = "paused";
            st.0.reason = "執行被中斷（逾時或關機），稍後續跑".into();
            let delay = Duration::from_secs(600);
            st.0.resume_at = Some(self.ctx.now_ms() + delay.as_millis() as u64);
            st.1 = Some(p);
            drop(st);
            if tokio::runtime::Handle::try_current().is_ok() {
                self.ctx.request_later(delay, RESUME_REASON);
            }
        }
    }
}

fn rand_unit() -> f64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(kuroshio_net::fetch::now_ms());
    (h.finish() >> 11) as f64 / (1u64 << 53) as f64
}

fn secs(s: f64) -> Duration {
    Duration::from_secs_f64(s.clamp(0.0, 7.0 * 86400.0))
}

impl TwIpJob {
    pub fn new(sources: Sources, hooks: Hooks) -> TwIpJob {
        TwIpJob {
            inner: Arc::new(Inner {
                sources,
                hooks,
                st: Mutex::new((
                    Status {
                        state: "idle",
                        ..Default::default()
                    },
                    None,
                )),
            }),
        }
    }

    /// 有沒有進行中的進度（暫停中等著續跑）
    pub fn has_progress(&self) -> bool {
        self.inner.st.lock().unwrap().1.is_some()
    }

    /// 放棄進行中的進度（測試、設定關掉工作時）
    pub fn reset(&self) {
        self.inner.st.lock().unwrap().1 = None;
    }

    /// `/api/jobs` 的 `detail.tw-ip`、`/api/access` 的 `update`
    pub fn status_json(&self) -> Value {
        let (cur, local) = (self.inner.hooks.current)();
        let st = self.inner.st.lock().unwrap().0.clone();
        let progress = match st.phase {
            "rir" => format!("RIR {}/{}", st.done, st.total),
            "asn" => format!("ASN {}/{}", st.done, st.total),
            "build" => "整理、驗證".to_string(),
            _ => String::new(),
        };
        let fmt = |t: Option<u64>| t.map(crate::time::fmt_date_time).unwrap_or_default();
        let text = match st.state {
            "running" => {
                let eta = st.eta.map(|t| format!("，預計 {} 完成", fmt(Some(t)))).unwrap_or_default();
                format!("執行中：{progress}{eta}")
            }
            "paused" => format!(
                "暫停：{}{}{}",
                st.reason,
                if progress.is_empty() {
                    String::new()
                } else {
                    format!("（已完成 {progress}）")
                },
                st.resume_at.map(|t| format!("，{} 再試", fmt(Some(t)))).unwrap_or_default()
            ),
            "aborted" => format!("已放棄：{}（繼續用目前的清單）", st.reason),
            "done" | "skipped" => st.last_result.clone(),
            _ => String::new(),
        };
        let list_date = cur.as_ref().map(|t| t.generated_at.clone());
        json!({
            "state": st.state,
            "reason": st.reason,
            "progress": progress,
            "step": { "phase": st.phase, "done": st.done, "total": st.total },
            "startedAt": st.started_at,
            "eta": st.eta,
            "resumeAt": st.resume_at,
            "lastEnd": st.last_end,
            "lastSuccess": st.last_success,
            "lastResult": st.last_result,
            "listDate": list_date,
            "source": if local { "本機產生" } else { "公版" },
            "peakMemKB": st.peak_mem.div_ceil(1024),
            "text": text,
        })
    }

    fn set<F: FnOnce(&mut Status)>(&self, f: F) {
        f(&mut self.inner.st.lock().unwrap().0);
    }

    /// 執行一次（可能是新的一輪，也可能是續跑）。暫停時回傳多久後續跑
    async fn run_once(&self, ctx: &JobCtx) -> Result<Option<Duration>> {
        let c = Conf::from_cfg(&ctx.cfg);
        let manual = ctx.reason.starts_with("手動");
        let resume = ctx.reason == RESUME_REASON;
        let now = ctx.now_ms();
        let taken = self.inner.st.lock().unwrap().1.take();
        let prog = match taken {
            Some(p) => p,
            None if resume => return Ok(None), // 已經完成或放棄了：沒有要續跑的
            None => {
                let (cur, _) = (self.inner.hooks.current)();
                if !manual {
                    if let Some((date, age)) = cur
                        .as_ref()
                        .and_then(|t| age_days(&t.generated_at, now).map(|a| (t.generated_at.clone(), a)))
                    {
                        if age < c.min_age_days {
                            let msg = format!("目前的清單（{date}）才 {age} 天，這次不必更新");
                            info!("台灣 IP 清單：{msg}");
                            self.set(|s| {
                                s.state = "skipped";
                                s.last_result = msg;
                                s.last_end = Some(now);
                            });
                            return Ok(None);
                        }
                    }
                }
                info!("台灣 IP 清單：開始在本機重新產生（{}）", ctx.reason);
                self.set(|s| {
                    s.started_at = Some(now);
                    s.cycle_peak = 0;
                    s.phase = "";
                });
                Progress {
                    cycle_start: now,
                    ..Default::default()
                }
            }
        };
        self.set(|s| {
            s.state = "running";
            s.reason.clear();
            s.resume_at = None;
        });
        let mut g = Guard {
            inner: self.inner.clone(),
            ctx: ctx.clone(),
            prog: Some(prog),
        };
        let exit = match self.steps(ctx, &c, &mut g).await {
            Ok(e) => e,
            Err(e) => Some(Exit::Abort(format!("{e:#}"))),
        };
        let now = ctx.now_ms();
        match exit {
            None => Ok(None),
            Some(Exit::Pause(why, delay)) => {
                let p = g.prog.take();
                info!("台灣 IP 清單：暫停（{why}），{} 秒後再試", delay.as_secs());
                let mut st = self.inner.st.lock().unwrap();
                st.0.state = "paused";
                st.0.reason = why;
                st.0.resume_at = Some(now + delay.as_millis() as u64);
                st.1 = p;
                Ok(Some(delay))
            }
            Some(Exit::Abort(why)) => {
                g.prog = None;
                warn!("台灣 IP 清單：放棄這一輪（{why}），繼續用目前的清單");
                self.set(|s| {
                    s.state = "aborted";
                    s.reason = why.clone();
                    s.resume_at = None;
                    s.eta = None;
                    s.last_end = Some(now);
                    s.last_result = format!("放棄：{why}");
                });
                Err(anyhow!("{why}"))
            }
        }
    }

    /// 依序做每一步；每一步之前檢查期限、記憶體、CPU、有沒有別的工作在等
    async fn steps(&self, ctx: &JobCtx, c: &Conf, g: &mut Guard) -> Result<Option<Exit>> {
        let hooks = self.inner.hooks.clone();
        let rirs = self.inner.sources.rirs.clone();
        let asns = all_asns();
        let mut first_asn = true;
        let avg_pause = (c.pause.0 + c.pause.1) / 2.0;
        loop {
            let now = ctx.now_ms();
            let Some(p) = g.prog.as_mut() else { bail!("進度遺失") };
            if now.saturating_sub(p.cycle_start) as f64 > c.deadline_h * 3_600_000.0 {
                return Ok(Some(Exit::Abort(format!("超過 {} 小時還沒完成", c.deadline_h))));
            }
            // 目前做到哪、估計剩餘時間
            let rir_left = rirs.len().saturating_sub(p.rir_done) as f64;
            let asn_left = asns.len().saturating_sub(p.asn_done) as f64;
            let per_rir = if p.rir_done > 0 {
                p.rir_ms as f64 / p.rir_done as f64
            } else {
                30_000.0
            };
            let per_asn = if p.asn_done > 0 {
                p.asn_ms as f64 / p.asn_done as f64
            } else {
                avg_pause * 1000.0 + 2000.0
            };
            let eta = now + (rir_left * per_rir + asn_left * per_asn) as u64;
            let (phase, done, total) = if p.rir_done < rirs.len() {
                ("rir", p.rir_done, rirs.len())
            } else if p.asn_done < asns.len() {
                ("asn", p.asn_done, asns.len())
            } else {
                ("build", 0, 0)
            };
            self.set(|s| {
                s.phase = phase;
                s.done = done;
                s.total = total;
                s.eta = Some(eta);
            });
            let used = p.heap_bytes();
            self.set(|s| {
                s.cycle_peak = s.cycle_peak.max(used);
                s.peak_mem = s.peak_mem.max(used);
            });
            if used as u64 > c.max_mem_kb * 1024 {
                return Ok(Some(Exit::Abort(format!(
                    "進度資料用了 {} KB，超過上限 {} KB",
                    used / 1024,
                    c.max_mem_kb
                ))));
            }
            let short = (hooks.memory_short)().or_else(|| {
                (hooks.load)().and_then(|(l, n)| (l > c.max_load_per_core * n as f64).then(|| format!("CPU 負載太高（{l:.1}，{n} 核心）")))
            });
            if let Some(why) = short {
                p.res_pauses += 1;
                let d = c.retry * 2f64.powi(p.res_pauses.min(10) as i32 - 1);
                return Ok(Some(Exit::Pause(why, secs(d.min(7200.0)))));
            }
            p.res_pauses = 0;
            if ctx.others_waiting() {
                return Ok(Some(Exit::Pause("讓其他排程工作先執行".into(), secs(c.retry.min(60.0)))));
            }
            let t0 = Instant::now();
            let res: std::result::Result<(), Option<Duration>> = match phase {
                "rir" => {
                    let (name, url) = &rirs[p.rir_done];
                    let mut parser = DelegatedParser::new();
                    let r = fetch_into(url, RIR_MAX, secs(c.rir_timeout), |ch| {
                        parser.feed(ch);
                        Ok(())
                    })
                    .await;
                    let p = g.prog.as_mut().unwrap();
                    p.rir_ms += t0.elapsed().as_millis() as u64;
                    let r = match r {
                        Ok(Got::Ok) => parser.finish().map(Ok),
                        Ok(Got::RateLimited(d)) => Ok(Err(d)),
                        Err(e) => Err(e),
                    };
                    match r {
                        Ok(Ok(d)) => {
                            p.tw = p.tw.union(&d);
                            p.rir_done += 1;
                            p.failures = 0;
                            info!("台灣 IP 清單：{name} 完成（RIR {}/{}）", p.rir_done, rirs.len());
                            Ok(())
                        }
                        Ok(Err(d)) => Err(Some(d)),
                        Err(e) => {
                            p.failures += 1;
                            let msg = format!("{name}：{e:#}");
                            if p.failures >= c.max_failures {
                                return Ok(Some(Exit::Abort(format!("連續 {} 次失敗：{msg}", p.failures))));
                            }
                            let d = c.retry * 2f64.powi(p.failures as i32 - 1);
                            return Ok(Some(Exit::Pause(format!("網路錯誤：{msg}"), secs(d.min(6.0 * 3600.0)))));
                        }
                    }
                }
                "asn" => {
                    let asn = asns[p.asn_done];
                    if !first_asn {
                        let wait = c.pause.0 + (c.pause.1 - c.pause.0) * rand_unit();
                        tokio::time::sleep(secs(wait)).await;
                    }
                    first_asn = false;
                    let mut sc = PrefixScanner::new();
                    let r = fetch_into(&self.inner.sources.ripestat_url(asn), ASN_MAX, secs(c.asn_timeout), |ch| {
                        sc.feed(ch);
                        Ok(())
                    })
                    .await;
                    let p = g.prog.as_mut().unwrap();
                    p.asn_ms += t0.elapsed().as_millis() as u64;
                    let r = match r {
                        Ok(Got::Ok) => sc.finish().map(Ok),
                        Ok(Got::RateLimited(d)) => Ok(Err(d)),
                        Err(e) => Err(e),
                    };
                    match r {
                        Ok(Ok(d)) => {
                            p.announced.insert(asn, d);
                            p.asn_done += 1;
                            p.failures = 0;
                            Ok(())
                        }
                        Ok(Err(d)) => Err(Some(d)),
                        Err(e) => {
                            p.failures += 1;
                            let msg = format!("AS{asn}：{e:#}");
                            if p.failures >= c.max_failures {
                                return Ok(Some(Exit::Abort(format!("連續 {} 次失敗：{msg}", p.failures))));
                            }
                            let d = c.retry * 2f64.powi(p.failures as i32 - 1);
                            return Ok(Some(Exit::Pause(format!("網路錯誤：{msg}"), secs(d.min(6.0 * 3600.0)))));
                        }
                    }
                }
                _ => return self.finish_cycle(ctx, c, g).await,
            };
            if let Err(Some(d)) = res {
                // 429：對方要求等一下
                let p = g.prog.as_mut().unwrap();
                p.failures += 1;
                if p.failures >= c.max_failures {
                    return Ok(Some(Exit::Abort(format!("連續 {} 次被要求降速（HTTP 429）", p.failures))));
                }
                if d <= Duration::from_secs(120) {
                    info!("台灣 IP 清單：資料來源要求等 {} 秒", d.as_secs());
                    tokio::time::sleep(d).await;
                } else {
                    return Ok(Some(Exit::Pause("資料來源要求降速（HTTP 429）".into(), d)));
                }
            }
        }
    }

    /// 全部抓完：組出清單、驗證、換上
    async fn finish_cycle(&self, ctx: &JobCtx, _c: &Conf, g: &mut Guard) -> Result<Option<Exit>> {
        let now = ctx.now_ms();
        let date = date_of(now);
        let p = g.prog.take().ok_or_else(|| anyhow!("進度遺失"))?;
        let held = p.heap_bytes();
        let (v, _) = build(&p.tw, &p.announced, &date, self.inner.sources.json());
        drop(p);
        let bytes = compact(&v).into_bytes();
        drop(v);
        let t = match TwIp::parse(&bytes) {
            Ok(t) => t,
            Err(e) => return Ok(Some(Exit::Abort(format!("產生的清單格式錯誤：{e:#}")))),
        };
        let used = held + bytes.len() + t.groups.iter().map(|g| g.nets.heap_bytes()).sum::<usize>();
        self.set(|s| {
            s.cycle_peak = s.cycle_peak.max(used);
            s.peak_mem = s.peak_mem.max(used);
            s.phase = "";
            s.eta = None;
        });
        let (cur, _) = (self.inner.hooks.current)();
        let v4 = t.all().v4.size();
        if let Some(c) = cur.as_deref() {
            if same_nets(c, &t) {
                let msg = format!("重新產生完成（{date}），內容跟目前的清單一樣，不必寫入");
                info!("台灣 IP 清單：{msg}");
                self.set(|s| {
                    s.state = "done";
                    s.last_end = Some(now);
                    s.last_success = Some(now);
                    s.last_result = msg;
                });
                return Ok(None);
            }
        }
        if let Err(why) = validate(cur.as_deref(), &t) {
            return Ok(Some(Exit::Abort(format!("驗證沒通過：{why}"))));
        }
        if let Err(e) = (self.inner.hooks.install)(t, bytes) {
            return Ok(Some(Exit::Abort(format!("換上新清單失敗：{e:#}"))));
        }
        let msg = format!("已換上本機產生的清單（{date}，台灣 IPv4 {v4} 個位址）");
        info!("台灣 IP 清單：{msg}");
        self.set(|s| {
            s.state = "done";
            s.last_end = Some(now);
            s.last_success = Some(now);
            s.last_result = msg;
        });
        Ok(None)
    }
}

impl Job for TwIpJob {
    fn run(&self, ctx: JobCtx) -> BoxFuture<Result<()>> {
        let me = self.clone();
        Box::pin(async move {
            let mut ctx = ctx;
            loop {
                match me.run_once(&ctx).await? {
                    None => return Ok(()),
                    Some(d) if ctx.can_requeue() => {
                        ctx.request_later(d, RESUME_REASON);
                        return Ok(());
                    }
                    Some(d) => {
                        // 指令列直接執行：原地等，接著做
                        tokio::time::sleep(d).await;
                        ctx.reason = RESUME_REASON.to_string();
                    }
                }
            }
        })
    }

    fn detail(&self) -> Option<Value> {
        Some(self.status_json())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RIR: &str = "# 註解\n2|apnic|20261110|7|19830613|20261110|+1000\napnic|*|ipv4|*|5|summary\n\
                       apnic|TW|ipv4|1.160.0.0|1048576|20090908|allocated|A91A\n\
                       apnic|TW|ipv4|10.0.0.0|768|20090908|assigned|X\n\
                       apnic|JP|ipv4|1.0.16.0|4096|20110412|allocated|Y\n\
                       apnic|TW|ipv4|9.9.9.0|256|20110412|available|\n\
                       apnic|TW|ipv6|2001:b000::|20|20030115|allocated|Z\n\
                       apnic|TW|asn|3462|1|19950101|allocated|Z\r\n\
                       apnic|TW|ipv4|61.216.0.0|262144|20090908|allocated|B";

    fn parse_in_chunks(text: &[u8], size: usize) -> Result<Dual> {
        let mut p = DelegatedParser::new();
        for c in text.chunks(size) {
            p.feed(c);
        }
        p.finish()
    }

    #[test]
    fn delegated_streaming_any_chunk_size() {
        let want = parse_in_chunks(RIR.as_bytes(), RIR.len()).unwrap();
        assert_eq!(want.v4_cidrs(), vec!["1.160.0.0/12", "10.0.0.0/23", "10.0.2.0/24", "61.216.0.0/14"]);
        assert_eq!(want.v6_cidrs(), vec!["2001:b000::/20"]);
        // 段落邊界落在一行中間、換行字元本身、CRLF 中間：結果都一樣
        for size in 1..64 {
            assert_eq!(parse_in_chunks(RIR.as_bytes(), size).unwrap(), want, "chunk {size}");
        }
    }

    #[test]
    fn delegated_detects_truncation_and_garbage() {
        // 少了最後一行：標頭的筆數對不上
        let cut = &RIR[..RIR.rfind('\n').unwrap()];
        let e = parse_in_chunks(cut.as_bytes(), 7).unwrap_err().to_string();
        assert!(e.contains("不完整"), "{e}");
        assert!(parse_in_chunks(b"<html>error</html>\n", 5).is_err(), "不是統計檔");
        // 超長的一行：丟掉，而且算成格式錯誤（筆數對不上）
        let long = RIR.replace("apnic|JP|ipv4|1.0.16.0|4096|20110412|allocated|Y", &"x".repeat(2000));
        assert!(parse_in_chunks(long.as_bytes(), 100).is_err());
    }

    #[test]
    fn scanner_streaming() {
        let ok = br#"{"messages":[["info","x"]],"status":"ok","data_call_status":"supported","data":{"prefixes":[{"prefix":"1.160.0.0/12","timelines":[{"starttime":"2026-10-28T08:00:00"}]},{"prefix":"2001:b000::/20","timelines":[]}],"resource":"3462"},"status_code":200}"#;
        for size in [1, 2, 3, 7, 50, ok.len()] {
            let mut s = PrefixScanner::new();
            for c in ok.chunks(size) {
                s.feed(c);
            }
            let d = s.finish().unwrap();
            assert_eq!(d.v4_cidrs(), vec!["1.160.0.0/12"], "chunk {size}");
            assert_eq!(d.v6_cidrs(), vec!["2001:b000::/20"]);
        }
        let run = |b: &[u8]| {
            let mut s = PrefixScanner::new();
            s.feed(b);
            s.finish()
        };
        assert!(run(br#"{"status":"error","data":{"prefixes":[]}}"#).is_err());
        assert!(run(br#"{"data":{"prefixes":[]}}"#).is_err(), "沒有 status");
        assert!(run(&ok[..ok.len() - 10]).is_err(), "被截斷");
        assert!(run(br#"{"status":"ok","data":{"prefixes":[{"prefix":"nope"}]}}"#).is_err());
        // 內層的 status 不算
        assert!(run(br#"{"data":{"status":"ok","prefixes":[]}}"#).is_err());
        assert!(run(br#"{"status":"ok","data":{"prefixes":[]}}"#).unwrap().is_empty());
    }

    #[test]
    fn groups_are_clipped_to_tw_and_other_fills_the_rest() {
        let (tw, _) = Dual::parse(["1.160.0.0/12", "61.216.0.0/14", "2001:b000::/20"]);
        let mut ann = BTreeMap::new();
        // HiNet：台灣網段內的、跨出台灣網段的、完全在國外的
        ann.insert(
            3462,
            Dual::parse(["1.160.0.0/13", "61.216.0.0/13", "8.8.8.0/24", "2001:b000::/24"]).0,
        );
        ann.insert(38841, Dual::parse(["1.168.0.0/16"]).0);
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
    fn group_ids_unique_and_asns_not_shared() {
        let mut seen = std::collections::HashSet::new();
        for g in GROUPS {
            assert!(seen.insert(g.id.to_string()), "{}", g.id);
        }
        let asns = all_asns();
        let set: std::collections::HashSet<u32> = asns.iter().copied().collect();
        assert_eq!(set.len(), asns.len(), "有 ASN 出現在兩個群組");
        assert!(!seen.contains(OTHER_ID));
        assert_eq!(today().len(), 10);
        assert_eq!(date_of(0), "1970-01-01");
        assert_eq!(age_days("2026-11-01", crate::time::parse_date_utc("2026-11-11").unwrap()), Some(10));
        assert_eq!(age_days("bad", 0), None);
    }

    #[test]
    fn retry_after_values() {
        assert_eq!(retry_after(Some("120")), Duration::from_secs(120));
        assert_eq!(retry_after(Some("Wed, 21 Oct 2026 07:28:00 GMT")), Duration::from_secs(60));
        assert_eq!(retry_after(None), Duration::from_secs(60));
        assert_eq!(retry_after(Some("0")), Duration::from_secs(1));
        assert_eq!(retry_after(Some("999999")), Duration::from_secs(6 * 3600));
        assert!(Sources::default().ripestat_url(3462).contains("sourceapp=kuroshio-dns"));
    }

    fn twip(date: &str, groups: &[(&str, &[&str])]) -> TwIp {
        let mut gs: Vec<Value> = GROUPS
            .iter()
            .map(|g| {
                let nets = groups.iter().find(|x| x.0 == g.id).map(|x| x.1.to_vec()).unwrap_or_default();
                json!({ "id": g.id, "name": g.name, "v4": nets })
            })
            .collect();
        let other = groups.iter().find(|x| x.0 == OTHER_ID).map(|x| x.1.to_vec()).unwrap_or_default();
        gs.push(json!({ "id": OTHER_ID, "name": OTHER_NAME, "v4": other }));
        TwIp::parse(json!({ "generatedAt": date, "groups": gs }).to_string().as_bytes()).unwrap()
    }

    #[test]
    fn validation() {
        let cur = twip("2026-10-01", &[("cht", &["1.160.0.0/12"]), ("other", &["61.216.0.0/14"])]);
        let ok = twip(
            "2026-11-01",
            &[("cht", &["1.160.0.0/12"]), ("other", &["61.216.0.0/15", "60.0.0.0/16"])],
        );
        assert_eq!(validate(Some(&cur), &ok), Ok(()));
        assert_eq!(validate(None, &ok), Ok(()));
        let old = twip("2026-10-01", &[("cht", &["1.160.0.0/12"]), ("other", &["61.216.0.0/14"])]);
        assert!(validate(Some(&cur), &old).unwrap_err().contains("沒有比目前的"));
        let shrunk = twip("2026-11-01", &[("cht", &["1.160.0.0/13"]), ("other", &["61.216.0.0/14"])]);
        assert!(validate(Some(&cur), &shrunk).unwrap_err().contains("20%"), "縮水的清單不採用");
        let lost = twip("2026-11-01", &[("other", &["1.160.0.0/12", "61.216.0.0/14"])]);
        assert!(validate(Some(&cur), &lost).unwrap_err().contains("cht"), "原本有網段的群組變成空的");
        // 少了群組：格式不對
        let mut missing = ok.clone();
        missing.groups.retain(|g| g.id != "kbro");
        assert!(validate(Some(&cur), &missing).unwrap_err().contains("kbro"));
        assert!(same_nets(&cur, &old) && !same_nets(&cur, &ok));
    }
}
