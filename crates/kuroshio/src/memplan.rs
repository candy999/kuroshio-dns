//! 記憶體規劃（`kuroshio memory-plan`，3.3.3 起）：用跟執行時同一套規則，推算某個記憶體大小的機器會怎樣運作
//!
//! 規則（跟程式裡的判斷一樣）：
//! - 保留量：[`crate::memgov::auto_reserve`]（Linux：max(16 MB, 實體記憶體 5%, min_free_kbytes × 3)）
//! - 記憶體壓力：可用 < 保留量 / 2 → 不足；< 保留量 + 遲滯（max(保留量 / 2, 8 MB)）→ 偏低；其餘正常
//! - 背景工作（每日評測、CDN）只在「正常」時啟動，執行中變成偏低就在檢查點暫停
//! - 過濾清單：建好每條約 [`crate::filtering::BYTES_PER_DOMAIN`] bytes；重建時建置中每條另外約
//!   [`crate::filtering::BUILD_BYTES_PER_RULE`]，要放得進保留量以上的空間；放不下就依停用順序不載入，保護清單一定載入
//! - 每日評測（3.3.3 起在子程序裡跑）：同時測 min(設定, max(4, 保留量以上可用的 1/4 ÷ 512 KB)) 個候選
//!
//! 常數（[`Assumptions`]）是實測推算的，不是程式的判斷規則：基本用量、CDN 資料庫、評測子程序的基本用量與原始答案。
//! 32 位元的數字來自 Padavan（Newifi D3，mipsel）3.3.3 的實測，64 位元還沒有實測。

use crate::memgov::{auto_reserve, margin, Platform};
use serde_json::{json, Value};

const MB: u64 = 1 << 20;
const KB: u64 = 1 << 10;

/// 內建清單的規則行數（2026-11 下載實測）：還沒有本機副本、不知道規則數時用來估
pub const KNOWN_RULES: &[(&str, u64)] = &[
    ("https://filter.futa.gg/TW165_abp.txt", 29292),
    ("https://filter.futa.gg/TWNIC-RPZ_abp.txt", 98),
    (
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt",
        182368,
    ),
    ("https://filter.futa.gg/nrd/past-07day_abp.txt", 506583),
    ("https://filter.futa.gg/hosts_abp.txt", 656),
    ("https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt", 101267),
    ("https://easylist-downloads.adblockplus.org/easylistchina.txt", 17110),
    ("https://small.oisd.nl/", 62595),
    ("https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/light.txt", 92878),
    (
        "https://danny0838.github.io/content-farm-terminator/files/blocklist/content-farms.txt",
        20551,
    ),
    ("https://a.dove.isdumb.one/cdn", 7609),
    ("https://raw.githubusercontent.com/blocklistproject/Lists/master/smart-tv.txt", 77),
    (
        "https://raw.githubusercontent.com/Ruddernation-Designs/Adobe-URL-Block-List/master/hosts",
        950,
    ),
    (
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
        266543,
    ),
    ("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", 190969),
    ("https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt", 1461073),
    (
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh-vpn-proxy-bypass.txt",
        16682,
    ),
];

/// 不同清單重複的網域只算一次：Newifi D3 的預設清單 49 萬行實際載入 37 萬條
pub const DEDUP_PCT: u64 = 75;

/// 不在 [`KNOWN_RULES`] 裡的清單，估每份多少條
pub const UNKNOWN_LIST_RULES: u64 = 50_000;

/// 實測推算的常數（`kuroshio memory-plan --json` 會列出來；校正後再更新）
#[derive(Debug, Clone, Copy)]
pub struct Assumptions {
    /// 程式本身（執行檔、執行環境、設定、統計等固定資料），不含清單、快取、CDN
    pub base_rss: u64,
    /// CDN 網域資料庫（預設上限、實際用量）
    pub cdn: u64,
    /// DNS 快取每筆約多少（含鍵）
    pub cache_entry: u64,
    /// 評測子程序的基本用量（不含連線與原始答案）
    pub bench_base: u64,
    /// 評測手上的原始答案（預設清單、候選數）
    pub bench_raw: u64,
    /// 每個同時測的候選（連線、緩衝）
    pub bench_per_candidate: u64,
    /// 系統（核心 + 其他服務）在黑潮 DNS 啟動前用掉的：固定部分 + 實體記憶體的比例（%）。只用在假設的記憶體大小
    pub os_fixed: u64,
    pub os_pct: u64,
}

impl Assumptions {
    /// 依這個執行檔的位元數
    pub fn for_this_build() -> Assumptions {
        Self::for_bits(if cfg!(target_pointer_width = "64") { 64 } else { 32 })
    }

    /// 指定 32 / 64 位元（在電腦上推算路由器：`--bits 32`）
    pub fn for_bits(bits: u32) -> Assumptions {
        let wide = bits == 64;
        Assumptions {
            // D3（3.3.3）：評測前 RSS 21.8 MB − 清單 3.4 MB − CDN 1.7 MB ≈ 16.7 MB
            base_rss: if wide { 22 * MB } else { 16 * MB + 512 * KB },
            cdn: 2 * MB,
            cache_entry: if wide { 360 } else { 260 },
            // D3（3.3.3，評測子程序）：剛開始 11.9 MB；收集階段同時 32 個、原始答案 6 MB 時到 34.5 MB；
            // 判斷階段最高 37 MB（多出的約 2.5 MB 算進基本用量）
            bench_base: if wide { 18 * MB } else { 14 * MB + 512 * KB },
            bench_raw: 6 * MB,
            bench_per_candidate: 512 * KB,
            os_fixed: 24 * MB,
            os_pct: 8,
        }
    }

    pub fn bits(&self) -> u32 {
        if self.base_rss > 20 * MB {
            64
        } else {
            32
        }
    }

    pub fn json(&self) -> Value {
        let mb = |b: u64| (b as f64 / MB as f64 * 10.0).round() / 10.0;
        json!({
            "baseRssMB": mb(self.base_rss), "cdnMB": mb(self.cdn), "cacheEntryBytes": self.cache_entry,
            "benchBaseMB": mb(self.bench_base), "benchRawMB": mb(self.bench_raw),
            "benchPerCandidateKB": self.bench_per_candidate / KB,
            "osFixedMB": mb(self.os_fixed), "osPercent": self.os_pct,
            "bits": self.bits(),
            "source": if self.bits() == 64 { "64 位元：還沒有實測，先用 32 位元的數字放大" } else { "32 位元：Padavan（Newifi D3，mipsel）3.3.3 實測" },
        })
    }
}

/// 一台機器的條件
#[derive(Debug, Clone)]
pub struct Input {
    /// 實體記憶體
    pub total: u64,
    /// 黑潮 DNS 啟動前系統可用的記憶體（None = 依 [`Assumptions`] 推算）
    pub avail_before: Option<u64>,
    /// `vm.min_free_kbytes`（None = 依 Linux 預設公式推算）
    pub min_free_kb: Option<u64>,
    /// 使用者設定的保留量（MB、%；都是 0 = 自動）
    pub reserve_mb: u64,
    pub reserve_pct: u64,
    /// 啟用的清單合計規則數，與其中保護清單的規則數
    pub rules: u64,
    pub protected_rules: u64,
    /// 快取筆數上限（resolver.cacheMax）
    pub cache_max: u64,
    /// 每日評測同時測幾個（設定換算後的值）
    pub bench_conc: u64,
}

/// Linux 的 min_free_kbytes 預設：sqrt(記憶體 KB × 16)，限制在 128 KB–256 MB
pub fn default_min_free_kb(total: u64) -> u64 {
    (((total / KB) * 16) as f64).sqrt().clamp(128.0, 262_144.0) as u64
}

fn pressure(avail: u64, reserve: u64) -> &'static str {
    if avail < reserve / 2 {
        "critical"
    } else if avail < reserve + margin(reserve) {
        "low"
    } else {
        "normal"
    }
}

/// 推算這台機器會怎樣運作
pub fn plan(i: &Input, a: &Assumptions) -> Value {
    use crate::filtering::{BUILD_BYTES_PER_RULE, BYTES_PER_DOMAIN};
    let avail_before = i
        .avail_before
        .unwrap_or_else(|| i.total.saturating_sub(a.os_fixed + i.total / 100 * a.os_pct));
    let min_free = i.min_free_kb.unwrap_or_else(|| default_min_free_kb(i.total));
    let auto = auto_reserve(Some(i.total), Platform::Linux, Some(min_free)).0;
    let user = (i.reserve_mb * MB).max(i.total / 100 * i.reserve_pct.min(90));
    let reserve = if user > 0 { user.min(i.total / 2) } else { auto };
    let mg = margin(reserve);
    // 程式本身與 CDN 資料庫
    let avail0 = avail_before.saturating_sub(a.base_rss + a.cdn);
    // 過濾清單：建好的大小 + 建置中的大小要放得進保留量以上；放不下就只載保護清單
    let room0 = avail0.saturating_sub(reserve);
    let need = |r: u64| r * BYTES_PER_DOMAIN + r * BUILD_BYTES_PER_RULE;
    let (lists, loaded_rules) = if need(i.rules) <= room0 && pressure(avail0 - i.rules * BYTES_PER_DOMAIN, reserve) == "normal" {
        ("all", i.rules)
    } else if need(i.protected_rules) <= room0 || i.protected_rules == 0 {
        ("protected", i.protected_rules)
    } else {
        // 保護清單放不下也照樣載入（記警告）：保護比省記憶體重要
        ("protected-over-budget", i.protected_rules)
    };
    let lists_bytes = loaded_rules * BYTES_PER_DOMAIN;
    let steady = a.base_rss + a.cdn + lists_bytes;
    let avail_after = avail_before.saturating_sub(steady);
    let state = pressure(avail_after, reserve);
    // 快取：記憶體正常時才長大，長到可用記憶體到「保留量 + 遲滯」為止，或到 cacheMax
    let cache_room = avail_after.saturating_sub(reserve + mg);
    let cache_bytes = (i.cache_max * a.cache_entry).min(cache_room);
    // 每日評測：只在正常時啟動（快取還小的時候）；跑的期間變成偏低就暫停
    let bench = (state == "normal").then(|| {
        let headroom = avail_after.saturating_sub(reserve);
        let conc = i.bench_conc.min(((headroom / 4) / a.bench_per_candidate).max(4)).max(1);
        let peak = a.bench_base + a.bench_raw + conc * a.bench_per_candidate;
        let during = avail_after.saturating_sub(peak);
        json!({
            "concurrency": conc,
            "processPeakMB": mb1(peak),
            "availDuringMB": mb1(during),
            "pressureDuring": pressure(during, reserve),
            "completes": pressure(during, reserve) == "normal",
        })
    });
    let verdict = match (state, lists, &bench) {
        ("normal", "all", Some(b)) if b["completes"] == true => "完整功能：清單全部載入，每日評測與 CDN 背景工作照常",
        ("normal", "all", _) => "清單全部載入；每日評測跑的期間記憶體會偏低，會暫停、可能拖很久",
        ("normal", _, _) => "只載入保護清單（反詐騙、惡意網域）；其餘清單放不下",
        ("low", _, _) => "記憶體偏低：只載入保護清單，背景工作（每日評測、CDN）延後、快取不長大；DNS 轉送照常",
        _ => "記憶體不足：只剩轉送與保護清單，暫不接受新的加密連線；建議改用更輕量的韌體（例如 padavan-tw）",
    };
    json!({
        "totalMB": mb1(i.total),
        "availBeforeMB": mb1(avail_before),
        "availBeforeAssumed": i.avail_before.is_none(),
        "minFreeKB": min_free,
        "reserveMB": mb1(reserve),
        "marginMB": mb1(mg),
        "kuroshioSteadyMB": mb1(steady),
        "lists": lists,
        "listRules": loaded_rules,
        "listsMB": mb1(lists_bytes),
        "listRebuildPeakMB": mb1(loaded_rules * BUILD_BYTES_PER_RULE),
        "availAfterMB": mb1(avail_after),
        "pressure": state,
        "cacheMaxMB": mb1(cache_bytes),
        "benchmark": bench,
        "verdict": verdict,
    })
}

fn mb1(b: u64) -> f64 {
    (b as f64 / MB as f64 * 10.0).round() / 10.0
}

/// 文字表格（`kuroshio memory-plan`）
pub fn text(rows: &[Value], a: &Assumptions) -> String {
    let mut out = vec![
        "記憶體規劃（估計值：判斷規則跟程式一樣，常數是實測推算的）".to_string(),
        String::new(),
        "| 實體記憶體 | 啟動前可用 | 保留量 | 黑潮 DNS 常駐 | 清單 | 啟動後可用 | 狀態 | 每日評測 | 結果 |".to_string(),
        "|---|---|---|---|---|---|---|---|---|".to_string(),
    ];
    for r in rows {
        let bench = match r["benchmark"].as_object() {
            Some(b) => format!(
                "同時 {} 個，子程序最高約 {} MB{}",
                b["concurrency"],
                b["processPeakMB"],
                if b["completes"] == true { "" } else { "（會暫停）" }
            ),
            None => "延後（記憶體不夠寬裕）".into(),
        };
        let lists = match r["lists"].as_str() {
            Some("all") => format!("全部（{} 條，{} MB）", r["listRules"], r["listsMB"]),
            Some("protected") => format!("只有保護清單（{} 條）", r["listRules"]),
            _ => format!("只有保護清單（{} 條，超過預算照樣載入）", r["listRules"]),
        };
        out.push(format!(
            "| {}{} MB | {} MB{} | {} MB | {} MB | {} | {} MB | {} | {} | {} |",
            if r["thisMachine"] == true { "這台：" } else { "" },
            r["totalMB"],
            r["availBeforeMB"],
            if r["availBeforeAssumed"] == true { "（推算）" } else { "" },
            r["reserveMB"],
            r["kuroshioSteadyMB"],
            lists,
            r["availAfterMB"],
            match r["pressure"].as_str() {
                Some("normal") => "正常",
                Some("low") => "偏低",
                _ => "不足",
            },
            bench,
            r["verdict"].as_str().unwrap_or(""),
        ));
    }
    out.push(String::new());
    out.push(format!(
        "常數：程式本身約 {:.1} MB、CDN 資料庫約 {:.1} MB、評測子程序基本 {:.1} MB + 原始答案 {:.1} MB + 每個候選 {} KB；{}",
        a.base_rss as f64 / MB as f64,
        a.cdn as f64 / MB as f64,
        a.bench_base as f64 / MB as f64,
        a.bench_raw as f64 / MB as f64,
        a.bench_per_candidate / KB,
        a.json()["source"].as_str().unwrap_or("")
    ));
    out.push(format!(
        "「推算」的啟動前可用 = 實體記憶體 − {:.0} MB − {}%（OpenWrt 一般情況）；實際值請在機器上執行本指令（不加 --ram）",
        a.os_fixed as f64 / MB as f64,
        a.os_pct
    ));
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(total_mb: u64) -> Input {
        Input {
            total: total_mb * MB,
            avail_before: None,
            min_free_kb: None,
            reserve_mb: 0,
            reserve_pct: 0,
            rules: 370_000,
            protected_rules: 60_000,
            cache_max: 100_000,
            bench_conc: 32,
        }
    }

    #[test]
    fn small_machines_degrade_in_order() {
        let a = Assumptions::for_bits(32);
        let p512 = plan(&input(512), &a);
        assert_eq!(p512["lists"], "all");
        assert_eq!(p512["pressure"], "normal");
        assert_eq!(p512["benchmark"]["completes"], true);
        let p128 = plan(&input(128), &a);
        assert_eq!(p128["reserveMB"], 16.0, "128 MB：保留量 16 MB");
        assert_eq!(p128["lists"], "all");
        // 保留量以上可用約 56 MB：1/4 ÷ 512 KB = 28 個（設定是 32）
        assert_eq!(p128["benchmark"]["concurrency"], 28);
        assert_eq!(p128["benchmark"]["completes"], true);
        let p64 = plan(&input(64), &a);
        assert_ne!(p64["lists"], "all", "64 MB：清單放不下全部");
        assert!(p64["benchmark"].is_null(), "64 MB：每日評測延後");
        // 實際量到的可用記憶體優先於推算
        let mut i = input(128);
        i.avail_before = Some(30 * MB);
        assert_eq!(plan(&i, &a)["availBeforeAssumed"], false);
        assert_eq!(default_min_free_kb(128 * MB), 1448);
    }
}
