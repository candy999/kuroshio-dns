//! 黑潮 DNS 過濾引擎：node 版 `legacy-node/lib/filter.js` 的移植。
//!
//! # 語意（跟 node 版相同）
//! - 兩層：**自訂規則**整層最優先，其次是**訂閱清單**。某一層有命中（封鎖或放行）就不再看下一層。
//! - 每一層內的優先順序：`@@...$important` > `...$important` > `@@...` > 封鎖。
//!   同一個優先等級裡取「第一個命中」：先看精確（hosts / `|domain^`），再從完整名稱往上一層一層看
//!   `||domain^`，最後才是正規表示式 / 萬用字元（依載入順序）。
//! - 語法：AdGuard（`||domain^`、`|domain^`、`@@`、`$important`、`$badfilter`、`$dnstype`、
//!   `$match-case`；`$third-party` 這類資源修飾詞只在 `relaxed_modifiers` 時忽略，否則整條略過）、
//!   hosts（任何 IP 後接網域 → 精確封鎖，IP 本身絕不採用；只取第一個網域）、純網域行（含子網域）、
//!   `!` / `#` 註解、化妝品規則略過、`/regex/`。
//! - 分類：廣告(1) < 遙測(2) < 惡意(3)；同一個網域在多份清單出現只算一條，分類取傷害性高的。
//! - 自訂規則可用 `! @begin 遙測` / `! @end` 分段標記分類（廣告 / ads、遙測 / telemetry、惡意 / malware）。
//!
//! # 記憶體結構（規格 05 §3.2）
//! 網域規則存成「64 位元鍵」的排序陣列（每筆 8 bytes）＋ 1 byte 的分類 / 清單編號：
//! - 鍵 = `domain_hash(網域) & !7`，低 3 位元是旗標：精確 / 含子網域、放行 / 封鎖、important。
//!   同一個網域的不同旗標排在一起，一次二分搜尋就找到。
//! - [`domain_hash`]：FNV-1a 64，對「小寫、不含結尾點」的網域**由右往左**逐位元組計算，
//!   這樣比對時一次掃過查詢名稱就能得到每一層上層網域的雜湊。
//! - 正規表示式、萬用字元、`$dnstype` 規則另外存（保留原始文字），依序線性比對，有數量上限。
//! - 只存雜湊，所以清單層命中時回傳的規則文字是由命中的網域還原（跟 node 版完全一樣的格式）；
//!   自訂規則與複雜規則保留原始文字。
//! - 去重：建置完成時依（網域, 精確/子網域）分組，照載入順序模擬 node 版 `RuleTier._put`
//!   （單一規則時合併、分類取高的；出現不同動作或 `$dnstype` 後變成陣列、每個優先等級取第一條），
//!   所以分類、命中規則與統計數字都跟 node 版一致。
//!
//! # 跟 node 版不同的地方
//! - 正規表示式用內建的小引擎（不引入 regex crate）：反向參照 `\1` / `\k<name>`、舊式八進位跳脫不支援，
//!   這類規則算「略過」（`skipped` 與 `regex_unsupported` 都會 +1）；回溯超過 10 萬步
//!   就當作沒命中（node 版會一直跑）；非 ASCII 字元在字元類別裡的大小寫對應是近似的。
//! - 新增的預算：`max_domains`（超過的清單整份不載入）與 `max_complex`（超過的清單複雜規則丟掉）。
//! - 最多 64 份清單；單行超過 64 KB 的部分丟掉；分類只有四種（設定裡不認得的分類由整合端決定怎麼對應）。
//! - 沒有 node 版那個 10 萬筆的判定快取（伺服器的 DNS 快取已經涵蓋）。
//! - 61 位元雜湊理論上可能碰撞（1,000 萬筆時每查一層誤判機率約 4×10⁻¹²）。
//!
//! # 用法
//! ```
//! use kuroshio_filter::{BuildOptions, Category, FilterBuilder, ListSpec};
//! let mut b = FilterBuilder::new(BuildOptions::default());
//! b.add_custom(b"@@||good.example^\n");
//! b.add_list(ListSpec::new("清單", Category::Ads), b"||example^\n0.0.0.0 tracker.test\n").unwrap();
//! let f = b.finish();
//! assert!(f.check("ads.example", 1).unwrap().is_block());
//! assert!(f.check("good.example", 1).unwrap().is_allow());
//! assert!(f.check("x.tracker.test", 1).is_none());
//! ```

mod builder;
mod filter;
mod js;
mod parse;
mod regex;

pub use builder::{BuildError, BuildOptions, FilterBuilder, ListSpec, SourceWriter};
pub use filter::{Filter, Verdict};

/// 規則分類。數值就是傷害性排名（自訂 0 < 廣告 1 < 遙測 2 < 惡意 3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    /// 自訂規則（段落外）
    Custom = 0,
    Ads = 1,
    Telemetry = 2,
    Malware = 3,
}

impl Category {
    pub const ALL: [Category; 4] = [Category::Custom, Category::Ads, Category::Telemetry, Category::Malware];

    /// 設定檔與 node 版使用的名稱：`custom` / `ads` / `telemetry` / `malware`
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Custom => "custom",
            Category::Ads => "ads",
            Category::Telemetry => "telemetry",
            Category::Malware => "malware",
        }
    }

    /// 中文名稱（日誌、LuCI 顯示用）
    pub fn label(self) -> &'static str {
        match self {
            Category::Custom => "自訂",
            Category::Ads => "廣告",
            Category::Telemetry => "遙測",
            Category::Malware => "惡意",
        }
    }

    /// 解析設定檔的分類名稱（也接受中文）；不認得的回傳 None
    pub fn parse(s: &str) -> Option<Category> {
        Some(match s.to_ascii_lowercase().as_str() {
            "custom" | "自訂" => Category::Custom,
            "ads" | "廣告" => Category::Ads,
            "telemetry" | "遙測" => Category::Telemetry,
            "malware" | "惡意" => Category::Malware,
            _ => return None,
        })
    }

    fn from_bits(b: u8) -> Category {
        Category::ALL[usize::from(b & 3)]
    }
}

/// 判定動作
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Block,
}

/// 命中的是哪一層
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierKind {
    Custom,
    Lists,
}

impl TierKind {
    /// node 版的層名稱：`custom` / `lists`
    pub fn as_str(self) -> &'static str {
        match self {
            TierKind::Custom => "custom",
            TierKind::Lists => "lists",
        }
    }
}

/// 命中方式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    /// 只比對網域本身（hosts、`|domain^`）
    Exact,
    /// 網域本身與子網域（`||domain^`、純網域行）
    Suffix,
    /// 正規表示式 / 萬用字元
    Pattern,
}

/// 各分類的數量（以 [`Category`] 當索引）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CategoryCounts(pub [u64; 4]);

impl CategoryCounts {
    pub fn get(&self, c: Category) -> u64 {
        self.0[c as usize]
    }
    fn add(&mut self, c: Category, n: i64) {
        let v = &mut self.0[c as usize];
        *v = v.saturating_add_signed(n);
    }
}

/// 一個來源（自訂規則檔或清單）的載入狀態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceStatus {
    Loaded,
    /// 設定裡停用（`enabled: false`），不載入
    Disabled,
    /// 累計超過 `max_domains`，整份不載入。`rules` 是這份清單的網域規則數、`remaining` 是當時剩下的額度
    OverBudget {
        rules: u64,
        remaining: u64,
    },
}

/// 一個來源的統計
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceStats {
    pub name: String,
    pub category: Category,
    pub custom: bool,
    pub status: SourceStatus,
    /// 讀到的行數
    pub lines: u64,
    /// 網域規則數（雜湊結構裡的，未去重）
    pub domain_rules: u64,
    /// 複雜規則數（正規表示式、萬用字元、`$dnstype`）
    pub complex_rules: u64,
    /// 不適用 DNS 而略過（node 版的 skipped）
    pub unsupported: u64,
    /// 其中 node 版能載入、但本引擎不支援的正規表示式（反向參照、後顧等）
    pub regex_unsupported: u64,
    /// 超過複雜規則上限而丟掉
    pub complex_dropped: u64,
    /// `$badfilter` 規則數
    pub badfilter: u64,
}

/// 整體統計
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterStats {
    /// 自訂層規則數（同 node 版 `stats.custom`）
    pub custom: u64,
    /// 清單層規則數（同 node 版 `stats.lists`：去重後；含複雜規則）
    pub lists: u64,
    /// 清單層各分類數量（同 node 版 `stats.byCategory`）
    pub by_category: CategoryCounts,
    /// 自訂層各分類數量（段落分類）
    pub custom_by_category: CategoryCounts,
    /// 不適用 DNS 而略過的規則（同 node 版 `stats.skipped`；含 `regex_unsupported`）
    pub skipped: u64,
    /// node 版能載入、本引擎不支援的正規表示式規則數
    pub regex_unsupported: u64,
    /// 重複（同網域、同動作）而合併掉的規則數
    pub duplicates: u64,
    /// 被 `$badfilter` 取消的規則數
    pub badfilter_removed: u64,
    /// 雜湊結構裡的網域筆數（兩層合計，去重後）
    pub domains: u64,
    /// 計入預算的網域規則數（未去重）與上限
    pub budget_used: u64,
    pub max_domains: u64,
    /// 複雜規則數（兩層合計）、上限、超過上限丟掉的數量
    pub complex: u64,
    pub max_complex: u64,
    pub complex_dropped: u64,
    /// 各來源（依加入順序；自訂規則檔也在內）
    pub sources: Vec<SourceStats>,
}

impl FilterStats {
    /// 超過預算未載入的清單
    pub fn over_budget(&self) -> impl Iterator<Item = &SourceStats> {
        self.sources.iter().filter(|s| matches!(s.status, SourceStatus::OverBudget { .. }))
    }
}

/// 網域雜湊：FNV-1a 64（offset basis `0xcbf29ce484222325`、prime `0x100000001b3`），
/// 輸入是小寫、不含結尾點的網域，**由最後一個位元組往前**逐位元組計算。
pub fn domain_hash(domain: &str) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in domain.as_bytes().iter().rev() {
        h = fnv_step(h, b);
    }
    h
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

#[inline]
fn fnv_step(h: u64, b: u8) -> u64 {
    (h ^ u64::from(b)).wrapping_mul(FNV_PRIME)
}

/// FNV-1a 64（正向），用於規則文字的指紋
fn text_hash(s: &str) -> u64 {
    s.bytes().fold(FNV_OFFSET, fnv_step)
}

/// 查詢類型的名稱（同 node 版 dns-packet 的命名；65 / 64 是 HTTPS / SVCB，其他未知類型是 `UNKNOWN_n`）。
/// 只有 `$dnstype` 規則會用到。
pub fn qtype_name(qtype: u16) -> std::borrow::Cow<'static, str> {
    QTYPES
        .iter()
        .find(|(n, _)| *n == qtype)
        .map(|(_, s)| std::borrow::Cow::Borrowed(*s))
        .unwrap_or_else(|| std::borrow::Cow::Owned(format!("UNKNOWN_{qtype}")))
}

/// [`qtype_name`] 的反向（不分大小寫；也接受 `UNKNOWN_n`、`TYPEn`）
pub fn qtype_from_name(name: &str) -> Option<u16> {
    let up = name.to_ascii_uppercase();
    if let Some((n, _)) = QTYPES.iter().find(|(_, s)| *s == up) {
        return Some(*n);
    }
    up.strip_prefix("UNKNOWN_")
        .or_else(|| up.strip_prefix("TYPE"))
        .and_then(|n| n.parse().ok())
}

const QTYPES: [(u16, &str); 46] = [
    (1, "A"),
    (2, "NS"),
    (5, "CNAME"),
    (6, "SOA"),
    (10, "NULL"),
    (12, "PTR"),
    (13, "HINFO"),
    (15, "MX"),
    (16, "TXT"),
    (17, "RP"),
    (18, "AFSDB"),
    (24, "SIG"),
    (25, "KEY"),
    (28, "AAAA"),
    (29, "LOC"),
    (33, "SRV"),
    (35, "NAPTR"),
    (36, "KX"),
    (37, "CERT"),
    (39, "DNAME"),
    (41, "OPT"),
    (42, "APL"),
    (43, "DS"),
    (44, "SSHFP"),
    (45, "IPSECKEY"),
    (46, "RRSIG"),
    (47, "NSEC"),
    (48, "DNSKEY"),
    (49, "DHCID"),
    (50, "NSEC3"),
    (51, "NSEC3PARAM"),
    (52, "TLSA"),
    (55, "HIP"),
    (59, "CDS"),
    (60, "CDNSKEY"),
    (64, "SVCB"),
    (65, "HTTPS"),
    (99, "SPF"),
    (249, "TKEY"),
    (250, "TSIG"),
    (251, "IXFR"),
    (252, "AXFR"),
    (255, "ANY"),
    (257, "CAA"),
    (32768, "TA"),
    (32769, "DLV"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_fixed() {
        // 固定值：改了雜湊就會讓存下來的緊湊格式失效，必須同時改版本
        assert_eq!(domain_hash(""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(domain_hash("a"), 0xaf63_dc4c_8601_ec8c);
        assert_ne!(domain_hash("ab"), domain_hash("ba"));
    }

    #[test]
    fn qtypes() {
        assert_eq!(qtype_name(65), "HTTPS");
        assert_eq!(qtype_name(28), "AAAA");
        assert_eq!(qtype_name(4242), "UNKNOWN_4242");
        assert_eq!(qtype_from_name("https"), Some(65));
        assert_eq!(qtype_from_name("UNKNOWN_4242"), Some(4242));
    }
}
