//! 串流建置：清單邊下載邊餵位元組，逐行解析，不保留整份文字。

use std::collections::HashSet;

use crate::filter::{class_of, lit_trigrams, meta_of, Filter, KeyedRule, PatternRule, TierData, F_ALLOW, F_EXACT, F_IMPORTANT};
use crate::parse::{badfilter_target, parse_rule, Body, Parsed, Rule};
use crate::{domain_hash, js, text_hash, Category, CategoryCounts, FilterStats, SourceStats, SourceStatus};

/// 建置選項
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildOptions {
    /// 網域規則總數上限（設定 `filter.maxDomains`）。依清單順序累計，超過的清單整份不載入；自訂規則永遠載入（但會佔額度）。
    pub max_domains: u64,
    /// 複雜規則（正規表示式、萬用字元、`$dnstype`）上限；超過的清單規則丟掉並計數。自訂規則不受限（但會佔額度）。
    /// 建議值：tiny 2,000、small 5,000、standard 以上 20,000。
    pub max_complex: u64,
    /// 其中「沒有可用固定字串」（三字元索引用不上、每次查詢都要跑一次）的正規表示式 / 萬用字元規則上限
    /// （設定 `filter.maxUnindexed`）。這種規則每 2,000 條約讓每次查詢多 0.5 ms；超過的清單規則丟掉並計數。
    /// 自訂規則不受限（但會佔額度）。建議值：tiny 200、small 500、standard 1,000、large 2,000。
    pub max_unindexed: u64,
    /// 設定 `filter.relaxedModifiers`：把 `||domain^$third-party` 之類當成整個網域封鎖（只套用在清單層）
    pub relaxed_modifiers: bool,
}

impl Default for BuildOptions {
    fn default() -> Self {
        BuildOptions {
            max_domains: 10_000_000,
            max_complex: 20_000,
            max_unindexed: 2_000,
            relaxed_modifiers: false,
        }
    }
}

/// 一份清單
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListSpec {
    pub name: String,
    pub category: Category,
    /// 設定裡的 `enabled`（預設 true）；false 時不載入，只記在統計裡
    pub enabled: bool,
}

impl ListSpec {
    pub fn new(name: impl Into<String>, category: Category) -> ListSpec {
        ListSpec {
            name: name.into(),
            category,
            enabled: true,
        }
    }
}

/// 建置錯誤
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// 清單編號只有 6 位元
    TooManyLists,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::TooManyLists => write!(f, "過濾清單太多：最多 {MAX_LISTS} 份"),
        }
    }
}

impl std::error::Error for BuildError {}

pub(crate) const MAX_LISTS: usize = 64;

/// 建置中的一筆網域規則（16 bytes）。
/// - `key`：`domain_hash & !7 | 旗標`
/// - `aux`：`序號(32) | dnstype 標記(1) | 規則文字指紋(23) | meta(8)`；排序時同一網域依序號（載入順序）排列
#[derive(Debug, Clone, Copy)]
struct Rec {
    key: u64,
    aux: u64,
}

const MARKER: u64 = 1 << 31;

impl Rec {
    fn of(r: [u64; 2]) -> Rec {
        Rec { key: r[0], aux: r[1] }
    }
    fn seq(self) -> u32 {
        (self.aux >> 32) as u32
    }
    fn marker(self) -> bool {
        self.aux & MARKER != 0
    }
    fn fp(self) -> u32 {
        ((self.aux >> 8) & 0x7f_ffff) as u32
    }
    fn meta(self) -> u8 {
        self.aux as u8
    }
    fn cat(self) -> Category {
        Category::from_bits(self.meta() >> 6)
    }
}

fn fingerprint(trimmed_text: &str) -> u32 {
    (text_hash(trimmed_text) >> 41) as u32
}

fn make_key(domain: &str, exact: bool, allow: bool, important: bool) -> u64 {
    (domain_hash(domain) & !7) | if exact { F_EXACT } else { 0 } | if allow { F_ALLOW } else { 0 } | if important { F_IMPORTANT } else { 0 }
}

#[derive(Default)]
struct TierBuild {
    /// [key, aux]；用陣列存是為了最後能 `into_flattened` 原地改成鍵陣列，不必再配置一份
    raw: Vec<[u64; 2]>,
    seq: u32,
    /// (序號, 規則)
    keyed: Vec<(u32, KeyedRule)>,
    patterns: Vec<PatternRule>,
    /// `$badfilter` 要取消的規則文字
    bad: Vec<Box<str>>,
    /// 自訂層：依序號存原始文字
    texts: Vec<Box<str>>,
    skipped: u64,
    regex_unsupported: u64,
}

/// 串流建置器。依序加入自訂規則與清單，最後 [`FilterBuilder::finish`] 產生不可變的 [`Filter`]。
pub struct FilterBuilder {
    opts: BuildOptions,
    custom: TierBuild,
    lists: TierBuild,
    sources: Vec<SourceStats>,
    list_sources: Vec<usize>,
    /// 自訂規則目前的分類段落（跨檔案延續，同 node 版把所有自訂檔的行接在一起）
    section: Category,
    budget_used: u64,
    complex: u64,
    complex_dropped: u64,
    unindexed: u64,
    unindexed_dropped: u64,
}

impl FilterBuilder {
    pub fn new(opts: BuildOptions) -> FilterBuilder {
        FilterBuilder {
            opts,
            custom: TierBuild::default(),
            lists: TierBuild::default(),
            sources: Vec::new(),
            list_sources: Vec::new(),
            section: Category::Custom,
            budget_used: 0,
            complex: 0,
            complex_dropped: 0,
            unindexed: 0,
            unindexed_dropped: 0,
        }
    }

    /// 預留空間（例如依上次下載的規則數），避免 Vec 倍增時的尖峰
    pub fn reserve(&mut self, domain_rules: usize) {
        self.lists.raw.reserve_exact(domain_rules);
    }

    /// 開始一個自訂規則檔（可以呼叫多次；開頭的 BOM 會去掉）
    pub fn custom(&mut self) -> SourceWriter<'_> {
        let idx = self.sources.len();
        self.sources.push(SourceStats {
            name: String::from("自訂規則"),
            category: Category::Custom,
            custom: true,
            status: SourceStatus::Loaded,
            lines: 0,
            domain_rules: 0,
            complex_rules: 0,
            unsupported: 0,
            regex_unsupported: 0,
            complex_dropped: 0,
            unindexed_dropped: 0,
            badfilter: 0,
        });
        SourceWriter::new(self, idx, true, 0, Category::Custom, true)
    }

    /// 開始一份清單。停用的清單會記在統計裡，餵進來的資料直接丟掉。
    pub fn list(&mut self, spec: ListSpec) -> Result<SourceWriter<'_>, BuildError> {
        if self.list_sources.len() >= MAX_LISTS {
            return Err(BuildError::TooManyLists);
        }
        let idx = self.sources.len();
        let list_no = self.list_sources.len() as u8;
        self.list_sources.push(idx);
        self.sources.push(SourceStats {
            name: spec.name,
            category: spec.category,
            custom: false,
            status: if spec.enabled {
                SourceStatus::Loaded
            } else {
                SourceStatus::Disabled
            },
            lines: 0,
            domain_rules: 0,
            complex_rules: 0,
            unsupported: 0,
            regex_unsupported: 0,
            complex_dropped: 0,
            unindexed_dropped: 0,
            badfilter: 0,
        });
        Ok(SourceWriter::new(self, idx, false, list_no, spec.category, spec.enabled))
    }

    /// 便利函式：一次加入整個自訂規則檔
    pub fn add_custom(&mut self, bytes: &[u8]) -> &SourceStats {
        let mut w = self.custom();
        w.feed(bytes);
        let idx = w.end();
        &self.sources[idx]
    }

    /// 便利函式：一次加入整份清單
    pub fn add_list(&mut self, spec: ListSpec, bytes: &[u8]) -> Result<&SourceStats, BuildError> {
        let mut w = self.list(spec)?;
        w.feed(bytes);
        let idx = w.end();
        Ok(&self.sources[idx])
    }

    /// 完成建置：排序、去重（分類取傷害性高的）、套用 `$badfilter`，產生不可變的過濾器。
    pub fn finish(self) -> Filter {
        let FilterBuilder {
            opts,
            custom,
            lists,
            sources,
            list_sources,
            budget_used,
            complex,
            complex_dropped,
            unindexed,
            unindexed_dropped,
            ..
        } = self;
        let mut stats = FilterStats {
            budget_used,
            max_domains: opts.max_domains,
            complex,
            max_complex: opts.max_complex,
            complex_dropped,
            unindexed,
            max_unindexed: opts.max_unindexed,
            unindexed_dropped,
            skipped: custom.skipped + lists.skipped,
            regex_unsupported: custom.regex_unsupported + lists.regex_unsupported,
            ..FilterStats::default()
        };
        let (custom, cs) = finish_tier(custom, false, true);
        let (lists, ls) = finish_tier(lists, opts.relaxed_modifiers, false);
        stats.custom = cs.count;
        stats.custom_by_category = cs.by_cat;
        stats.lists = ls.count;
        stats.by_category = ls.by_cat;
        stats.duplicates = cs.duplicates + ls.duplicates;
        stats.badfilter_removed = cs.bad_removed + ls.bad_removed;
        stats.domains = (custom.keys.len() + lists.keys.len()) as u64;
        stats.complex = (custom.keyed.len() + custom.patterns.len() + lists.keyed.len() + lists.patterns.len()) as u64;
        // `$badfilter` 取消之後實際留下、每次查詢都要跑的（索引裡的 `always`）
        stats.unindexed = (custom.always.len() + lists.always.len()) as u64;
        stats.sources = sources;
        Filter {
            custom,
            lists,
            list_sources,
            stats,
        }
    }
}

/// 一個來源的寫入器：[`SourceWriter::feed`] 任意切塊的位元組（一行可以被切在兩塊之間），最後 [`SourceWriter::end`]。
/// 沒呼叫 `end` 就丟掉時也會自動結束。
pub struct SourceWriter<'b> {
    b: &'b mut FilterBuilder,
    source: usize,
    custom: bool,
    list_no: u8,
    cat: Category,
    /// 啟用且未超過預算
    active: bool,
    over: bool,
    bom_pending: bool,
    carry: Vec<u8>,
    ended: bool,
    // 超過預算時要退回的位置
    start_raw: usize,
    start_keyed: usize,
    start_patterns: usize,
    start_bad: usize,
    start_complex: u64,
    start_budget: u64,
    start_dropped: u64,
}

/// 單行最長保留多少位元組（超過的部分丟掉，避免異常檔案吃光記憶體）
const MAX_LINE: usize = 64 * 1024;

impl<'b> SourceWriter<'b> {
    fn new(b: &'b mut FilterBuilder, source: usize, custom: bool, list_no: u8, cat: Category, enabled: bool) -> SourceWriter<'b> {
        let t = if custom { &b.custom } else { &b.lists };
        SourceWriter {
            start_raw: t.raw.len(),
            start_keyed: t.keyed.len(),
            start_patterns: t.patterns.len(),
            start_bad: t.bad.len(),
            start_complex: b.complex,
            start_budget: b.budget_used,
            start_dropped: b.complex_dropped,
            b,
            source,
            custom,
            list_no,
            cat,
            active: enabled,
            over: false,
            bom_pending: custom,
            carry: Vec::new(),
            ended: false,
        }
    }

    /// 餵一段位元組
    pub fn feed(&mut self, mut chunk: &[u8]) {
        if !self.active && !self.over {
            return;
        }
        while let Some(nl) = chunk.iter().position(|&c| c == b'\n') {
            let (head, rest) = chunk.split_at(nl);
            chunk = &rest[1..];
            if self.carry.is_empty() {
                self.line(head);
            } else {
                self.push_carry(head);
                let line = std::mem::take(&mut self.carry);
                self.line(&line);
                self.carry = line;
                self.carry.clear();
            }
        }
        self.push_carry(chunk);
    }

    fn push_carry(&mut self, bytes: &[u8]) {
        let room = MAX_LINE.saturating_sub(self.carry.len());
        self.carry.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    /// 結束這個來源，回傳它在 [`FilterStats::sources`] 的索引
    pub fn end(mut self) -> usize {
        self.finish_source();
        self.source
    }

    fn finish_source(&mut self) {
        if self.ended {
            return;
        }
        self.ended = true;
        if self.active || self.over {
            // 最後一段（沒有換行結尾）也是一行，同 node 版 split
            let last = std::mem::take(&mut self.carry);
            self.line(&last);
        }
        let st = &mut self.b.sources[self.source];
        if self.over {
            st.status = SourceStatus::OverBudget {
                rules: st.domain_rules,
                remaining: self.b.opts.max_domains.saturating_sub(self.start_budget),
            };
        } else if self.active {
            let t = if self.custom { &mut self.b.custom } else { &mut self.b.lists };
            t.skipped += st.unsupported;
            t.regex_unsupported += st.regex_unsupported;
        }
    }

    fn line(&mut self, raw: &[u8]) {
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        let text = String::from_utf8_lossy(raw);
        let mut text: &str = &text;
        if self.bom_pending {
            self.bom_pending = false;
            text = text.strip_prefix('\u{feff}').unwrap_or(text);
        }
        self.b.sources[self.source].lines += 1;
        let cat = if self.custom {
            if let Some((is_end, arg)) = section(text) {
                self.b.section = if is_end { Category::Custom } else { section_cat(arg) };
                return;
            }
            self.b.section
        } else {
            self.cat
        };
        match parse_rule(text, self.b.opts.relaxed_modifiers && !self.custom) {
            Parsed::Skip => {}
            Parsed::Unsupported { regex_feature } => {
                let st = &mut self.b.sources[self.source];
                st.unsupported += 1;
                st.regex_unsupported += u64::from(regex_feature);
            }
            Parsed::Rule(rule) => self.add(rule, text, cat),
        }
    }

    fn add(&mut self, rule: Rule, text: &str, cat: Category) {
        let custom = self.custom;
        if rule.badfilter {
            self.b.sources[self.source].badfilter += 1;
            if !self.over {
                self.tier().bad.push(badfilter_target(text).into_boxed_str());
            }
            return;
        }
        let meta = meta_of(cat, self.list_no);
        let complex = matches!(rule.body, Body::Pattern { .. }) || rule.dnstype.is_some();
        {
            let st = &mut self.b.sources[self.source];
            if complex {
                st.complex_rules += 1;
            }
            if !matches!(rule.body, Body::Pattern { .. }) {
                st.domain_rules += 1;
            }
        }
        if self.over {
            return;
        }
        if complex && !custom && self.b.complex >= self.b.opts.max_complex {
            self.b.complex_dropped += 1;
            self.b.sources[self.source].complex_dropped += 1;
            return;
        }
        let Rule {
            allow,
            important,
            dnstype,
            body,
            ..
        } = rule;
        match body {
            Body::Pattern { re, lit } => {
                let tri = lit.as_deref().and_then(lit_trigrams);
                // 沒有可用固定字串：三字元索引用不上，每次查詢都要跑一次正規表示式
                if tri.is_none() {
                    if !custom && self.b.unindexed >= self.b.opts.max_unindexed {
                        self.b.unindexed_dropped += 1;
                        self.b.sources[self.source].unindexed_dropped += 1;
                        return;
                    }
                    self.b.unindexed += 1;
                }
                self.b.complex += 1;
                self.tier().patterns.push(PatternRule {
                    re,
                    tri,
                    lit: lit.map(String::into_boxed_str),
                    allow,
                    important,
                    dnstype: dnstype.map(Box::new),
                    meta,
                    text: text.into(),
                });
            }
            Body::Exact(ref d) | Body::Suffix(ref d) => {
                if !custom && self.b.budget_used >= self.b.opts.max_domains {
                    self.go_over();
                    return;
                }
                self.b.budget_used += 1;
                let key = make_key(d, matches!(body, Body::Exact(_)), allow, important);
                let fp = fingerprint(js::trim(text));
                let t = self.tier();
                let seq = t.seq;
                t.seq = t.seq.wrapping_add(1);
                let mut aux = (u64::from(seq) << 32) | (u64::from(fp) << 8) | u64::from(meta);
                if let Some(dnstype) = dnstype {
                    aux |= MARKER;
                    t.keyed.push((
                        seq,
                        KeyedRule {
                            key,
                            dnstype,
                            meta,
                            text: text.into(),
                        },
                    ));
                    self.b.complex += 1;
                }
                let room = if custom {
                    u64::MAX
                } else {
                    self.b.opts.max_domains - self.b.budget_used
                };
                let t = self.tier();
                if t.raw.len() == t.raw.capacity() {
                    // 每次只長 1.5 倍、而且不超過剩下的預算，壓低重新配置時新舊並存的尖峰
                    let grow = (t.raw.capacity() / 2)
                        .max(4096)
                        .min(usize::try_from(room).unwrap_or(usize::MAX).max(1));
                    t.raw.reserve_exact(grow);
                }
                t.raw.push([key, aux]);
                if custom {
                    t.texts.push(text.into());
                }
            }
        }
    }

    fn tier(&mut self) -> &mut TierBuild {
        if self.custom {
            &mut self.b.custom
        } else {
            &mut self.b.lists
        }
    }

    /// 超過預算：退回這份清單已經放進去的東西，之後只計數
    fn go_over(&mut self) {
        self.over = true;
        self.active = false;
        let (r, k, p, bd) = (self.start_raw, self.start_keyed, self.start_patterns, self.start_bad);
        let t = self.tier();
        t.raw.truncate(r);
        t.keyed.truncate(k);
        t.patterns.truncate(p);
        t.bad.truncate(bd);
        self.b.complex = self.start_complex;
        self.b.budget_used = self.start_budget;
        self.b.complex_dropped = self.start_dropped;
        self.b.sources[self.source].complex_dropped = 0;
    }
}

impl Drop for SourceWriter<'_> {
    fn drop(&mut self) {
        self.finish_source();
    }
}

/// 自訂規則的分類段落：`/^\s*[!#]\s*@(begin|end)\b\s*(\S*)/i`，回傳 (是否 end, 參數)
fn section(line: &str) -> Option<(bool, &str)> {
    let t = line.trim_start_matches(js::is_space);
    let t = t.strip_prefix(['!', '#'])?;
    let t = t.trim_start_matches(js::is_space).strip_prefix('@')?;
    let (is_end, rest) = if t.get(..5).is_some_and(|w| w.eq_ignore_ascii_case("begin")) {
        (false, &t[5..])
    } else if t.get(..3).is_some_and(|w| w.eq_ignore_ascii_case("end")) {
        (true, &t[3..])
    } else {
        return None;
    };
    if rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let rest = rest.trim_start_matches(js::is_space);
    let n = rest.find(js::is_space).unwrap_or(rest.len());
    Some((is_end, &rest[..n]))
}

/// 段落名稱：廣告 / ads、遙測 / telemetry、惡意 / malware；其他維持「自訂」
fn section_cat(arg: &str) -> Category {
    match &*js::lower(arg) {
        "ads" | "廣告" => Category::Ads,
        "telemetry" | "遙測" => Category::Telemetry,
        "malware" | "惡意" => Category::Malware,
        _ => Category::Custom,
    }
}

#[derive(Default)]
struct TierStats {
    count: u64,
    by_cat: CategoryCounts,
    duplicates: u64,
    bad_removed: u64,
}

/// 完成一層：套用 `$badfilter`、依網域分組模擬 node 版 `_put` 的去重與陣列順序，產生緊湊結構。
fn finish_tier(mut t: TierBuild, relaxed: bool, is_custom: bool) -> (TierData, TierStats) {
    let mut st = TierStats::default();

    // 1. $badfilter：取消「規則文字（trim 後）完全相同」的規則，跨清單有效
    if !t.bad.is_empty() {
        let bad_texts: HashSet<&str> = t.bad.iter().map(|s| &**s).collect();
        let mut bad_keys: HashSet<(u64, u32)> = HashSet::new();
        for b in &t.bad {
            if let Parsed::Rule(r) = parse_rule(b, relaxed) {
                if let (false, None, Body::Exact(d) | Body::Suffix(d)) = (r.badfilter, &r.dnstype, &r.body) {
                    bad_keys.insert((make_key(d, matches!(r.body, Body::Exact(_)), r.allow, r.important), fingerprint(b)));
                }
            }
        }
        let mut dead_seqs: HashSet<u32> = HashSet::new();
        t.keyed.retain(|(seq, k)| {
            let keep = !bad_texts.contains(js::trim(&k.text));
            if !keep {
                dead_seqs.insert(*seq);
            }
            keep
        });
        let before = t.raw.len() + t.patterns.len();
        t.raw.retain(|&r| {
            let r = Rec::of(r);
            if r.marker() {
                !dead_seqs.contains(&r.seq())
            } else {
                !bad_keys.contains(&(r.key, r.fp()))
            }
        });
        t.patterns.retain(|p| !bad_texts.contains(js::trim(&p.text)));
        st.bad_removed = (before - t.raw.len() - t.patterns.len()) as u64;
    }
    t.bad = Vec::new();

    // 2. 依（網域, 精確/子網域）分組、組內依載入順序
    t.raw.sort_unstable_by_key(|r| (r[0] & !(F_ALLOW | F_IMPORTANT), r[1]));

    // 3. 模擬 node 版 RuleTier._put：
    //    - 第一筆之後，只要一直是「同動作、同 important、都沒有 $dnstype」就合併（分類取傷害性高的，不另計數）
    //    - 一旦出現不同的規則就變成陣列：之後全部照順序加入（各自計數），比對時每個優先等級取陣列裡第一個
    //    結果：每組每個優先等級最多留一筆一般規則；$dnstype 規則只有排在同等級一般規則之前才有機會命中
    let mut live_keyed: HashSet<u32> = HashSet::new();
    let n = t.raw.len();
    let (mut i, mut w) = (0, 0);
    while i < n {
        let g = t.raw[i][0] & !(F_ALLOW | F_IMPORTANT);
        let mut j = i + 1;
        while j < n && t.raw[j][0] & !(F_ALLOW | F_IMPORTANT) == g {
            j += 1;
        }
        let mut cur = Rec::of(t.raw[i]);
        st.count += 1;
        st.by_cat.add(cur.cat(), 1);
        let mut k = i + 1;
        while k < j {
            let r = Rec::of(t.raw[k]);
            if cur.marker() || r.marker() || class_of(cur.key) != class_of(r.key) {
                break;
            }
            if r.cat() > cur.cat() {
                st.by_cat.add(cur.cat(), -1);
                st.by_cat.add(r.cat(), 1);
                cur = r;
            }
            st.duplicates += 1;
            k += 1;
        }
        let mut winners: [Option<Rec>; 4] = [None; 4];
        for idx in std::iter::once(None).chain((k..j).map(Some)) {
            let r = idx.map_or(cur, |x| Rec::of(t.raw[x]));
            if idx.is_some() {
                st.count += 1;
                st.by_cat.add(r.cat(), 1);
            }
            let c = class_of(r.key);
            if r.marker() {
                if winners[c].is_none() {
                    live_keyed.insert(r.seq());
                }
            } else if winners[c].is_none() {
                winners[c] = Some(r);
            }
        }
        // 依鍵的低位元（旗標）順序寫回，維持整體排序；寫入位置 w ≤ i，不會蓋到還沒讀的資料
        for low in 0..4u64 {
            if let Some(r) = winners[class_of(low)] {
                t.raw[w] = [r.key, r.aux];
                w += 1;
            }
        }
        i = j;
    }
    t.raw.truncate(w);

    // 4. 產生緊湊結構：meta / 文字另外配置；鍵直接在原本的緩衝區裡往前搬（第 i 個鍵寫到 u64 位置 i，
    //    讀的是位置 2i，不會蓋到還沒讀的資料），再縮小配置，尖峰只有原本的緩衝區 + meta
    let meta: Box<[u8]> = t.raw.iter().map(|r| Rec::of(*r).meta()).collect();
    let texts: Box<[Box<str>]> = if is_custom {
        t.raw
            .iter()
            .map(|r| std::mem::take(&mut t.texts[Rec::of(*r).seq() as usize]))
            .collect()
    } else {
        Box::new([])
    };
    let m = t.raw.len();
    let mut flat = t.raw.into_flattened();
    for i in 0..m {
        flat[i] = flat[2 * i];
    }
    flat.truncate(m);
    flat.shrink_to_fit();
    let keys = flat.into_boxed_slice();
    let keyed: Box<[KeyedRule]> = t
        .keyed
        .into_iter()
        .filter(|(seq, _)| live_keyed.contains(seq))
        .map(|(_, k)| k)
        .collect();
    for p in &t.patterns {
        st.count += 1;
        st.by_cat.add(Category::from_bits(p.meta >> 6), 1);
    }
    let patterns = t.patterns.into_boxed_slice();
    let (by_tri, always) = crate::filter::pattern_index(&patterns);
    (
        TierData {
            keys,
            meta,
            texts,
            keyed,
            patterns,
            by_tri,
            always,
        },
        st,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections() {
        assert_eq!(section("! @begin 遙測"), Some((false, "遙測")));
        assert_eq!(section("  # @BEGIN malware x"), Some((false, "malware")));
        assert_eq!(section("!@end"), Some((true, "")));
        assert_eq!(section("! @beginning"), None);
        assert_eq!(section("#   ! @begin 廣告"), None);
        assert_eq!(section_cat("ADS"), Category::Ads);
        assert_eq!(section_cat("x"), Category::Custom);
    }
}
