//! 建好的過濾器（不可變；整合端用 `Arc<Filter>` 整份替換）與比對。

use std::borrow::Cow;
use std::cell::OnceCell;

use crate::parse::DnsType;
use crate::regex::Regex;
use crate::{fnv_step, js, qtype_name, Action, Category, FilterStats, MatchKind, TierKind, FNV_OFFSET};

/// 鍵的低 3 位元旗標
pub(crate) const F_IMPORTANT: u64 = 1;
pub(crate) const F_ALLOW: u64 = 2;
pub(crate) const F_EXACT: u64 = 4;
pub(crate) const FLAGS: u64 = 7;

/// meta 位元組：高 2 位元分類、低 6 位元清單編號
pub(crate) fn meta_of(cat: Category, list: u8) -> u8 {
    ((cat as u8) << 6) | (list & 63)
}
fn meta_cat(m: u8) -> Category {
    Category::from_bits(m >> 6)
}
fn meta_list(m: u8) -> usize {
    usize::from(m & 63)
}

/// 優先等級：0 = `@@$important`、1 = `$important`、2 = `@@`、3 = 封鎖
pub(crate) fn class_of(key: u64) -> usize {
    match (key & F_ALLOW != 0, key & F_IMPORTANT != 0) {
        (true, true) => 0,
        (false, true) => 1,
        (true, false) => 2,
        (false, false) => 3,
    }
}

/// 有 `$dnstype` 的網域規則（數量少，線性比對）
#[derive(Debug)]
pub(crate) struct KeyedRule {
    /// 完整鍵（含旗標）
    pub key: u64,
    pub dnstype: DnsType,
    pub meta: u8,
    pub text: Box<str>,
}

/// 正規表示式 / 萬用字元規則
#[derive(Debug)]
pub(crate) struct PatternRule {
    pub re: Regex,
    pub lit: Option<Box<str>>,
    /// lit 第一個與最後一個三字元組的雜湊（快速排除用）
    pub tri: Option<(u16, u16)>,
    pub allow: bool,
    pub important: bool,
    pub dnstype: Option<Box<DnsType>>,
    pub meta: u8,
    pub text: Box<str>,
}

/// 三字元組雜湊（12 位元）
fn trigram(b: &[u8]) -> u16 {
    let v = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
    (v.wrapping_mul(0x9e37_79b1) >> 20) as u16
}

/// lit 的快速排除鍵
pub(crate) fn lit_trigrams(lit: &str) -> Option<(u16, u16)> {
    let b = lit.as_bytes();
    (b.len() >= 3).then(|| (trigram(&b[..3]), trigram(&b[b.len() - 3..])))
}

/// 查詢名稱所有三字元組的位元集合（4096 位元）
fn name_trigrams(name: &str) -> [u64; 64] {
    let mut set = [0u64; 64];
    for w in name.as_bytes().windows(3) {
        let h = trigram(w);
        set[usize::from(h >> 6)] |= 1 << (h & 63);
    }
    set
}

impl PatternRule {
    fn flags(&self) -> u64 {
        (if self.allow { F_ALLOW } else { 0 }) | (if self.important { F_IMPORTANT } else { 0 })
    }
}

/// 一層規則
#[derive(Debug, Default)]
pub(crate) struct TierData {
    /// 排序過的鍵（雜湊 & !7 | 旗標）
    pub keys: Box<[u64]>,
    /// 跟 keys 平行：分類 / 清單編號
    pub meta: Box<[u8]>,
    /// 自訂層才有：跟 keys 平行的原始規則文字
    pub texts: Box<[Box<str>]>,
    pub keyed: Box<[KeyedRule]>,
    pub patterns: Box<[PatternRule]>,
    /// 複雜規則的索引：（固定字串開頭三個字元的雜湊，規則編號），依雜湊排序。
    /// 查詢時只看「名稱裡有出現那個雜湊」的規則，不必每個查詢把幾千條規則全部掃一遍
    pub by_tri: TriIndex,
    /// 沒有固定字串可以先篩的規則（每個查詢都要比對），依編號排序
    pub always: Box<[u32]>,
}

/// （三字元雜湊，規則編號），依雜湊排序
pub(crate) type TriIndex = Box<[(u16, u32)]>;

/// 建立複雜規則的索引（見 `TierData::by_tri` / `always`）
pub(crate) fn pattern_index(patterns: &[PatternRule]) -> (TriIndex, Box<[u32]>) {
    let mut by_tri = Vec::new();
    let mut always = Vec::new();
    for (i, p) in patterns.iter().enumerate() {
        match (&p.lit, p.tri) {
            (Some(_), Some((a, _))) => by_tri.push((a, i as u32)),
            _ => always.push(i as u32),
        }
    }
    by_tri.sort_unstable();
    (by_tri.into_boxed_slice(), always.into_boxed_slice())
}

#[derive(Clone, Copy)]
enum Src {
    Hashed(usize),
    Keyed(usize),
    Pattern(usize),
}

#[derive(Clone, Copy)]
struct Hit {
    src: Src,
    /// 命中的網域在查詢名稱裡的起點（Pattern 不用）
    start: usize,
    exact: bool,
}

/// 比對時共用的查詢資訊（依需要才計算）
struct Query<'q> {
    name: &'q str,
    /// (起點, 雜湊)，由長到短
    levels: &'q [(usize, u64)],
    qtype: u16,
    qtype_name: OnceCell<Cow<'static, str>>,
    chars: OnceCell<Vec<char>>,
    trigrams: OnceCell<[u64; 64]>,
}

impl Query<'_> {
    fn qtype_matches(&self, d: &DnsType) -> bool {
        d.matches(self.qtype_name.get_or_init(|| qtype_name(self.qtype)))
    }
}

impl TierData {
    fn find(&self, q: &Query<'_>) -> Option<Hit> {
        let mut hits: [Option<Hit>; 4] = [None; 4];
        let consider = |hits: &mut [Option<Hit>; 4], class: usize, hit: Hit| {
            if hits[class].is_none() {
                hits[class] = Some(hit);
            }
        };
        for (li, &(start, h)) in q.levels.iter().enumerate() {
            let base = h & !FLAGS;
            for exact in [true, false] {
                // 精確規則只比對完整名稱
                if exact && li != 0 {
                    continue;
                }
                let kind = if exact { F_EXACT } else { 0 };
                // 有 $dnstype 的規則（只保留排在同等級一般規則之前的，見 builder）
                for (ki, k) in self.keyed.iter().enumerate() {
                    if k.key & !(F_ALLOW | F_IMPORTANT) == base | kind && q.qtype_matches(&k.dnstype) {
                        consider(
                            &mut hits,
                            class_of(k.key),
                            Hit {
                                src: Src::Keyed(ki),
                                start,
                                exact,
                            },
                        );
                    }
                }
                let mut i = self.keys.partition_point(|&k| k < base);
                while let Some(&k) = self.keys.get(i) {
                    if k & !FLAGS != base {
                        break;
                    }
                    if k & F_EXACT == kind {
                        consider(
                            &mut hits,
                            class_of(k),
                            Hit {
                                src: Src::Hashed(i),
                                start,
                                exact,
                            },
                        );
                    }
                    i += 1;
                }
            }
            if hits[0].is_some() {
                return hits[0];
            }
        }
        if self.patterns.is_empty() {
            return hits.into_iter().flatten().next();
        }
        // 候選：沒有固定字串的規則，加上「固定字串開頭的三字元雜湊有出現在名稱裡」的規則；
        // 依編號排序後照原本的順序比對，結果跟全部掃一遍相同
        let mut cand: Vec<u32> = self.always.to_vec();
        if !self.by_tri.is_empty() {
            let set = q.trigrams.get_or_init(|| name_trigrams(q.name));
            for (wi, word) in set.iter().enumerate() {
                let mut w = *word;
                while w != 0 {
                    let h = (wi as u16) << 6 | w.trailing_zeros() as u16;
                    w &= w - 1;
                    let i = self.by_tri.partition_point(|x| x.0 < h);
                    cand.extend(self.by_tri[i..].iter().take_while(|x| x.0 == h).map(|x| x.1));
                }
            }
            if cand.len() > self.always.len() {
                cand.sort_unstable();
            }
        }
        for pi in cand.into_iter().map(|i| i as usize) {
            let p = &self.patterns[pi];
            let class = class_of(p.flags());
            // 已經有同等級或更高等級的命中時，這條不會改變結果
            if hits[..=class].iter().any(Option::is_some) {
                continue;
            }
            if let Some(lit) = &p.lit {
                if let Some((a, b)) = p.tri {
                    let set = q.trigrams.get_or_init(|| name_trigrams(q.name));
                    let has = |h: u16| set[usize::from(h >> 6)] & (1 << (h & 63)) != 0;
                    if !has(a) || !has(b) {
                        continue;
                    }
                }
                if !q.name.contains(&**lit) {
                    continue;
                }
            }
            if let Some(d) = &p.dnstype {
                if !q.qtype_matches(d) {
                    continue;
                }
            }
            if p.re.is_match(q.chars.get_or_init(|| q.name.chars().collect())) {
                consider(
                    &mut hits,
                    class,
                    Hit {
                        src: Src::Pattern(pi),
                        start: 0,
                        exact: false,
                    },
                );
            }
        }
        hits.into_iter().flatten().next()
    }

    fn heap_bytes(&self) -> usize {
        use std::mem::size_of;
        self.keys.len() * size_of::<u64>()
            + self.meta.len()
            + self.texts.len() * size_of::<Box<str>>()
            + self.texts.iter().map(|t| t.len()).sum::<usize>()
            + self.keyed.len() * size_of::<KeyedRule>()
            + self.keyed.iter().map(|k| k.text.len() + k.dnstype.heap_bytes()).sum::<usize>()
            + self.patterns.len() * size_of::<PatternRule>()
            + self.by_tri.len() * size_of::<(u16, u32)>()
            + self.always.len() * size_of::<u32>()
            + self
                .patterns
                .iter()
                .map(|p| {
                    p.text.len()
                        + p.lit.as_ref().map_or(0, |l| l.len())
                        + p.re.heap_bytes()
                        + p.dnstype.as_ref().map_or(0, |d| std::mem::size_of::<DnsType>() + d.heap_bytes())
                })
                .sum::<usize>()
    }
}

/// 判定結果（沒有命中時 [`Filter::check`] 回傳 None，即 node 版的 `action: 'none'`）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict<'f> {
    pub action: Action,
    pub tier: TierKind,
    pub category: Category,
    /// 清單層：來源在 [`FilterStats::sources`] 裡的索引；自訂層為 None
    pub list: Option<usize>,
    pub kind: MatchKind,
    pub important: bool,
    /// 命中的網域（查詢名稱本身或它的上層網域）；正規表示式 / 萬用字元為 None
    pub domain: Option<String>,
    text: Option<&'f str>,
}

impl<'f> Verdict<'f> {
    pub fn is_block(&self) -> bool {
        self.action == Action::Block
    }
    pub fn is_allow(&self) -> bool {
        self.action == Action::Allow
    }

    /// 命中的規則文字（同 node 版 `rule`）。自訂規則與複雜規則是原始行；
    /// 清單層的網域規則只存雜湊，由命中的網域還原成 `||domain^` / `|domain^`（加上 `@@`、`$important`）。
    pub fn rule(&self) -> Cow<'f, str> {
        match self.text {
            Some(t) => Cow::Borrowed(t),
            None => Cow::Owned(format!(
                "{}{}{}^{}",
                if self.is_allow() { "@@" } else { "" },
                if self.kind == MatchKind::Exact { "|" } else { "||" },
                self.domain.as_deref().unwrap_or(""),
                if self.important { "$important" } else { "" }
            )),
        }
    }
}

/// 過濾器。用 [`crate::FilterBuilder`] 建立。
#[derive(Debug, Default)]
pub struct Filter {
    pub(crate) custom: TierData,
    pub(crate) lists: TierData,
    /// 清單編號 → 來源索引
    pub(crate) list_sources: Vec<usize>,
    pub(crate) stats: FilterStats,
}

/// 查詢名稱正規化：轉小寫、去掉一個結尾的點（同 node 版 `check`）
fn normalize(name: &str) -> Cow<'_, str> {
    match js::lower(name) {
        Cow::Borrowed(s) => Cow::Borrowed(s.strip_suffix('.').unwrap_or(s)),
        Cow::Owned(mut s) => {
            if s.ends_with('.') {
                s.pop();
            }
            Cow::Owned(s)
        }
    }
}

impl Filter {
    /// 沒有任何規則的過濾器
    pub fn empty() -> Filter {
        Filter::default()
    }

    /// 判定查詢（同 node 版 `check(name, qtype)`）。`qtype` 是 DNS 類型數值，只有 `$dnstype` 規則會用到。
    /// 回傳 None 表示不處理（node 版 `action: 'none'`）。
    pub fn check(&self, name: &str, qtype: u16) -> Option<Verdict<'_>> {
        let norm = normalize(name);
        let b = norm.as_bytes();
        // 每一層上層網域的雜湊（由右往左一次算完），整理成由長到短
        let mut buf = [(0usize, 0u64); 64];
        let mut heap = Vec::new();
        let mut n = 0;
        let mut h = FNV_OFFSET;
        for i in (0..b.len()).rev() {
            h = fnv_step(h, b[i]);
            if i == 0 || b[i - 1] == b'.' {
                if n < buf.len() {
                    buf[n] = (i, h);
                } else {
                    if heap.is_empty() {
                        heap.extend_from_slice(&buf);
                    }
                    heap.push((i, h));
                }
                n += 1;
            }
        }
        let levels: &mut [(usize, u64)] = if heap.is_empty() { &mut buf[..n] } else { &mut heap[..] };
        levels.reverse();
        let q = Query {
            name: &norm,
            levels,
            qtype,
            qtype_name: OnceCell::new(),
            chars: OnceCell::new(),
            trigrams: OnceCell::new(),
        };

        for (tier, data) in [(TierKind::Custom, &self.custom), (TierKind::Lists, &self.lists)] {
            let Some(hit) = data.find(&q) else { continue };
            let (key_flags, meta, text) = match hit.src {
                Src::Hashed(i) => (data.keys[i], data.meta[i], data.texts.get(i).map(|t| &**t)),
                Src::Keyed(i) => {
                    let k = &data.keyed[i];
                    (k.key, k.meta, Some(&*k.text))
                }
                Src::Pattern(i) => {
                    let p = &data.patterns[i];
                    (p.flags(), p.meta, Some(&*p.text))
                }
            };
            let pattern = matches!(hit.src, Src::Pattern(_));
            return Some(Verdict {
                action: if key_flags & F_ALLOW != 0 { Action::Allow } else { Action::Block },
                tier,
                category: meta_cat(meta),
                list: match tier {
                    TierKind::Custom => None,
                    TierKind::Lists => self.list_sources.get(meta_list(meta)).copied(),
                },
                kind: if pattern {
                    MatchKind::Pattern
                } else if hit.exact {
                    MatchKind::Exact
                } else {
                    MatchKind::Suffix
                },
                important: key_flags & F_IMPORTANT != 0,
                domain: (!pattern).then(|| norm[hit.start..].to_owned()),
                text,
            });
        }
        None
    }

    /// CNAME 鏈過濾（同 node 版 resolver `_store`）：查詢名稱本身沒有被放行時，
    /// 依序檢查回應裡的 CNAME 目標，第一個被封鎖的就回傳它的判定（整個回應要改成攔截回應）。
    /// 查詢名稱本身被封鎖的情況，呼叫端在查上游之前就該用 [`Filter::check`] 處理掉。
    pub fn check_cname<'a, I>(&self, qname: &str, targets: I, qtype: u16) -> Option<Verdict<'_>>
    where
        I: IntoIterator<Item = &'a str>,
    {
        if self.check(qname, qtype).is_some_and(|v| v.is_allow()) {
            return None;
        }
        targets.into_iter().find_map(|t| self.check(t, qtype).filter(Verdict::is_block))
    }

    pub fn stats(&self) -> &FilterStats {
        &self.stats
    }

    /// 雜湊結構裡的網域筆數（兩層合計）
    pub fn domain_count(&self) -> usize {
        self.custom.keys.len() + self.lists.keys.len()
    }

    /// 估計佔用的記憶體（bytes）：雜湊陣列、分類、複雜規則（含正規表示式節點）與文字、統計
    pub fn memory_bytes(&self) -> usize {
        std::mem::size_of::<Filter>()
            + self.custom.heap_bytes()
            + self.lists.heap_bytes()
            + self.list_sources.capacity() * std::mem::size_of::<usize>()
            + self.stats.sources.capacity() * std::mem::size_of::<crate::SourceStats>()
            + self.stats.sources.iter().map(|s| s.name.capacity()).sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use crate::{BuildOptions, Category, FilterBuilder, ListSpec};

    /// 複雜規則用索引挑候選，結果要跟「每一條都掃」完全一樣（命中哪一條、動作、優先順序）
    #[test]
    fn pattern_index_matches_full_scan() {
        let mut rules = String::new();
        for i in 0..300 {
            rules.push_str(&format!("||ad{i}*.track.test^\n"));
            rules.push_str(&format!("/banner{}[0-9]+\\.example\\./\n", i % 7));
            if i % 5 == 0 {
                rules.push_str(&format!("@@||ad{i}*.track.test^\n"));
            }
            if i % 11 == 0 {
                rules.push_str(&format!("||ad{i}x*.track.test^$important\n"));
            }
            if i % 13 == 0 {
                rules.push_str(&format!("@@/^w{i}\\.(a|b)\\.test$/$important\n"));
                rules.push_str("/^(a|b)[0-9]+\\.nolit\\./\n");
            }
        }
        rules.push_str("||*.wild.example^\n/^x.z$/\n");
        let build = || {
            let mut b = FilterBuilder::new(BuildOptions::default());
            b.add_custom(b"/^custom[0-9]\\.test$/\n@@||ok*.track.test^\n");
            b.add_list(ListSpec::new("L", Category::Ads), rules.as_bytes()).unwrap();
            b.finish()
        };
        let indexed = build();
        let mut full = build();
        assert!(indexed.lists.patterns.len() > 600 && !indexed.lists.by_tri.is_empty() && !indexed.lists.always.is_empty());
        for t in [&mut full.custom, &mut full.lists] {
            t.by_tri = Box::new([]);
            t.always = (0..t.patterns.len() as u32).collect();
        }
        let mut names: Vec<String> = Vec::new();
        for i in 0..320 {
            names.push(format!("ad{i}.track.test"));
            names.push(format!("ad{i}x9.track.test"));
            names.push(format!("ad{i}foo.sub.track.test"));
            names.push(format!("banner{}77.example.com", i % 9));
            names.push(format!("w{i}.a.test"));
            names.push(format!("a{i}.nolit.example"));
            names.push(format!("ok{i}.track.test"));
        }
        for n in [
            "a.wild.example",
            "xyz",
            "custom5.test",
            "plain.example",
            "",
            "a",
            "ab",
            "track.test",
            "AD3.Track.Test.",
        ] {
            names.push(n.to_string());
        }
        let mut some = 0;
        for n in &names {
            for qtype in [1u16, 28] {
                let (a, b) = (indexed.check(n, qtype), full.check(n, qtype));
                assert_eq!(a, b, "{n}");
                assert_eq!(a.as_ref().map(|v| v.rule()), b.as_ref().map(|v| v.rule()), "{n}");
                some += a.is_some() as usize;
            }
        }
        assert!(some > 500, "{some}");
    }
}
