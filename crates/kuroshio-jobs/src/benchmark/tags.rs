//! 評測名單的標記（3.5.0，規格 11 的 A1）
//!
//! 名單檔每一筆可以帶「整理名單時的資料」，兩種寫法：
//!
//! - **行內**（`dohlist.txt`、`dotlist.txt`、`doqlist.txt`、`protected.txt`）：`#` 之後以空白分開的 `key=value`，
//!   例如 `https://dns.example.com/dns-query  # tier=A op=Example_Net ms=3.1 ecs=1`。不認識的 key 忽略。
//! - **上一行**（`iplist.txt`：同一行不能加註解）：緊接在位址前一行的註解，第一個欄位是 `A`／`B` 就是分級，
//!   後面是經營者（截到第一個括號前），另外認得 `<數字> ms` 與 `ECS`。
//!
//! 分段行 `# ---- A 級 ----`／`# ---- B 級 ----` 設定「目前的預設分級」，沒有自己分級的那幾筆用它。
//!
//! 標記只是起點與排序依據：**不能讓有標記的候選跳過任何檢查**（資格賽、汙染、封殺、憑證）；
//! `ms` 是整理名單那天、那條線路量的，不是今天的延遲。

/// 分級
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tier {
    /// 經營者明確
    A,
    /// 品質都過、經營者看不出來
    B,
    /// 使用者自己加的（沒有標記）：分級評測不會把它排除
    User,
    /// 都沒有標記：當成 B
    #[default]
    Unknown,
}

impl Tier {
    /// 輸出用的名稱（`upstreams.json` 的 `tier`、報表）
    pub fn name(self) -> &'static str {
        match self {
            Tier::A => "A",
            Tier::B | Tier::Unknown => "B",
            Tier::User => "user",
        }
    }

    fn parse(s: &str) -> Option<Tier> {
        match s.trim() {
            "A" | "a" => Some(Tier::A),
            "B" | "b" => Some(Tier::B),
            "user" | "User" => Some(Tier::User),
            _ => None,
        }
    }
}

/// 經營者名稱最長幾個位元組（超過截斷：使用者名單裡一行很長的註解不會吃記憶體）
pub const MAX_OP: usize = 64;
/// 預期會擋的類型最長幾個位元組
const MAX_FILTER: usize = 64;

/// 一筆名單的標記
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Tag {
    pub tier: Tier,
    /// 經營者（AS 名稱）
    pub op: String,
    /// 整理名單時量到的延遲：只當沒有歷史時的排序依據
    pub ms: Option<f32>,
    pub ecs: bool,
    /// 國家級電信商自己的伺服器
    pub carrier: bool,
    /// 對照組預期會擋的類型（`filter=ads,adult`）
    pub filter: Option<String>,
    /// 對照組（`protected.txt`）
    pub protected: bool,
}

impl Tag {
    /// 有沒有任何標記（使用者名單裡沒寫標記的，改用預設名單同一筆的標記）
    pub fn is_bare(&self) -> bool {
        self.tier == Tier::Unknown && self.op.is_empty() && self.ms.is_none() && !self.ecs && !self.carrier && self.filter.is_none()
    }
}

/// 截到 `max` 位元組以內（不切斷字元）
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn truthy(v: &str) -> bool {
    matches!(v, "1" | "true" | "yes" | "y" | "Y")
}

/// 行內標記：`#` 之後的 `key=value`
fn parse_inline(comment: &str, tag: &mut Tag) {
    for kv in comment.split_whitespace() {
        let Some((k, v)) = kv.split_once('=') else { continue };
        match k {
            "tier" => {
                if let Some(t) = Tier::parse(v) {
                    tag.tier = t;
                }
            }
            "op" => tag.op = truncate(v, MAX_OP),
            "ms" => tag.ms = v.parse::<f32>().ok().filter(|x| x.is_finite() && *x >= 0.0),
            "ecs" => tag.ecs = truthy(v),
            "carrier" => tag.carrier = truthy(v),
            "filter" if !v.is_empty() => tag.filter = Some(truncate(v, MAX_FILTER)),
            "protected" => tag.protected = truthy(v),
            _ => {}
        }
    }
}

/// 上一行標記（`iplist.txt`）：`A <經營者>（AS…）… 3.9 ms ECS`。第一個欄位不是 A／B 就不是標記
fn parse_previous(comment: &str) -> Option<Tag> {
    let text = comment.trim();
    let (first, rest) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
    let tier = match first {
        "A" => Tier::A,
        "B" => Tier::B,
        _ => return None,
    };
    let rest = rest.trim_start();
    // 經營者截到第一個括號前：AS 名稱本身可能有半形括號（`Alibaba_(US)_Technology_Co.（AS45102）`），
    // 所以有全形括號就用全形的，沒有才看半形的
    let cut = rest.find('（').or_else(|| rest.find('(')).unwrap_or(rest.len());
    let op = rest[..cut].split_whitespace().next().unwrap_or("");
    let words: Vec<&str> = rest.split_whitespace().collect();
    let ms = words
        .windows(2)
        .find(|w| w[1] == "ms")
        .and_then(|w| w[0].parse::<f32>().ok())
        .filter(|x| x.is_finite() && *x >= 0.0);
    Some(Tag {
        tier,
        op: truncate(op, MAX_OP),
        ms,
        ecs: words.contains(&"ECS"),
        ..Default::default()
    })
}

/// 分段行 `---- A 級 ----`
fn parse_section(comment: &str) -> Option<Tier> {
    let t = comment.trim();
    if !t.starts_with("----") {
        return None;
    }
    let inner = t.trim_matches(|c: char| c == '-' || c.is_whitespace());
    let (first, rest) = inner.split_once(char::is_whitespace).unwrap_or((inner, ""));
    if !rest.trim().starts_with('級') && !rest.trim().is_empty() {
        return None;
    }
    Tier::parse(first)
}

/// 一行裡行內註解的開頭：`#` 前面是空白（網址本身不會有「空白 + #」）
fn split_inline(line: &str) -> (&str, Option<&str>) {
    let b = line.as_bytes();
    for i in 1..b.len() {
        if b[i] == b'#' && b[i - 1].is_ascii_whitespace() {
            return (line[..i].trim_end(), Some(&line[i + 1..]));
        }
    }
    (line, None)
}

/// 解析名單檔：每一筆（去掉行內註解的內容）與它的標記。去 BOM、去空行；整行 `#` 或 `//` 開頭是註解
/// （跟 [`crate::util::parse_list`] 一樣的那幾行才算一筆）。沒有任何標記的是 [`Tier::Unknown`]
pub fn parse_tagged(text: &str) -> Vec<(String, Tag)> {
    let mut out = Vec::new();
    let mut section: Option<Tier> = None;
    let mut prev: Option<Tag> = None;
    for raw in text.strip_prefix('\u{feff}').unwrap_or(text).split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw).trim();
        if line.is_empty() {
            prev = None;
            continue;
        }
        if let Some(c) = line.strip_prefix('#') {
            if let Some(t) = parse_section(c) {
                section = Some(t);
                prev = None;
            } else {
                prev = parse_previous(c);
            }
            continue;
        }
        if line.starts_with("//") {
            prev = None;
            continue;
        }
        let (entry, inline) = split_inline(line);
        let mut tag = prev.take().unwrap_or_default();
        if let Some(c) = inline {
            parse_inline(c, &mut tag);
        }
        if tag.tier == Tier::Unknown {
            if let Some(s) = section {
                tag.tier = s;
            }
        }
        out.push((entry.to_string(), tag));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_tags_parsed() {
        let l =
            parse_tagged("https://dns.example.com/dns-query  # tier=A op=Example_Net ms=3.1 ecs=1 carrier=1 src=x checked=2026-11-22\n");
        assert_eq!(l.len(), 1);
        let (id, t) = &l[0];
        assert_eq!(id, "https://dns.example.com/dns-query");
        assert_eq!(t.tier, Tier::A);
        assert_eq!(t.op, "Example_Net");
        assert_eq!(t.ms, Some(3.1));
        assert!(t.ecs && t.carrier && !t.protected);
        assert_eq!(t.filter, None);
        // 對照組的 filter=
        let l = parse_tagged("tls://dns.example.net  # filter=ads,adult 依據：說明 checked=2026-11-22");
        assert_eq!(l[0].0, "tls://dns.example.net");
        assert_eq!(l[0].1.filter.as_deref(), Some("ads,adult"));
        assert_eq!(l[0].1.tier, Tier::Unknown);
    }

    #[test]
    fn iplist_previous_line_and_section_tags() {
        let text = "\u{feff}# 檔頭說明\n# 共 3 筆：A 1、B 2\n\n# ---- A 級 ----\n\
            # A Example_Net（AS64500）TW dns.example.com 3.9 ms\r\n192.0.2.1\n\
            198.51.100.1\n\n# ---- B 級 ----\n\
            # B Alibaba_(US)_Technology_Co.（AS64501）CN dns.example.net 26.2 ms ECS\n198.51.100.2\n\
            2001:db8::53\n\
            # 一般說明，不是標記\n192.0.2.9\n";
        let l = parse_tagged(text);
        let ids: Vec<&str> = l.iter().map(|(i, _)| i.as_str()).collect();
        assert_eq!(ids, ["192.0.2.1", "198.51.100.1", "198.51.100.2", "2001:db8::53", "192.0.2.9"]);
        assert_eq!(l[0].1.tier, Tier::A);
        assert_eq!(l[0].1.op, "Example_Net");
        assert_eq!(l[0].1.ms, Some(3.9));
        assert!(!l[0].1.ecs);
        // 沒有上一行註解：用分段的分級
        assert_eq!(
            l[1].1,
            Tag {
                tier: Tier::A,
                ..Default::default()
            }
        );
        // 經營者本身有半形括號：截到全形括號前
        assert_eq!(l[2].1.tier, Tier::B);
        assert_eq!(l[2].1.op, "Alibaba_(US)_Technology_Co.");
        assert!(l[2].1.ecs);
        assert_eq!(l[2].1.ms, Some(26.2));
        assert_eq!(l[3].1.tier, Tier::B);
        // 上一行是一般註解：沒有標記，分級照分段
        assert_eq!(l[4].1.tier, Tier::B);
        assert!(l[4].1.op.is_empty());
    }

    #[test]
    fn previous_line_tag_needs_adjacent_comment() {
        // 中間隔了空行：上一行的註解不算這一筆的
        let l = parse_tagged("# A Example_Net（AS64500）\n\n192.0.2.1\n// 舊格式的註解\n192.0.2.2\n");
        assert_eq!(l[0].1.tier, Tier::Unknown);
        assert_eq!(l[1].1.tier, Tier::Unknown);
        // 沒有任何標記的舊格式：照常讀，跟 parse_list 同樣的那幾行
        let old = "a.example.com\r\n# x\r\n  b.example.com  \n// y\n\n";
        let l: Vec<String> = parse_tagged(old).into_iter().map(|(i, _)| i).collect();
        assert_eq!(l, crate::util::parse_list(old));
    }

    #[test]
    fn unknown_keys_ignored_and_op_truncated() {
        let long = "x".repeat(200);
        let l = parse_tagged(&format!(
            "https://dns.example.com/dns-query # future=1 tier=Z op={long} ms=abc ecs=0 foo\n# A {}（AS1）\n192.0.2.1\n",
            "營".repeat(40)
        ));
        let t = &l[0].1;
        assert_eq!(t.tier, Tier::Unknown, "不認識的分級忽略");
        assert_eq!(t.op.len(), MAX_OP);
        assert_eq!(t.ms, None);
        assert!(!t.ecs);
        // 多位元組字元不切斷
        let op = &l[1].1.op;
        assert!(op.len() <= MAX_OP && op.chars().all(|c| c == '營'), "{op}");
        assert!(!op.is_empty());
    }

    #[test]
    fn tier_names() {
        assert_eq!(Tier::A.name(), "A");
        assert_eq!(Tier::Unknown.name(), "B");
        assert_eq!(Tier::User.name(), "user");
        assert!(Tag::default().is_bare());
        assert!(!Tag {
            tier: Tier::A,
            ..Default::default()
        }
        .is_bare());
    }
}
