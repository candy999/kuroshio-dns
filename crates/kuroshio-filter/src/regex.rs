//! 極簡正規表示式引擎：JavaScript 語法（非 unicode 模式、含 Annex B 寬鬆語法）的子集，
//! 一律不分大小寫（等同 node 版的 `new RegExp(src, 'i')`），回溯式比對。
//!
//! 支援：字元、`.`、字元類別 `[...]` / `[^...]`（含範圍與 `\d \w \s`）、`\d \D \w \W \s \S \b \B`、
//! `^ $`、群組 `( )` `(?: )` `(?<name> )`、前瞻 `(?= )` `(?! )`、後顧 `(?<= )` `(?<! )`、選擇 `|`、
//! 量詞 `* + ? {n} {n,} {n,m}` 與非貪婪版本、`\t \n \r \v \f \0 \cX \xHH \uHHHH`。
//!
//! 不支援（規則算「不支援」略過並計數）：反向參照 `\1` / `\k<name>`、舊式八進位跳脫 `\012`。語法錯誤（node 版 `new RegExp` 會丟例外的情況）則跟 node 版一樣整條忽略。
//!
//! 回溯有步數上限（[`STEP_LIMIT`]），超過就當作沒命中，避免惡意規則拖垮 DNS。

use std::cell::Cell;

/// 每次比對最多走幾步（所有起點合計）
pub(crate) const STEP_LIMIT: u32 = 100_000;

/// 群組最多巢狀幾層。解析是遞迴的：清單裡一行幾萬個 `(` 會把堆疊用完、整個程式當掉，
/// 超過就當成「不支援」略過（實際的規則不會超過十層）
const MAX_NEST: u32 = 200;

/// 比對時最多遞迴幾層。回溯是遞迴的，`(?:a?){60000}` 這種「不吃字元也能一直重複」的樣式
/// 在步數用完之前就會把堆疊用完；超過就當作沒命中（跟步數上限同樣的處理）。
/// 253 個字元的網域名稱，一般的樣式每個字元大約兩層，用不到這個數字的一半。
const MAX_DEPTH: u32 = 1200;

/// 比對時最多用掉多少堆疊。每層遞迴實際占多少位元組依編譯模式與 CPU 而不同
/// （除錯版大好幾倍），只靠層數上限不保險；這裡直接量堆疊位址的差距。
/// 執行緒堆疊是 2 MiB（Rust / tokio 預設）：正式版給 512 KiB（最長的網域名稱配一般樣式用不到一半），
/// 除錯版的堆疊框大很多，給 1.5 MiB。
const STACK_BUDGET: usize = if cfg!(debug_assertions) { 1536 * 1024 } else { 512 * 1024 };

/// 目前的堆疊位置（區域變數的位址）
#[inline(always)]
fn stack_pos() -> usize {
    let x = 0u8;
    std::hint::black_box(&x) as *const u8 as usize
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegexError {
    /// node 版也會失敗的語法錯誤
    Syntax,
    /// 合法的 JS 語法，但這個引擎不支援
    Unsupported,
}

#[derive(Debug, Clone)]
pub(crate) struct Regex {
    root: Node,
    anchored: bool,
}

#[derive(Debug, Clone)]
enum Node {
    Empty,
    /// 已正規化（JS Canonicalize：轉大寫）的字元
    Char(char),
    /// 連續的一般字元（已正規化），省記憶體
    Lit(Box<str>),
    Any,
    /// 貪婪的 `.*`（adblock 的 `*`）
    Star,
    /// adblock 的分隔字元 `^`：`(?:$|[^a-z0-9_.%-])`
    Sep,
    Class(Box<Class>),
    Start,
    End,
    WordBoundary(bool),
    Concat(Box<[Node]>),
    Alt(Box<[Node]>),
    Repeat {
        node: Box<Node>,
        min: u32,
        max: u32,
        greedy: bool,
    },
    /// 前瞻 / 後顧（`behind`）
    Look {
        node: Box<Node>,
        negate: bool,
        behind: bool,
    },
}

#[derive(Debug, Clone)]
struct Class {
    negated: bool,
    items: Vec<Item>,
}

#[derive(Debug, Clone, Copy)]
enum Item {
    Range(char, char),
    Digit(bool),
    Word(bool),
    Space(bool),
}

/// JS 非 unicode 模式的 Canonicalize：轉大寫；結果不是單一字元、或非 ASCII 轉成 ASCII 時維持原字元
fn canon(c: char) -> char {
    if c.is_ascii() {
        return c.to_ascii_uppercase();
    }
    let mut it = c.to_uppercase();
    match (it.next(), it.next()) {
        (Some(u), None) if u.is_ascii() => c,
        (Some(u), None) => u,
        _ => c,
    }
}

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn is_line_term(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

impl Item {
    fn matches(self, c: char) -> bool {
        match self {
            Item::Range(lo, hi) => {
                let inr = |x: char| lo <= x && x <= hi;
                if inr(c) {
                    return true;
                }
                // 不分大小寫：大寫或小寫形式落在範圍內就算
                let up = canon(c);
                if inr(up) {
                    return true;
                }
                let mut lw = c.to_lowercase();
                matches!((lw.next(), lw.next()), (Some(l), None) if inr(l))
            }
            Item::Digit(neg) => c.is_ascii_digit() != neg,
            Item::Word(neg) => is_word(c) != neg,
            Item::Space(neg) => crate::js::is_space(c) != neg,
        }
    }
}

impl Class {
    fn matches(&self, c: char) -> bool {
        self.items.iter().any(|i| i.matches(c)) != self.negated
    }
}

impl Node {
    fn heap_bytes(&self) -> usize {
        match self {
            Node::Class(c) => std::mem::size_of::<Class>() + c.items.capacity() * std::mem::size_of::<Item>(),
            Node::Lit(l) => l.len(),
            Node::Concat(v) | Node::Alt(v) => v.len() * std::mem::size_of::<Node>() + v.iter().map(Node::heap_bytes).sum::<usize>(),
            Node::Repeat { node, .. } | Node::Look { node, .. } => std::mem::size_of::<Node>() + node.heap_bytes(),
            _ => 0,
        }
    }
}

// ---------------------------------------------------------------- 解析

struct Parser {
    p: Vec<char>,
    i: usize,
    /// 目前巢狀到第幾層（群組、前瞻、後顧）
    depth: u32,
}

type R<T> = Result<T, RegexError>;

impl Parser {
    fn peek(&self) -> Option<char> {
        self.p.get(self.i).copied()
    }
    fn peek_at(&self, k: usize) -> Option<char> {
        self.p.get(self.i + k).copied()
    }
    fn starts(&self, s: &str) -> bool {
        s.chars().enumerate().all(|(k, c)| self.peek_at(k) == Some(c))
    }

    fn alt(&mut self) -> R<Node> {
        self.depth += 1;
        if self.depth > MAX_NEST {
            return Err(RegexError::Unsupported);
        }
        let r = self.alt_inner();
        self.depth -= 1;
        r
    }

    fn alt_inner(&mut self) -> R<Node> {
        let mut alts = vec![self.concat()?];
        while self.peek() == Some('|') {
            self.i += 1;
            alts.push(self.concat()?);
        }
        Ok(if alts.len() == 1 {
            alts.pop().unwrap_or(Node::Empty)
        } else {
            Node::Alt(alts.into_boxed_slice())
        })
    }

    fn concat(&mut self) -> R<Node> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let (atom, quantifiable) = self.atom()?;
            items.push(self.quantifier(atom, quantifiable)?);
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.pop().unwrap_or(Node::Empty),
            _ => concat(items),
        })
    }

    /// 在目前位置讀 `{n}` / `{n,}` / `{n,m}`；不是合法量詞時回傳 None（Annex B：當成一般字元）
    fn brace(&self) -> Option<(u32, u32, usize)> {
        let mut k = self.i;
        if self.p.get(k) != Some(&'{') {
            return None;
        }
        k += 1;
        let num = |k: &mut usize| -> Option<u32> {
            let st = *k;
            let mut v: u64 = 0;
            while let Some(d) = self.p.get(*k).and_then(|c| c.to_digit(10)) {
                v = (v * 10 + u64::from(d)).min(u64::from(u32::MAX - 1));
                *k += 1;
            }
            (*k > st).then_some(v as u32)
        };
        let min = num(&mut k)?;
        let max = match self.p.get(k) {
            Some('}') => min,
            Some(',') => {
                k += 1;
                if self.p.get(k) == Some(&'}') {
                    u32::MAX
                } else {
                    num(&mut k)?
                }
            }
            _ => return None,
        };
        if self.p.get(k) != Some(&'}') {
            return None;
        }
        Some((min, max, k + 1 - self.i))
    }

    fn quantifier(&mut self, atom: Node, quantifiable: bool) -> R<Node> {
        let (min, max, len) = match self.peek() {
            Some('*') => (0, u32::MAX, 1),
            Some('+') => (1, u32::MAX, 1),
            Some('?') => (0, 1, 1),
            Some('{') => match self.brace() {
                Some(q) => q,
                None => return Ok(atom),
            },
            _ => return Ok(atom),
        };
        if !quantifiable {
            return Err(RegexError::Syntax);
        }
        if min > max {
            return Err(RegexError::Syntax);
        }
        self.i += len;
        let greedy = if self.peek() == Some('?') {
            self.i += 1;
            false
        } else {
            true
        };
        Ok(Node::Repeat {
            node: Box::new(atom),
            min,
            max,
            greedy,
        })
    }

    fn atom(&mut self) -> R<(Node, bool)> {
        let c = self.peek().ok_or(RegexError::Syntax)?;
        self.i += 1;
        Ok(match c {
            '(' => {
                let node = if self.starts("?:") {
                    self.i += 2;
                    self.alt()?
                } else if self.starts("?=") || self.starts("?!") {
                    let negate = self.peek_at(1) == Some('!');
                    self.i += 2;
                    Node::Look {
                        node: Box::new(self.alt()?),
                        negate,
                        behind: false,
                    }
                } else if self.starts("?<=") || self.starts("?<!") {
                    let negate = self.peek_at(2) == Some('!');
                    self.i += 3;
                    let node = Node::Look {
                        node: Box::new(self.alt()?),
                        negate,
                        behind: true,
                    };
                    if self.peek() != Some(')') {
                        return Err(RegexError::Syntax);
                    }
                    self.i += 1;
                    // 後顧不能加量詞
                    return Ok((node, false));
                } else if self.starts("?<") {
                    // 具名群組：名稱只能是識別字
                    self.i += 2;
                    let st = self.i;
                    while let Some(ch) = self.peek() {
                        if ch == '>' {
                            break;
                        }
                        if !(ch.is_alphanumeric() || ch == '_' || ch == '$') {
                            return Err(RegexError::Syntax);
                        }
                        self.i += 1;
                    }
                    if self.peek() != Some('>') || self.i == st {
                        return Err(RegexError::Syntax);
                    }
                    self.i += 1;
                    self.alt()?
                } else if self.peek() == Some('?') {
                    return Err(RegexError::Syntax);
                } else {
                    self.alt()?
                };
                if self.peek() != Some(')') {
                    return Err(RegexError::Syntax);
                }
                self.i += 1;
                (node, true)
            }
            '[' => (Node::Class(Box::new(self.class()?)), true),
            '.' => (Node::Any, true),
            '^' => (Node::Start, false),
            '$' => (Node::End, false),
            '\\' => self.escape()?,
            '*' | '+' | '?' => return Err(RegexError::Syntax),
            '{' => {
                self.i -= 1;
                if self.brace().is_some() {
                    return Err(RegexError::Syntax);
                }
                self.i += 1;
                (Node::Char('{'), true)
            }
            c => (Node::Char(canon(c)), true),
        })
    }

    fn hex(&mut self, n: usize) -> Option<char> {
        let mut v = 0u32;
        for k in 0..n {
            v = v * 16 + self.peek_at(k)?.to_digit(16)?;
        }
        let c = char::from_u32(v)?;
        self.i += n;
        Some(c)
    }

    /// `\` 之後的共通跳脫字元（類別內外都一樣的部分）；回傳 None 表示不是這一類
    fn char_escape(&mut self, c: char, in_class: bool) -> R<Option<char>> {
        Ok(Some(match c {
            't' => '\t',
            'n' => '\n',
            'v' => '\u{0b}',
            'f' => '\u{0c}',
            'r' => '\r',
            '0' => {
                if self.peek().is_some_and(|d| d.is_ascii_digit()) {
                    return Err(RegexError::Unsupported);
                }
                '\0'
            }
            '1'..='9' => return Err(RegexError::Unsupported),
            'k' => return Err(RegexError::Unsupported),
            'c' => match self.peek() {
                Some(l) if l.is_ascii_alphabetic() || (in_class && (l.is_ascii_digit() || l == '_')) => {
                    self.i += 1;
                    char::from_u32(l as u32 % 32).unwrap_or('\0')
                }
                _ => {
                    // Annex B：`\c` 後面不是字母時，`\` 當一般字元，`c` 留給下一個
                    self.i -= 1;
                    '\\'
                }
            },
            'x' => self.hex(2).unwrap_or('x'),
            'u' => {
                if self.peek_at(0).and_then(|c| c.to_digit(16)).is_some()
                    && (0..4).all(|k| self.peek_at(k).is_some_and(|c| c.is_ascii_hexdigit()))
                {
                    // 落在代理字元區的 \uD800 這類，Rust 的 char 無法表示
                    self.hex(4).ok_or(RegexError::Unsupported)?
                } else {
                    'u'
                }
            }
            _ => return Ok(None),
        }))
    }

    fn escape(&mut self) -> R<(Node, bool)> {
        let c = self.peek().ok_or(RegexError::Syntax)?;
        self.i += 1;
        let set = |it: Item| {
            Node::Class(Box::new(Class {
                negated: false,
                items: vec![it],
            }))
        };
        Ok(match c {
            'd' => (set(Item::Digit(false)), true),
            'D' => (set(Item::Digit(true)), true),
            'w' => (set(Item::Word(false)), true),
            'W' => (set(Item::Word(true)), true),
            's' => (set(Item::Space(false)), true),
            'S' => (set(Item::Space(true)), true),
            'b' => (Node::WordBoundary(true), false),
            'B' => (Node::WordBoundary(false), false),
            _ => match self.char_escape(c, false)? {
                Some(ch) => (Node::Char(canon(ch)), true),
                None => (Node::Char(canon(c)), true),
            },
        })
    }

    fn class_atom(&mut self) -> R<Result<char, Item>> {
        let c = self.peek().ok_or(RegexError::Syntax)?;
        self.i += 1;
        if c != '\\' {
            return Ok(Ok(c));
        }
        let e = self.peek().ok_or(RegexError::Syntax)?;
        self.i += 1;
        Ok(match e {
            'd' => Err(Item::Digit(false)),
            'D' => Err(Item::Digit(true)),
            'w' => Err(Item::Word(false)),
            'W' => Err(Item::Word(true)),
            's' => Err(Item::Space(false)),
            'S' => Err(Item::Space(true)),
            'b' => Ok('\u{08}'),
            '-' => Ok('-'),
            _ => Ok(self.char_escape(e, true)?.unwrap_or(e)),
        })
    }

    fn class(&mut self) -> R<Class> {
        let negated = if self.peek() == Some('^') {
            self.i += 1;
            true
        } else {
            false
        };
        let mut items = Vec::new();
        loop {
            match self.peek() {
                None => return Err(RegexError::Syntax),
                Some(']') => {
                    self.i += 1;
                    break;
                }
                _ => {}
            }
            let a = self.class_atom()?;
            if self.peek() == Some('-') && self.peek_at(1).is_some_and(|c| c != ']') {
                self.i += 1;
                let b = self.class_atom()?;
                match (a, b) {
                    (Ok(x), Ok(y)) => {
                        if x > y {
                            return Err(RegexError::Syntax);
                        }
                        items.push(Item::Range(x, y));
                    }
                    (a, b) => {
                        // Annex B：類別跳脫當範圍端點時，`-` 是一般字元
                        for v in [a, Ok('-'), b] {
                            items.push(match v {
                                Ok(ch) => Item::Range(ch, ch),
                                Err(it) => it,
                            });
                        }
                    }
                }
            } else {
                items.push(match a {
                    Ok(ch) => Item::Range(ch, ch),
                    Err(it) => it,
                });
            }
        }
        Ok(Class { negated, items })
    }
}

/// 串接：連續的一般字元合併成一個 `Lit`
fn concat(items: Vec<Node>) -> Node {
    let mut out: Vec<Node> = Vec::with_capacity(items.len());
    let mut run = String::new();
    let flush = |out: &mut Vec<Node>, run: &mut String| {
        let mut cs = run.chars();
        match (cs.next(), cs.next()) {
            (None, _) => {}
            (Some(c), None) => out.push(Node::Char(c)),
            _ => out.push(Node::Lit(run.as_str().into())),
        }
        run.clear();
    };
    for n in items {
        match n {
            Node::Char(c) => run.push(c),
            n => {
                flush(&mut out, &mut run);
                out.push(n);
            }
        }
    }
    flush(&mut out, &mut run);
    match out.len() {
        0 => Node::Empty,
        1 => out.pop().unwrap_or(Node::Empty),
        _ => Node::Concat(out.into_boxed_slice()),
    }
}

// ---------------------------------------------------------------- 比對

struct Matcher<'a> {
    s: &'a [char],
    steps: Cell<u32>,
    depth: Cell<u32>,
    /// 開始比對時的堆疊位置
    base: usize,
}

impl Matcher<'_> {
    fn tick(&self) -> bool {
        let n = self.steps.get();
        if n >= STEP_LIMIT {
            return false;
        }
        self.steps.set(n + 1);
        true
    }

    /// 進入一層遞迴；太深就把步數設成用完（整次比對當作沒命中）
    fn enter(&self) -> bool {
        let d = self.depth.get();
        if d >= MAX_DEPTH || stack_pos().abs_diff(self.base) > STACK_BUDGET {
            self.steps.set(STEP_LIMIT);
            return false;
        }
        self.depth.set(d + 1);
        true
    }

    fn leave(&self) {
        self.depth.set(self.depth.get() - 1);
    }

    fn node(&self, n: &Node, i: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
        if !self.tick() || !self.enter() {
            return false;
        }
        let r = self.node_inner(n, i, k);
        self.leave();
        r
    }

    fn node_inner(&self, n: &Node, i: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
        let s = self.s;
        match n {
            Node::Empty => k(i),
            Node::Char(c) => i < s.len() && canon(s[i]) == *c && k(i + 1),
            Node::Lit(l) => {
                let mut j = i;
                for c in l.chars() {
                    if j >= s.len() || canon(s[j]) != c {
                        return false;
                    }
                    j += 1;
                }
                k(j)
            }
            Node::Star => {
                // 貪婪：先吃到換行字元或結尾，再一步步退回
                let end = s[i..].iter().position(|&c| is_line_term(c)).map_or(s.len(), |p| i + p);
                for j in (i..=end).rev() {
                    if k(j) {
                        return true;
                    }
                    if !self.tick() {
                        return false;
                    }
                }
                false
            }
            Node::Sep => {
                if i == s.len() {
                    return k(i);
                }
                // [^a-z0-9_.%-]（不分大小寫）
                !matches!(canon(s[i]), 'A'..='Z' | '0'..='9' | '_' | '.' | '%' | '-') && k(i + 1)
            }
            Node::Any => i < s.len() && !is_line_term(s[i]) && k(i + 1),
            Node::Class(cl) => i < s.len() && cl.matches(s[i]) && k(i + 1),
            Node::Start => i == 0 && k(i),
            Node::End => i == s.len() && k(i),
            Node::WordBoundary(want) => {
                let a = i > 0 && is_word(s[i - 1]);
                let b = i < s.len() && is_word(s[i]);
                ((a != b) == *want) && k(i)
            }
            Node::Concat(v) => self.seq(v, i, k),
            Node::Alt(v) => {
                for a in v {
                    if self.node(a, i, k) {
                        return true;
                    }
                }
                false
            }
            Node::Repeat { node, min, max, greedy } => self.rep(node, *min, *max, *greedy, 0, i, k),
            Node::Look {
                node,
                negate,
                behind: false,
            } => {
                let found = self.node(node, i, &mut |_| true);
                found != *negate && k(i)
            }
            Node::Look {
                node,
                negate,
                behind: true,
            } => {
                // 後顧：找一個起點 j ≤ i，讓內容剛好比對到 i 為止（只看真假，結果跟 JS 由右往左比對相同）
                let found = (0..=i).rev().any(|j| self.node(node, j, &mut |e| e == i));
                found != *negate && k(i)
            }
        }
    }

    fn seq(&self, v: &[Node], i: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
        match v.split_first() {
            None => k(i),
            Some((first, rest)) => self.node(first, i, &mut |j| self.seq(rest, j, k)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn rep(&self, n: &Node, min: u32, max: u32, greedy: bool, count: u32, i: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
        if !self.tick() || !self.enter() {
            return false;
        }
        let r = self.rep_inner(n, min, max, greedy, count, i, k);
        self.leave();
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn rep_inner(&self, n: &Node, min: u32, max: u32, greedy: bool, count: u32, i: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
        let more = |k: &mut dyn FnMut(usize) -> bool| {
            count < max
                && self.node(n, i, &mut |j| {
                    // 已達最少次數後，空字串的重複不算（同 JS 的規則，避免無窮迴圈）
                    if j == i && count >= min {
                        return false;
                    }
                    self.rep(n, min, max, greedy, count.saturating_add(1), j, k)
                })
        };
        // 貪婪：先試多吃一次再試停下；非貪婪相反
        let stop = |k: &mut dyn FnMut(usize) -> bool| count >= min && k(i);
        if greedy {
            if more(k) {
                return true;
            }
            stop(k)
        } else {
            if stop(k) {
                return true;
            }
            more(k)
        }
    }
}

impl Regex {
    /// 解析 JS 正規表示式（`/.../` 中間那段），一律不分大小寫
    pub(crate) fn parse(src: &str) -> R<Regex> {
        let mut p = Parser {
            p: src.chars().collect(),
            i: 0,
            depth: 0,
        };
        let root = p.alt()?;
        if p.i != p.p.len() {
            // 多出來的 `)`
            return Err(RegexError::Syntax);
        }
        Ok(Regex::from_node(root))
    }

    fn from_node(root: Node) -> Regex {
        let anchored = match &root {
            Node::Start => true,
            Node::Concat(v) => matches!(v.first(), Some(Node::Start)),
            _ => false,
        };
        Regex { root, anchored }
    }

    /// node 版 `patternToRegex`：把 adblock 樣式（含 `*`、`^`、結尾 `|`）轉成比對主機名的規則。
    /// `pattern` 已轉小寫、已去掉開頭的 `||` / `|`。
    pub(crate) fn from_adblock(pattern: &str, anchor_domain: bool, anchor_start: bool) -> Regex {
        let mut p: Vec<char> = pattern.chars().collect();
        let end_anchor = p.last() == Some(&'|');
        if end_anchor {
            p.pop();
        }
        let mut items = Vec::with_capacity(p.len() + 3);
        if anchor_domain {
            items.push(Node::Start);
            if p.first() != Some(&'*') {
                // ^(?:.*\.)? ：網域本身或任何子網域
                items.push(Node::Repeat {
                    node: Box::new(Node::Concat(Box::new([Node::Star, Node::Char('.')]))),
                    min: 0,
                    max: 1,
                    greedy: true,
                });
            }
        } else if anchor_start {
            items.push(Node::Start);
        }
        for &ch in &p {
            items.push(match ch {
                '*' => Node::Star,
                '^' => Node::Sep,
                c => Node::Char(canon(c)),
            });
        }
        if end_anchor {
            items.push(Node::End);
        }
        Regex::from_node(concat(items))
    }

    /// 等同 JS 的 `re.test(s)`（不含 g 旗標）
    pub(crate) fn is_match(&self, s: &[char]) -> bool {
        let m = Matcher {
            s,
            steps: Cell::new(0),
            depth: Cell::new(0),
            base: stack_pos(),
        };
        let last = if self.anchored { 0 } else { s.len() };
        for start in 0..=last {
            if m.node(&self.root, start, &mut |_| true) {
                return true;
            }
            if m.steps.get() >= STEP_LIMIT {
                return false;
            }
        }
        false
    }

    /// 比對成功時名稱裡一定會出現的固定字串（小寫 ASCII），當作快速排除用；找不到就回傳 None。
    /// 取最上層串接裡最長的 `Lit`（只收 ASCII：查詢名稱已轉小寫，大小寫比對等同直接比對小寫）。
    pub(crate) fn required_literal(&self) -> Option<String> {
        let items: &[Node] = match &self.root {
            Node::Concat(v) => v,
            n => std::slice::from_ref(n),
        };
        items
            .iter()
            .filter_map(|n| match n {
                Node::Lit(l) if l.is_ascii() && l.len() >= 3 => Some(l.to_ascii_lowercase()),
                _ => None,
            })
            .max_by_key(String::len)
    }

    /// 估計佔用的堆積記憶體
    pub(crate) fn heap_bytes(&self) -> usize {
        self.root.heap_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(re: &str, s: &str) -> bool {
        let chars: Vec<char> = s.chars().collect();
        Regex::parse(re).unwrap().is_match(&chars)
    }

    #[test]
    fn basics() {
        assert!(t("^ad[0-9]+\\.regex\\.test$", "ad12.regex.test"));
        assert!(!t("^ad[0-9]+\\.regex\\.test$", "adx.regex.test"));
        assert!(t("AD\\d", "xad1"));
        assert!(t("^(a|b)+c$", "ababc"));
        assert!(!t("^(a|b)+c$", "abab"));
        assert!(t("^a{2,3}$", "aaa"));
        assert!(!t("^a{2,3}$", "aaaa"));
        assert!(t("a{,2}", "a{,2}"));
        assert!(t("^(?!ads\\.)[a-z]+\\.com$", "good.com"));
        assert!(!t("^(?!ads\\.)[a-z]+\\.com$", "ads.com"));
        assert!(t("\\bfoo\\b", "a.foo.b"));
        assert!(!t("\\bfoo\\b", "afoo.b"));
        assert!(t("^[^.]+\\.example\\.com$", "x.example.com"));
        assert!(!t("^[^.]+\\.example\\.com$", "y.x.example.com"));
        assert!(t("[A-Z]", "q"));
        assert!(t("^(?<n>ab)+$", "abab"));
        assert!(t("^a*?b$", "aaab"));
        assert!(t("x]y}", "x]y}"));
        assert!(t("[\\d-z]", "-"));
        assert!(t("(?<=x)lookbehind", "xlookbehind"));
        assert!(!t("(?<=x)lookbehind", "ylookbehind"));
        assert!(t("(?<!x)lb$", "ylb"));
        assert!(!t("(?<!x)lb$", "xlb"));
    }

    #[test]
    fn errors() {
        for bad in ["*a", "a**", "(a", "a)", "[a", "[z-a]", "a{2}{3}", "^*", "(?x)", "\\"] {
            assert_eq!(Regex::parse(bad).err(), Some(RegexError::Syntax), "{bad}");
        }
        for uns in ["(a)\\1", "\\k<x>", "\\012"] {
            assert_eq!(Regex::parse(uns).err(), Some(RegexError::Unsupported), "{uns}");
        }
    }

    #[test]
    fn required_literal() {
        let lit = |re: &str| Regex::parse(re).unwrap().required_literal();
        assert_eq!(lit("^ad[0-9]+\\.Regex\\.test$").as_deref(), Some(".regex.test"));
        assert_eq!(lit("^(a|b)c$"), None);
        assert_eq!(lit("abcd").as_deref(), Some("abcd"));
    }

    #[test]
    fn catastrophic_is_bounded() {
        let s: Vec<char> = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab".chars().collect();
        let re = Regex::parse("^(a+)+$").unwrap();
        assert!(!re.is_match(&s));
    }

    /// 在小堆疊（1 MiB，比 tokio 工作執行緒的 2 MiB 還小）的執行緒裡跑：堆疊用完會讓整個測試程序當掉
    fn small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            // 跟正式執行時的執行緒一樣大（Rust / tokio 預設 2 MiB）
            .stack_size(2 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap()
    }

    #[test]
    fn deep_nesting_is_rejected_not_a_crash() {
        // 清單裡一行幾萬個 `(`：以前解析時遞迴到堆疊用完，整個程式當掉
        let r = small_stack(|| {
            let src = format!("{}a{}", "(".repeat(30_000), ")".repeat(30_000));
            Regex::parse(&src).map(|_| ())
        });
        assert_eq!(r, Err(RegexError::Unsupported));
        // 正常的巢狀深度照常解析
        let ok = format!("{}a{}", "(?:".repeat(50), ")".repeat(50));
        assert!(t(&ok, "xax"));
    }

    #[test]
    fn deep_recursion_is_bounded_not_a_crash() {
        // 不吃字元也能重複幾萬次：以前在步數上限之前就把堆疊用完
        for re in ["(?:a?){60000}b", "(?:a*)*b", "(?:|a)+b", "(?:a?){60000}"] {
            let re = re.to_string();
            small_stack(move || {
                let s: Vec<char> = "aaaa.example.com".chars().collect();
                Regex::parse(&re).unwrap().is_match(&s)
            });
        }
        // adblock 樣式：幾萬個連續的 `*`
        small_stack(|| {
            let s: Vec<char> = "ads.example.com".chars().collect();
            Regex::from_adblock(&format!("a{}z", "*".repeat(60_000)), true, false).is_match(&s)
        });
        // 最長的網域名稱（253 個字元）配一般的樣式：不會碰到深度上限
        let name = format!("{}.example.com", ["abcdefghi"; 24].join("."));
        assert_eq!(name.len(), 251);
        assert!(t("^(?:[a-z0-9-]+\\.)*example\\.com$", &name));
        assert!(t("^.*\\.example\\..*$", &name));
        assert!(t("(?:[a-z]|[0-9]|\\.)+m$", &name));
    }

    #[test]
    fn adblock_patterns() {
        let m = |p: &str, d: bool, st: bool, s: &str| {
            let chars: Vec<char> = s.chars().collect();
            Regex::from_adblock(p, d, st).is_match(&chars)
        };
        assert!(m("cl*.apple.com^", true, false, "cl3.apple.com"));
        assert!(m("cl*.apple.com^", true, false, "x.cl3.apple.com"));
        assert!(!m("cl*.apple.com^", true, false, "xcl3.apple.com.evil"));
        assert!(m(
            "*netseer-ipaddr-assoc*.fbcdn.net",
            false,
            false,
            "x.netseer-ipaddr-assoc.abc.fbcdn.net"
        ));
        assert!(m("ads.example.com", false, true, "ads.example.community"));
        assert!(m("*.example.com^", true, false, "a.example.com"));
        assert!(!m("*.example.com^", true, false, "example.com"));
        assert!(m("ad*.com|", false, false, "xad1.com"));
        assert!(!m("ad*.com|", false, false, "ad1.com.tw"));
    }
}
