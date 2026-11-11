//! 跟 JavaScript 行為一致的小工具（node 版的語意以 JS 字串函式為準）。

use std::borrow::Cow;

/// JS 的 `\s` / `String.prototype.trim` 認定的空白（含 U+FEFF，不含 U+0085）
pub(crate) fn is_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{0b}' | '\u{0c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

/// `String.prototype.trim`
pub(crate) fn trim(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// `String.prototype.toLowerCase`（已經是小寫 ASCII 時不配置記憶體）
pub(crate) fn lower(s: &str) -> Cow<'_, str> {
    if s.bytes().all(|b| b.is_ascii() && !b.is_ascii_uppercase()) {
        Cow::Borrowed(s)
    } else {
        Cow::Owned(s.to_lowercase())
    }
}

/// `String.prototype.toUpperCase`
pub(crate) fn upper(s: &str) -> String {
    s.to_uppercase()
}

/// node 版的 `DOMAIN_RE`：
/// `^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*\.?$`
pub(crate) fn is_domain(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() {
        return false;
    }
    s.split('.').all(|label| {
        let b = label.as_bytes();
        let ok = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_';
        !b.is_empty() && ok(b[0]) && ok(b[b.len() - 1]) && b.iter().all(|&c| ok(c) || c == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_re() {
        for ok in ["a", "a.b", "a-b.c_d", "_dmarc.x", "a.b.", "1.2.3.4", "x--y.z"] {
            assert!(is_domain(ok), "{ok}");
        }
        for bad in ["", ".", "a..b", "-a.b", "a-.b", "a.b..", "A.b", "a b", "a*.b", ".a", "例子.台灣"] {
            assert!(!is_domain(bad), "{bad}");
        }
    }

    #[test]
    fn js_trim() {
        assert_eq!(trim("\u{feff} ||a^ \r"), "||a^");
        assert_eq!(trim("\u{85}x"), "\u{85}x");
    }
}
