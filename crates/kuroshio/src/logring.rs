//! 最近的日誌（記憶體環狀緩衝，設定頁「日誌」分頁用；OpenWrt 仍用 logread）

use std::collections::VecDeque;
use std::io::Write;
use std::sync::Mutex;

const MAX_LINES: usize = 500;

static RING: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// 最近 n 行（舊到新）
pub fn lines(n: usize) -> Vec<String> {
    let r = RING.lock().unwrap();
    r.iter().skip(r.len().saturating_sub(n)).cloned().collect()
}

/// 看起來是在帶密碼 / 金鑰的參數名稱（後面的值換成 `***`）
const SECRET_KEYS: [&str; 9] = [
    "token",
    "password",
    "passwd",
    "secret",
    "apikey",
    "api_key",
    "key",
    "authorization",
    "bearer",
];

/// 日誌會顯示在設定頁：`token=…`、`Authorization: Bearer …`、網址裡的 `user:pass@` 不留原文。
/// 程式本來就不該把密碼寫進日誌，這裡是最後一道（例如第三方函式庫的錯誤訊息帶了完整網址）
pub fn redact(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let b = lower.as_bytes();
    // 要換掉的範圍（位元組位置；小寫化不改變 ASCII 以外的位元組長度）
    let mut cuts: Vec<(usize, usize)> = Vec::new();
    for k in SECRET_KEYS {
        let mut from = 0;
        while let Some(i) = lower[from..].find(k) {
            let start = from + i;
            let mut j = start + k.len();
            from = j;
            // 前面不能是英數（`monkey=`、`tokens` 不算）
            if start > 0 && (b[start - 1].is_ascii_alphanumeric()) {
                continue;
            }
            // 接著是 `=` 或 `:`（前後可以有引號、空白）；只有 `Bearer` 可以只隔空白
            let sep = j;
            while j < b.len() && matches!(b[j], b'=' | b':' | b'"' | b'\'' | b' ') {
                j += 1;
            }
            if j == sep || !(lower[sep..j].contains(['=', ':']) || k == "bearer") {
                continue;
            }
            // `Authorization: Bearer xxx`：跳過 Bearer / Basic
            for scheme in ["bearer ", "basic "] {
                if lower[j..].starts_with(scheme) {
                    j += scheme.len();
                }
            }
            let mut e = j;
            while e < b.len() && !matches!(b[e], b' ' | b'&' | b'"' | b'\'' | b',' | b';' | b')' | b'}' | b'\n') {
                e += 1;
            }
            // 太短的不像密碼
            if e - j >= 6 {
                cuts.push((j, e));
            }
        }
    }
    // 網址裡的帳號密碼：`://user:pass@`
    let mut from = 0;
    while let Some(i) = lower[from..].find("://") {
        let s = from + i + 3;
        from = s;
        let end = lower[s..].find(['/', ' ', '?', '"']).map(|x| s + x).unwrap_or(b.len());
        if let Some(at) = lower[s..end].rfind('@') {
            cuts.push((s, s + at));
        }
    }
    if cuts.is_empty() {
        return line.to_string();
    }
    cuts.sort_unstable();
    let mut out = String::with_capacity(line.len());
    let mut pos = 0;
    for (a, e) in cuts {
        if a < pos || !line.is_char_boundary(a) || !line.is_char_boundary(e) {
            continue;
        }
        out.push_str(&line[pos..a]);
        out.push_str("***");
        pos = e;
    }
    out.push_str(&line[pos..]);
    out
}

fn push(text: &str) {
    let mut r = RING.lock().unwrap();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        if r.len() >= MAX_LINES {
            r.pop_front();
        }
        r.push_back(redact(line));
    }
}

/// tracing 的輸出端：寫進環狀緩衝（搭配 `MakeWriterExt::and` 同時寫到畫面或檔案）
#[derive(Clone, Copy, Default)]
pub struct RingWriter;

impl Write for RingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        push(&String::from_utf8_lossy(buf));
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RingWriter {
    type Writer = RingWriter;
    fn make_writer(&'a self) -> Self::Writer {
        RingWriter
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn redacts_secrets() {
        let r = super::redact;
        assert_eq!(
            r("DDNS 更新失敗：https://api.example.com/update?host=a&token=abcdef123456&ip=1.2.3.4"),
            "DDNS 更新失敗：https://api.example.com/update?host=a&token=***&ip=1.2.3.4"
        );
        assert_eq!(r("Authorization: Bearer abc.def.ghi-123 送出"), "Authorization: Bearer *** 送出");
        assert_eq!(
            r(r#"{"apiToken":"x","password": "hunter2hunter2"}"#),
            r#"{"apiToken":"x","password": "***"}"#
        );
        assert_eq!(
            r("連線 https://user:s3cretpw@dns.example.net/dns-query 失敗"),
            "連線 https://***@dns.example.net/dns-query 失敗"
        );
        assert_eq!(r("X-Api-Key: 0123456789abcdef"), "X-Api-Key: ***");
        // 一般的句子不動
        for s in [
            "金鑰 key 不對",
            "tokens=3 monkey=banana12",
            "上游 https://dns.example/dns-query 逾時",
            "查詢 a.example 類型 A",
        ] {
            assert_eq!(r(s), s);
        }
    }

    #[test]
    fn keeps_last_lines() {
        for i in 0..(super::MAX_LINES + 10) {
            super::push(&format!("line {i}\n"));
        }
        let l = super::lines(3);
        assert_eq!(l.len(), 3);
        assert_eq!(l[2], format!("line {}", super::MAX_LINES + 9));
        assert!(super::lines(10_000).len() <= super::MAX_LINES);
    }
}
