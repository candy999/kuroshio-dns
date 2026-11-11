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

fn push(text: &str) {
    let mut r = RING.lock().unwrap();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        if r.len() >= MAX_LINES {
            r.pop_front();
        }
        r.push_back(line.to_string());
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
