//! 防濫用（規格 03 第 9 節）：速率限制、nonce 重放紀錄
//!
//! 計數一律用 u32 / 一般整數放在 Mutex 裡（32 位元 MIPS 沒有 AtomicU64）。

use std::collections::HashMap;

/// 固定時間窗：同一個 key 每 `window_ms` 最多 `max` 次
pub struct RateLimit {
    max: u32,
    window_ms: u64,
    m: HashMap<String, (u64, u32)>,
}

impl RateLimit {
    pub fn new(max: u32, window_ms: u64) -> RateLimit {
        RateLimit {
            max,
            window_ms,
            m: HashMap::new(),
        }
    }

    pub fn take(&mut self, key: &str, now: u64) -> bool {
        if self.m.len() > 20_000 {
            let w = self.window_ms;
            self.m.retain(|_, (start, _)| now.saturating_sub(*start) <= w);
            if self.m.len() > 20_000 {
                self.m.clear();
            }
        }
        let b = self.m.entry(key.to_string()).or_insert((now, 0));
        if now.saturating_sub(b.0) > self.window_ms {
            *b = (now, 0);
        }
        b.1 = b.1.saturating_add(1);
        b.1 <= self.max
    }

    /// 目前時間窗內的次數（不計數）
    pub fn count(&self, key: &str, now: u64) -> u32 {
        match self.m.get(key) {
            Some((start, n)) if now.saturating_sub(*start) <= self.window_ms => *n,
            _ => 0,
        }
    }
}

/// `(寄件者, nonce)` 重放紀錄，保留 `keep_ms`
pub struct NonceCache {
    keep_ms: u64,
    m: HashMap<(String, Vec<u8>), u64>,
}

impl NonceCache {
    pub fn new(keep_ms: u64) -> NonceCache {
        NonceCache {
            keep_ms,
            m: HashMap::new(),
        }
    }

    pub fn seen(&self, from: &str, nonce: &[u8]) -> bool {
        self.m.contains_key(&(from.to_string(), nonce.to_vec()))
    }

    /// 記下；已經出現過回 false
    pub fn insert(&mut self, from: &str, nonce: &[u8], now: u64) -> bool {
        if self.m.len() > 50_000 {
            self.prune(now);
        }
        self.m.insert((from.to_string(), nonce.to_vec()), now).is_none()
    }

    pub fn prune(&mut self, now: u64) {
        let keep = self.keep_ms;
        self.m.retain(|_, t| now.saturating_sub(*t) <= keep);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_window() {
        let mut r = RateLimit::new(2, 1000);
        assert!(r.take("a", 0));
        assert!(r.take("a", 10));
        assert!(!r.take("a", 20));
        assert!(r.take("b", 20));
        assert!(r.take("a", 1500));
        assert_eq!(r.count("a", 1500), 1);
    }

    #[test]
    fn nonces() {
        let mut n = NonceCache::new(100);
        assert!(n.insert("a", b"x", 0));
        assert!(!n.insert("a", b"x", 1));
        assert!(n.insert("b", b"x", 1));
        n.prune(500);
        assert!(!n.seen("a", b"x"));
    }
}
