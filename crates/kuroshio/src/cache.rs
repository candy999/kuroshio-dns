//! DNS 快取（對齊 2.x `Resolver.cache`）
//!
//! - 鍵：`類型|名稱`（名稱小寫）
//! - 每分鐘清掃：過期超過 serve-stale 時間的刪掉；超過上限時刪掉最久沒用的，降到上限的 90%

use kuroshio_proto::logic::Class;
use kuroshio_proto::message::Record;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Entry {
    pub rcode: u16,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub class: Class,
    /// 回答的上游 id（或「全部失敗」）
    pub source: String,
    /// 回應裡的 CNAME 指向被封鎖的網域（分類）
    pub blocked: Option<&'static str>,
    /// 第一個上游先回的「快速回應」，之後會被合併測速後的結果取代
    pub fast: bool,
    /// IP 測速摘要，例如「12ms/6IP」
    pub ranked: Option<String>,
    /// 「如果用一般 DNS 會怎樣」：固定上游以外的上游給的 A 記錄（CDN 路由統計用）
    pub baseline: Option<kuroshio_cdn::Baseline>,
    pub stored_at: Instant,
    pub expires_at: Instant,
    /// 寫入時的 TTL（自適應預取用）
    pub ttl: u32,
    last_access: AtomicU32,
    pub hits: AtomicU32,
}

/// 單調時鐘（0.1 秒為單位，u32 可以撐 13 年）。32 位元 MIPS 沒有 64 位元原子操作，所以用 u32
fn mono_ds(base: Instant, t: Instant) -> u32 {
    (t.saturating_duration_since(base).as_millis() / 100).min(u32::MAX as u128) as u32
}

impl Entry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rcode: u16,
        answers: Vec<Record>,
        authorities: Vec<Record>,
        class: Class,
        source: String,
        ttl: u32,
        fast: bool,
        ranked: Option<String>,
    ) -> Entry {
        let now = Instant::now();
        Entry {
            rcode,
            answers,
            authorities,
            class,
            source,
            blocked: None,
            fast,
            ranked,
            baseline: None,
            stored_at: now,
            expires_at: now + Duration::from_secs(ttl as u64),
            ttl,
            last_access: AtomicU32::new(0),
            hits: AtomicU32::new(0),
        }
    }

    /// 剩幾秒（負數 = 已過期幾秒）
    pub fn remaining(&self, now: Instant) -> f64 {
        if self.expires_at >= now {
            self.expires_at.duration_since(now).as_secs_f64()
        } else {
            -(now.duration_since(self.expires_at).as_secs_f64())
        }
    }

    pub fn approx_bytes(&self) -> usize {
        let rec = |r: &Record| r.name.len() + 48 + matches!(r.data, kuroshio_proto::RData::Raw(ref d) if !d.is_empty()) as usize * 32;
        160 + self.source.len() + self.answers.iter().map(rec).sum::<usize>() + self.authorities.iter().map(rec).sum::<usize>()
    }
}

pub struct Cache {
    map: HashMap<String, Arc<Entry>>,
    pub max: usize,
    base: Instant,
}

impl Cache {
    pub fn new(max: usize) -> Cache {
        Cache {
            map: HashMap::new(),
            max: max.max(16),
            base: Instant::now(),
        }
    }

    pub fn key(qtype: u16, qname: &str) -> String {
        format!("{qtype}|{qname}")
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// 取出並記錄使用時間；回傳 (項目, 上次使用距今)
    pub fn get(&self, key: &str, now: Instant) -> Option<(Arc<Entry>, Duration)> {
        let e = self.map.get(key)?.clone();
        let now_ds = mono_ds(self.base, now);
        let last = e.last_access.swap(now_ds, Ordering::Relaxed);
        e.hits.fetch_add(1, Ordering::Relaxed);
        Some((e, Duration::from_millis(now_ds.saturating_sub(last) as u64 * 100)))
    }

    pub fn peek(&self, key: &str) -> Option<Arc<Entry>> {
        self.map.get(key).cloned()
    }

    /// 寫入：快速回應不覆蓋還新鮮的完整結果。回傳實際在快取裡的項目
    pub fn insert(&mut self, key: String, e: Entry, now: Instant) -> Arc<Entry> {
        let old = self.map.get(&key);
        if e.fast {
            if let Some(o) = old {
                if !o.fast && o.expires_at > now {
                    return o.clone();
                }
            }
        }
        // 沿用舊項目的使用紀錄（prefetch 判斷要看「最近有沒有人用」）
        let last = old
            .map(|o| o.last_access.load(Ordering::Relaxed))
            .unwrap_or_else(|| mono_ds(self.base, now));
        let hits = old.map(|o| o.hits.load(Ordering::Relaxed)).unwrap_or(0);
        e.last_access.store(last, Ordering::Relaxed);
        e.hits.store(hits, Ordering::Relaxed);
        let e = Arc::new(e);
        self.map.insert(key, e.clone());
        if self.map.len() > self.max + self.max / 10 {
            self.sweep(now, 0);
        }
        e
    }

    pub fn remove_where(&mut self, f: impl Fn(&str) -> bool) -> usize {
        let before = self.map.len();
        self.map.retain(|k, _| !f(k));
        before - self.map.len()
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// 清掃：過期超過 stale 秒的刪掉；超過上限刪掉最久沒用的，降到 90%
    pub fn sweep(&mut self, now: Instant, stale_sec: u64) {
        let stale = Duration::from_secs(stale_sec);
        self.map.retain(|_, e| e.expires_at + stale >= now);
        if self.map.len() > self.max {
            let target = self.max * 9 / 10;
            let mut v: Vec<(String, u32)> = self
                .map
                .iter()
                .map(|(k, e)| (k.clone(), e.last_access.load(Ordering::Relaxed)))
                .collect();
            v.sort_by_key(|x| x.1);
            let n = self.map.len() - target;
            for (k, _) in v.into_iter().take(n) {
                self.map.remove(&k);
            }
        }
    }

    /// 最常被查的 n 個鍵（開機預熱用）；失敗與被擋的不算
    pub fn hot_keys(&self, n: usize) -> Vec<String> {
        let mut v: Vec<(&String, u32)> = self
            .map
            .iter()
            .filter(|(_, e)| e.class != Class::ServFail && e.blocked.is_none())
            .map(|(k, e)| (k, e.hits.load(Ordering::Relaxed)))
            .filter(|x| x.1 > 0)
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        v.into_iter().take(n).map(|x| x.0.clone()).collect()
    }

    pub fn approx_bytes(&self) -> usize {
        self.map.iter().map(|(k, e)| k.len() + 48 + e.approx_bytes()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn entry(ttl: u32, fast: bool) -> Entry {
        Entry::new(
            0,
            vec![Record::a("a.test", ttl, Ipv4Addr::new(1, 2, 3, 4))],
            vec![],
            Class::Ok,
            "up".into(),
            ttl,
            fast,
            None,
        )
    }

    #[test]
    fn fast_does_not_replace_fresh_full_result() {
        let mut c = Cache::new(100);
        let now = Instant::now();
        c.insert("1|a.test".into(), entry(60, false), now);
        let kept = c.insert("1|a.test".into(), entry(10, true), now);
        assert!(!kept.fast);
        let replaced = c.insert("1|a.test".into(), entry(60, false), now);
        assert!(!replaced.fast);
    }

    #[test]
    fn sweep_stale_and_lru() {
        let mut c = Cache::new(20);
        let t0 = Instant::now();
        for i in 0..20 {
            c.insert(format!("1|n{i}.test"), entry(60, false), t0);
        }
        // 讓前 10 筆最近被用過
        for i in 0..10 {
            c.get(&format!("1|n{i}.test"), t0 + Duration::from_secs(5));
        }
        for i in 20..23 {
            c.insert(format!("1|n{i}.test"), entry(60, false), t0 + Duration::from_secs(6));
        }
        c.sweep(t0 + Duration::from_secs(6), 0);
        assert_eq!(c.len(), 18, "超過上限降到 90%");
        assert!(c.peek("1|n0.test").is_some(), "最近用過的保留");
        // 過期 + stale 時間之後才刪
        c.sweep(t0 + Duration::from_secs(61 + 30), 60);
        assert_eq!(c.len(), 18);
        c.sweep(t0 + Duration::from_secs(61 + 61), 60);
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn remaining_and_hits() {
        let mut c = Cache::new(10);
        let t0 = Instant::now();
        c.insert("1|a.test".into(), entry(10, false), t0);
        let (e, _) = c.get("1|a.test", t0).unwrap();
        assert!(e.remaining(t0 + Duration::from_secs(4)) > 5.0);
        assert!(e.remaining(t0 + Duration::from_secs(15)) < -4.0);
        assert_eq!(e.hits.load(Ordering::Relaxed), 1);
    }
}
