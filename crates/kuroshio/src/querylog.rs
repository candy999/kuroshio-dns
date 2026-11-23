//! 查詢紀錄（3.5.0，規格 11 C4）：管理介面看最近的查詢（網域、類型、來源、結果、延遲、答案來源），用來除錯。
//!
//! - **只在記憶體**：不寫磁碟、不進備份、不給公開頁、不傳給上游／下游／好友。
//! - **預設關閉**：關閉時查詢路徑只多一次 `AtomicBool` 的讀取。
//! - **有上限**：筆數（環狀，`system.queryLogRing`，小記憶體再收緊）、位元組（固定大小 × 筆數）、
//!   時間（暫時開啟最長 60 分鐘，到時間自動關閉並釋放）。
//! - **查詢絕不等這把鎖**：寫入用 `try_lock()`，拿不到就丟掉這一筆、累加 `dropped`。寫入時不配置
//!   （緩衝在開啟時一次配好，每筆是固定大小的結構）。
//! - 32 位元：時間用 `u32` 秒，計數器用 `AtomicU32`。

use serde_json::{json, Value};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// 網域最多記幾個位元組（超過截斷）
const NAME_MAX: usize = 80;
/// 答案來源（上游網址）最多記幾個位元組（超過截斷）
const SRC_MAX: usize = 48;
/// 暫時開啟最長幾分鐘
pub const MAX_MINUTES: u32 = 60;
/// 一次最多讀幾筆
pub const READ_MAX: usize = 1000;

/// 這一筆是怎麼回答的
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// 快取命中
    Hit = 0,
    /// 問了上游
    Miss = 1,
    /// 過濾擋掉
    Blocked = 2,
    /// 快取過期的舊資料（serve-stale）
    Stale = 3,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Hit => "hit",
            Kind::Miss => "miss",
            Kind::Blocked => "blocked",
            Kind::Stale => "stale",
        }
    }
    fn from_u8(v: u8) -> Kind {
        match v {
            0 => Kind::Hit,
            2 => Kind::Blocked,
            3 => Kind::Stale,
            _ => Kind::Miss,
        }
    }
}

/// 固定大小的一筆（約 160 bytes）
#[derive(Clone, Copy)]
struct Rec {
    at: u32,
    qtype: u16,
    ms: u16,
    rcode: u8,
    kind: u8,
    v6: bool,
    name_len: u8,
    src_len: u8,
    client: [u8; 16],
    name: [u8; NAME_MAX],
    src: [u8; SRC_MAX],
}

const EMPTY: Rec = Rec {
    at: 0,
    qtype: 0,
    ms: 0,
    rcode: 0,
    kind: 0,
    v6: false,
    name_len: 0,
    src_len: 0,
    client: [0; 16],
    name: [0; NAME_MAX],
    src: [0; SRC_MAX],
};

/// 每筆佔多少位元組（狀態頁與文件用）
pub const REC_BYTES: usize = std::mem::size_of::<Rec>();

/// 把字串的前面幾個位元組（在字元邊界截斷）複製進固定長度的陣列，不配置
fn copy_trunc<const N: usize>(dst: &mut [u8; N], s: &str) -> u8 {
    let mut n = s.len().min(N);
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    dst[..n].copy_from_slice(&s.as_bytes()[..n]);
    n as u8
}

struct Ring {
    buf: Vec<Rec>,
    /// 下一筆寫在哪裡
    next: usize,
    /// 目前有幾筆
    len: usize,
}

#[derive(Default)]
pub struct QueryLog {
    /// 開著（查詢路徑只看這個）
    on: AtomicBool,
    /// 設定檔的 `log.queryLog`：常開，不會到期
    permanent: AtomicBool,
    /// 暫時開啟到什麼時候（unix 秒）；0 = 沒有暫時開啟
    until: AtomicU32,
    /// 筆數上限
    cap: AtomicU32,
    /// 拿不到鎖丟掉的筆數
    dropped: AtomicU32,
    ring: Mutex<Option<Ring>>,
}

fn now_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

impl QueryLog {
    /// 套用設定：筆數上限與「常開」。常開時立刻配好緩衝
    pub fn configure(&self, cap: u32, permanent: bool) {
        self.cap.store(cap, Ordering::Relaxed);
        self.permanent.store(permanent, Ordering::Relaxed);
        if permanent && cap > 0 {
            self.open();
        } else if self.until.load(Ordering::Relaxed) == 0 {
            self.close();
        }
    }

    fn open(&self) {
        let cap = self.cap.load(Ordering::Relaxed) as usize;
        if cap == 0 {
            return;
        }
        let mut g = self.ring.lock().unwrap();
        if g.as_ref().map_or(true, |r| r.buf.len() != cap) {
            *g = Some(Ring {
                buf: vec![EMPTY; cap],
                next: 0,
                len: 0,
            });
        }
        drop(g);
        self.on.store(true, Ordering::Relaxed);
    }

    /// 關閉並釋放緩衝（記憶體控制「縮小診斷緩衝」也用這個）
    pub fn close(&self) {
        self.on.store(false, Ordering::Relaxed);
        self.until.store(0, Ordering::Relaxed);
        *self.ring.lock().unwrap() = None;
    }

    /// 記憶體控制：釋放緩衝（常開的也關掉，直到下一次重新載入設定或使用者再開）；回傳釋出多少位元組
    pub fn release(&self) -> u64 {
        let bytes = self.ring.lock().unwrap().as_ref().map_or(0, |r| (r.buf.len() * REC_BYTES) as u64);
        self.permanent.store(false, Ordering::Relaxed);
        self.close();
        bytes
    }

    /// 暫時開啟 `minutes` 分鐘（1～60）；0 = 關閉暫時開啟（常開的不受影響）。
    /// 開、關各寫一行 INFO（3.5.0 F6／H12：以前沒有日誌），回傳那一行（測試用）
    pub fn enable_for(&self, minutes: u32, now: u32) -> String {
        let msg = if minutes == 0 {
            self.until.store(0, Ordering::Relaxed);
            if self.permanent.load(Ordering::Relaxed) {
                "查詢紀錄的暫時開啟取消（設定是常開，照樣記錄）".to_string()
            } else {
                let n = self.ring.lock().unwrap().as_ref().map_or(0, |r| r.len);
                self.close();
                format!("查詢紀錄關閉（清掉 {n} 筆）")
            }
        } else {
            let m = minutes.min(MAX_MINUTES);
            self.until.store(now.saturating_add(m * 60), Ordering::Relaxed);
            self.open();
            format!("查詢紀錄開啟 {m} 分鐘（只在記憶體，到期自動關）")
        };
        tracing::info!("{msg}");
        msg
    }

    /// 開著嗎（查詢路徑先看這個；關閉時只有這一次原子讀取）
    #[inline]
    pub fn enabled(&self) -> bool {
        self.on.load(Ordering::Relaxed)
    }

    /// 暫時開啟到期了：關閉並釋放
    fn expire(&self, now: u32) -> bool {
        let until = self.until.load(Ordering::Relaxed);
        if until != 0 && now >= until && !self.permanent.load(Ordering::Relaxed) {
            self.close();
            return true;
        }
        false
    }

    /// 記一筆。拿不到鎖就丟掉（查詢不等）
    #[allow(clippy::too_many_arguments)]
    pub fn push(&self, now: u32, name: &str, qtype: u16, client: IpAddr, kind: Kind, rcode: u8, ms: f64, source: &str) {
        if !self.enabled() || self.expire(now) {
            return;
        }
        let Ok(mut g) = self.ring.try_lock() else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Some(r) = g.as_mut() else { return };
        let cap = r.buf.len();
        if cap == 0 {
            return;
        }
        let rec = &mut r.buf[r.next];
        rec.at = now;
        rec.qtype = qtype;
        rec.ms = ms.clamp(0.0, u16::MAX as f64) as u16;
        rec.rcode = rcode;
        rec.kind = kind as u8;
        match client.to_canonical() {
            IpAddr::V4(v) => {
                rec.v6 = false;
                rec.client = [0; 16];
                rec.client[..4].copy_from_slice(&v.octets());
            }
            IpAddr::V6(v) => {
                rec.v6 = true;
                rec.client = v.octets();
            }
        }
        rec.name_len = copy_trunc(&mut rec.name, name);
        rec.src_len = copy_trunc(&mut rec.src, source);
        r.next = (r.next + 1) % cap;
        r.len = (r.len + 1).min(cap);
    }

    /// 最近的紀錄（新的在前）：最多 `limit` 筆（上限 1,000），可以只看某個網域（包含這段文字）、某個來源、某個時間之後
    pub fn read(&self, now: u32, limit: usize, name: Option<&str>, client: Option<IpAddr>, since: Option<u32>) -> Value {
        self.expire(now);
        let limit = limit.clamp(1, READ_MAX);
        let name = name.map(|n| n.trim_end_matches('.').to_ascii_lowercase());
        let client = client.map(|c| c.to_canonical());
        let mut out = Vec::new();
        {
            let g = self.ring.lock().unwrap();
            if let Some(r) = g.as_ref() {
                let cap = r.buf.len();
                for i in 0..r.len {
                    if out.len() >= limit {
                        break;
                    }
                    let rec = &r.buf[(r.next + cap - 1 - i) % cap];
                    if since.is_some_and(|s| rec.at < s) {
                        continue;
                    }
                    let ip = rec_ip(rec);
                    if client.is_some_and(|c| c != ip) {
                        continue;
                    }
                    let n = std::str::from_utf8(&rec.name[..rec.name_len as usize]).unwrap_or("");
                    if name.as_deref().is_some_and(|f| !n.contains(f)) {
                        continue;
                    }
                    out.push(json!({
                        "at": u64::from(rec.at) * 1000, "name": n, "type": rec.qtype, "client": ip.to_string(),
                        "result": Kind::from_u8(rec.kind).name(), "rcode": rec.rcode, "ms": rec.ms,
                        "source": std::str::from_utf8(&rec.src[..rec.src_len as usize]).unwrap_or(""),
                    }));
                }
            }
        }
        let mut v = self.status(now);
        v["entries"] = Value::Array(out);
        v
    }

    /// 狀態（`/api/status` 只放這個，不放內容）
    pub fn status(&self, now: u32) -> Value {
        self.expire(now);
        let until = self.until.load(Ordering::Relaxed);
        let size = self.ring.lock().unwrap().as_ref().map_or(0, |r| r.len);
        json!({
            "enabled": self.enabled(),
            "permanent": self.permanent.load(Ordering::Relaxed) && self.enabled(),
            "until": if until == 0 { Value::Null } else { json!(u64::from(until) * 1000) },
            "capacity": self.cap.load(Ordering::Relaxed),
            "size": size,
            "dropped": self.dropped.load(Ordering::Relaxed),
            "bytes": if self.enabled() { self.cap.load(Ordering::Relaxed) as usize * REC_BYTES } else { 0 },
        })
    }
}

fn rec_ip(r: &Rec) -> IpAddr {
    if r.v6 {
        IpAddr::from(r.client)
    } else {
        IpAddr::from([r.client[0], r.client[1], r.client[2], r.client[3]])
    }
}

/// 查詢紀錄的筆數上限：設定值（`system.queryLogRing`），小記憶體再收緊（160 MB 以下最多 1,000 筆、512 MB 以下最多 5,000 筆）
pub fn capacity_for(configured: u64, mem_total: Option<u64>) -> u32 {
    const MB: u64 = 1024 * 1024;
    let limit = match mem_total {
        Some(t) if t < 160 * MB => 1_000,
        Some(t) if t < 512 * MB => 5_000,
        _ => 100_000,
    };
    configured.min(limit) as u32
}

/// 現在的 unix 秒（呼叫端傳進 `push`／`read`，測試可以注入）
pub fn now() -> u32 {
    now_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, n))
    }

    #[test]
    fn disabled_is_noop() {
        let q = QueryLog::default();
        q.configure(10, false);
        assert!(!q.enabled());
        q.push(100, "www.example.com", 1, ip(2), Kind::Miss, 0, 12.0, "udp://192.0.2.53:53");
        assert_eq!(q.read(100, 10, None, None, None)["entries"].as_array().unwrap().len(), 0);
        assert_eq!(q.status(100)["bytes"], 0, "關閉時沒有配置緩衝");
    }

    #[test]
    fn ring_overwrites_oldest_and_truncates() {
        let q = QueryLog::default();
        q.configure(3, true);
        for i in 0..5u8 {
            q.push(100 + i as u32, &format!("n{i}.example.com"), 1, ip(i), Kind::Hit, 0, 1.0, "cache");
        }
        let v = q.read(200, 10, None, None, None);
        let e = v["entries"].as_array().unwrap();
        let names: Vec<&str> = e.iter().map(|x| x["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            vec!["n4.example.com", "n3.example.com", "n2.example.com"],
            "新的在前、最舊的被蓋掉"
        );
        assert_eq!(v["size"], 3);
        // 長網域截斷（在字元邊界）
        let long = format!("{}.example.com", "a".repeat(200));
        q.push(300, &long, 28, ip(9), Kind::Blocked, 3, 0.5, &"x".repeat(300));
        let e = q.read(300, 1, None, None, None)["entries"][0].clone();
        assert_eq!(e["name"].as_str().unwrap().len(), NAME_MAX);
        assert_eq!(e["source"].as_str().unwrap().len(), SRC_MAX);
        assert_eq!(e["result"], "blocked");
        assert_eq!(e["type"], 28);
        let cjk = "測".repeat(40);
        q.push(301, &cjk, 1, ip(9), Kind::Miss, 0, 1.0, "");
        let n = q.read(301, 1, None, None, None)["entries"][0]["name"].as_str().unwrap().to_string();
        assert!(n.len() <= NAME_MAX && n.chars().all(|c| c == '測'), "不切在字元中間：{n}");
    }

    #[test]
    fn temporary_enable_expires_and_frees() {
        let q = QueryLog::default();
        q.configure(100, false);
        q.enable_for(10, 1000);
        assert!(q.enabled());
        q.push(1001, "a.example.com", 1, ip(2), Kind::Miss, 0, 3.0, "udp://192.0.2.53:53");
        assert_eq!(q.status(1001)["size"], 1);
        assert_eq!(q.status(1001)["until"], json!((1000u64 + 600) * 1000));
        // 到期：下一筆不記、緩衝釋放
        q.push(1000 + 600, "b.example.com", 1, ip(2), Kind::Miss, 0, 3.0, "");
        assert!(!q.enabled());
        assert_eq!(q.status(1600)["size"], 0);
        // 最長 60 分鐘
        q.enable_for(999, 2000);
        assert_eq!(q.status(2000)["until"], json!((2000u64 + 3600) * 1000));
        // 0 = 關掉
        q.enable_for(0, 2001);
        assert!(!q.enabled());
    }

    /// 3.5.0 F6／H12：開、關都寫一行（以前沒有日誌）
    #[test]
    fn querylog_toggle_is_logged() {
        let q = QueryLog::default();
        q.configure(100, false);
        assert_eq!(q.enable_for(10, 1000), "查詢紀錄開啟 10 分鐘（只在記憶體，到期自動關）");
        assert_eq!(q.enable_for(999, 1000), "查詢紀錄開啟 60 分鐘（只在記憶體，到期自動關）");
        q.push(1001, "a.example.com", 1, ip(2), Kind::Miss, 0, 3.0, "");
        q.push(1002, "b.example.com", 1, ip(2), Kind::Miss, 0, 3.0, "");
        assert_eq!(q.enable_for(0, 1003), "查詢紀錄關閉（清掉 2 筆）");
        assert!(!q.enabled());
        let p = QueryLog::default();
        p.configure(100, true);
        assert!(p.enable_for(0, 1003).contains("常開"));
        assert!(p.enabled());
    }

    #[test]
    fn push_drops_when_locked() {
        let q = QueryLog::default();
        q.configure(10, true);
        let g = q.ring.lock().unwrap();
        q.push(100, "a.example.com", 1, ip(2), Kind::Miss, 0, 1.0, "");
        drop(g);
        assert_eq!(q.status(100)["dropped"], 1, "拿不到鎖：丟掉、不等");
        assert_eq!(q.status(100)["size"], 0);
    }

    #[test]
    fn read_limit_and_filters() {
        let q = QueryLog::default();
        q.configure(2000, true);
        for i in 0..1500u32 {
            q.push(
                i,
                if i % 2 == 0 { "even.example.com" } else { "odd.example.net" },
                1,
                ip((i % 3) as u8),
                Kind::Miss,
                0,
                1.0,
                "",
            );
        }
        assert_eq!(
            q.read(2000, 5000, None, None, None)["entries"].as_array().unwrap().len(),
            READ_MAX,
            "最多 1,000 筆"
        );
        let e = q.read(2000, 1000, Some("Odd.Example.Net."), None, None);
        assert!(e["entries"].as_array().unwrap().iter().all(|x| x["name"] == "odd.example.net"));
        let e = q.read(2000, 1000, None, Some(ip(1)), None);
        assert!(e["entries"].as_array().unwrap().iter().all(|x| x["client"] == "192.168.1.1"));
        let e = q.read(2000, 1000, None, None, Some(1490));
        assert_eq!(e["entries"].as_array().unwrap().len(), 10);
    }

    #[test]
    fn release_frees_and_stops() {
        let q = QueryLog::default();
        q.configure(100, true);
        assert_eq!(q.release(), (100 * REC_BYTES) as u64);
        assert!(!q.enabled());
        q.push(1, "a.example.com", 1, ip(2), Kind::Miss, 0, 1.0, "");
        assert_eq!(q.status(1)["size"], 0);
    }

    #[test]
    fn capacity_shrinks_on_small_memory() {
        const MB: u64 = 1024 * 1024;
        assert_eq!(capacity_for(20_000, Some(128 * MB)), 1_000);
        assert_eq!(capacity_for(20_000, Some(256 * MB)), 5_000);
        assert_eq!(capacity_for(20_000, Some(2048 * MB)), 20_000);
        assert_eq!(capacity_for(20_000, None), 20_000);
        assert_eq!(capacity_for(500, Some(128 * MB)), 500);
    }
}
