//! 效能計數器（3.5.0，規格 11 C12）：找出 MT7621 這類沒有 AES 指令的機器在單獨運作時 CPU 花在哪裡。
//!
//! 只在本來就慢的地方累加（TLS／QUIC 握手完成、連線失敗），每次一個 `AtomicU32::fetch_add(Relaxed)`；
//! 32 位元的機器沒有 64 位元原子操作，計數器溢位就從 0 重來（每天幾千次握手，要很多年才會發生）。
//! 不在每筆查詢都會走到的路徑上加鎖或配置。

use serde_json::{json, Value};
use std::sync::atomic::{AtomicU32, Ordering};

/// 一種加密上游協定（DoT、DoH）的握手統計
pub struct Tls {
    /// 完整握手（沒有續用 session）
    pub full: AtomicU32,
    /// 用 TLS session resumption 續用，少一次完整握手
    pub resumed: AtomicU32,
    /// 協商到 AES-GCM（沒有 AES 指令時加解密慢）
    pub aes: AtomicU32,
    /// 協商到 ChaCha20-Poly1305（沒有 AES 指令時比較快）
    pub chacha: AtomicU32,
    /// 連線或握手失敗
    pub fail: AtomicU32,
}

impl Tls {
    const fn new() -> Tls {
        Tls {
            full: AtomicU32::new(0),
            resumed: AtomicU32::new(0),
            aes: AtomicU32::new(0),
            chacha: AtomicU32::new(0),
            fail: AtomicU32::new(0),
        }
    }

    /// 握手完成：完整還是續用、協商到哪一種密碼套件
    pub fn handshake(&self, resumed: bool, suite: Option<rustls::CipherSuite>) {
        let n = if resumed { &self.resumed } else { &self.full };
        n.fetch_add(1, Ordering::Relaxed);
        match suite.map(suite_kind) {
            Some(SuiteKind::Aes) => {
                self.aes.fetch_add(1, Ordering::Relaxed);
            }
            Some(SuiteKind::ChaCha) => {
                self.chacha.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn failed(&self) {
        self.fail.fetch_add(1, Ordering::Relaxed);
    }

    fn json(&self) -> Value {
        let g = |a: &AtomicU32| a.load(Ordering::Relaxed);
        json!({ "full": g(&self.full), "resumed": g(&self.resumed), "aes": g(&self.aes), "chacha": g(&self.chacha), "fail": g(&self.fail) })
    }
}

#[derive(Debug, PartialEq, Eq)]
enum SuiteKind {
    Aes,
    ChaCha,
    Other,
}

fn suite_kind(s: rustls::CipherSuite) -> SuiteKind {
    let name = format!("{s:?}");
    if name.contains("CHACHA20") {
        SuiteKind::ChaCha
    } else if name.contains("AES") {
        SuiteKind::Aes
    } else {
        SuiteKind::Other
    }
}

/// DoT 上游的握手
pub static DOT: Tls = Tls::new();
/// DoH（HTTP/2）上游的握手
pub static DOH: Tls = Tls::new();
/// QUIC（DoQ、DoH3）上游：建立的連線數、失敗數（QUIC 的握手在 quinn 裡，這裡只數連線）
pub static QUIC_NEW: AtomicU32 = AtomicU32::new(0);
pub static QUIC_FAIL: AtomicU32 = AtomicU32::new(0);
/// 目前開著的 QUIC 上游連線數（3.5.0 F4）：`connect()` 成功 +1、連線結束（被關閉、閒置逾時、不再使用）−1。
/// `new` 是新建的連線數；連線每 10 秒送 keep-alive、會重複使用很久，所以壓測前後 `new` 的差可能是 0
pub static QUIC_OPEN: AtomicU32 = AtomicU32::new(0);

/// `/api/status` 的 `perf.tls`
pub fn json() -> Value {
    json!({
        "dot": DOT.json(),
        "doh": DOH.json(),
        "quic": { "new": QUIC_NEW.load(Ordering::Relaxed), "fail": QUIC_FAIL.load(Ordering::Relaxed),
                  "open": QUIC_OPEN.load(Ordering::Relaxed) },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_classification() {
        assert_eq!(suite_kind(rustls::CipherSuite::TLS13_AES_128_GCM_SHA256), SuiteKind::Aes);
        assert_eq!(suite_kind(rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256), SuiteKind::ChaCha);
        assert_eq!(
            suite_kind(rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
            SuiteKind::ChaCha
        );
        let t = Tls::new();
        t.handshake(false, Some(rustls::CipherSuite::TLS13_AES_256_GCM_SHA384));
        t.handshake(true, Some(rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256));
        t.failed();
        assert_eq!(t.json(), json!({ "full": 1, "resumed": 1, "aes": 1, "chacha": 1, "fail": 1 }));
    }
}
