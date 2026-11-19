//! 監聽 socket 留在行程層級（規格 10 第 7 節，`ListenBank`）。
//!
//! 重新載入時舊的一輪（自己的 tokio runtime）要完全結束才建新的一輪，中間有 0.2～0.4 秒沒有人在聽。
//! 以前監聽 socket 跟著舊的一輪一起關掉，這段時間用戶端看到的是 Connection refused。
//! 現在監聽 socket 放在這張行程層級的表裡（做法同 `app.rs` 的 `CACHE_HANDOFF`），每一輪拿的是
//! `try_clone()`（`dup`）的複製品：舊的一輪結束只關掉自己的複製品，核心裡的 socket 一直開著，
//! 空窗期間的 UDP 封包留在接收緩衝區、TCP 連線留在 accept 佇列，新的一輪接手後照常回答。
//!
//! - 每一輪 `start()` 開頭 `begin()`，全部監聽建立之後 `sweep()`：這一輪沒有人拿的（設定改了位址、埠，
//!   或關掉了某個協定）才關掉。啟動失敗時不 sweep，下一輪還用得到。
//! - 埠是 0 的（測試）不進表，直接綁定。
//! - 不用 `SO_REUSEPORT`，也不會讓兩輪同時存在。

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::{LazyLock, Mutex};
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Udp,
    Tcp,
}

impl Proto {
    fn name(self) -> &'static str {
        match self {
            Proto::Udp => "UDP",
            Proto::Tcp => "TCP",
        }
    }
}

enum Sock {
    Udp(UdpSocket),
    Tcp(TcpListener),
}

impl Sock {
    /// 複製品（同一個核心 socket）。非阻塞模式在每個複製品上都再設一次（Windows 不保證會帶過去）
    fn try_clone(&self) -> io::Result<Sock> {
        Ok(match self {
            Sock::Udp(s) => {
                let c = s.try_clone()?;
                c.set_nonblocking(true)?;
                Sock::Udp(c)
            }
            Sock::Tcp(s) => {
                let c = s.try_clone()?;
                c.set_nonblocking(true)?;
                Sock::Tcp(c)
            }
        })
    }
}

/// 鍵：（用途, 協定, 位址）
type Key = (&'static str, Proto, SocketAddr);

struct Entry {
    sock: Sock,
    /// 這一輪有人拿過
    used: bool,
}

/// 表本身（測試可以各自建一張，不跟執行中的服務共用）
#[derive(Default)]
pub(crate) struct Bank {
    map: HashMap<Key, Entry>,
}

impl Bank {
    fn take(&mut self, key: Key, mut bind: impl FnMut() -> io::Result<Sock>) -> io::Result<Sock> {
        // port 0（測試）：每次都要新的埠，不進表
        if key.2.port() == 0 {
            return bind();
        }
        if let Some(e) = self.map.get_mut(&key) {
            // 同一輪重複要同一個位址（設定裡寫了兩次）：照舊直接綁定，結果跟以前一樣（TCP 會綁定失敗）
            if e.used {
                return bind();
            }
            match e.sock.try_clone() {
                Ok(c) => {
                    e.used = true;
                    return Ok(c);
                }
                Err(err) => {
                    warn!("{} {} 的監聽 socket 複製失敗：{err}；關掉舊的、重新綁定", key.1.name(), key.2);
                    self.map.remove(&key);
                }
            }
        }
        let sock = match bind() {
            // 上一輪留著、這一輪還沒人要的監聽擋住了新的位址（例如 0.0.0.0 改成 192.168.1.1、
            // 同一個埠換了用途）：先關掉它們再綁一次。以前舊的一輪結束時就關了，結果相同
            Err(e) if e.kind() == io::ErrorKind::AddrInUse && self.release_conflicts(&key) > 0 => bind()?,
            r => r?,
        };
        match sock.try_clone() {
            Ok(c) => {
                self.map.insert(key, Entry { sock, used: true });
                Ok(c)
            }
            // 複製不了：不進表，等同以前的行為（重新載入時會短暫拒絕連線）
            Err(err) => {
                warn!(
                    "{} {} 的監聽 socket 複製失敗：{err}；這個監聽重新載入時會短暫中斷",
                    key.1.name(),
                    key.2
                );
                Ok(sock)
            }
        }
    }

    /// 關掉這一輪還沒人要、而且跟 `key` 衝突（同協定、同埠、同一族，位址相同或其中一邊是萬用位址）的項目
    fn release_conflicts(&mut self, key: &Key) -> usize {
        let (_, proto, addr) = *key;
        let before = self.map.len();
        self.map.retain(|(_, p, a), e| {
            let overlap = a.ip() == addr.ip() || (a.is_ipv4() == addr.is_ipv4() && (a.ip().is_unspecified() || addr.ip().is_unspecified()));
            e.used || *p != proto || a.port() != addr.port() || !overlap
        });
        let n = before - self.map.len();
        if n > 0 {
            info!("{} {addr} 跟上一輪留著的監聽衝突：先關掉上一輪的 {n} 個再綁定", proto.name());
        }
        n
    }

    fn begin(&mut self) {
        for e in self.map.values_mut() {
            e.used = false;
        }
    }

    fn sweep(&mut self) -> usize {
        let before = self.map.len();
        self.map.retain(|(tag, p, a), e| {
            if !e.used {
                info!("關掉上一輪的監聽 {tag} {} {a}（新設定沒有用到）", p.name());
            }
            e.used
        });
        before - self.map.len()
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

static BANK: LazyLock<Mutex<Bank>> = LazyLock::new(Default::default);

fn bank() -> std::sync::MutexGuard<'static, Bank> {
    BANK.lock().unwrap_or_else(|e| e.into_inner())
}

/// 拿這個位址的 UDP 監聽 socket 的複製品；沒有就用 `bind` 綁一個、留一份在表裡。port 0 不進表（直接綁）
pub fn udp(tag: &'static str, addr: SocketAddr, mut bind: impl FnMut() -> io::Result<UdpSocket>) -> io::Result<UdpSocket> {
    match bank().take((tag, Proto::Udp, addr), || bind().map(Sock::Udp))? {
        Sock::Udp(s) => Ok(s),
        Sock::Tcp(_) => unreachable!("UDP 的鍵只會放 UDP socket"),
    }
}

/// 拿這個位址的 TCP 監聽 socket 的複製品（`bind` 要已經 `listen`）；沒有就綁一個、留一份在表裡。port 0 不進表
pub fn tcp(tag: &'static str, addr: SocketAddr, mut bind: impl FnMut() -> io::Result<TcpListener>) -> io::Result<TcpListener> {
    match bank().take((tag, Proto::Tcp, addr), || bind().map(Sock::Tcp))? {
        Sock::Tcp(s) => Ok(s),
        Sock::Udp(_) => unreachable!("TCP 的鍵只會放 TCP socket"),
    }
}

/// 表裡有沒有這個埠的 TCP 監聽（自己上一輪留著的）
/// （Windows 的 DoH auto 模式偵測「埠被 IIS 占用」時，不能把自己上一輪留著的監聽當成別人的）
pub fn holds_tcp_port(port: u16) -> bool {
    bank().map.keys().any(|(_, p, a)| *p == Proto::Tcp && a.port() == port)
}

/// 關掉這一輪還沒人拿、這個協定與埠的監聽（交給別的元件，例如 Windows 的 HTTP.sys），回傳關掉幾個
pub fn release_unused(proto: Proto, port: u16) -> usize {
    let mut b = bank();
    let before = b.map.len();
    b.map.retain(|(_, p, a), e| e.used || *p != proto || a.port() != port);
    before - b.map.len()
}

/// 拿了但用不上（例如同一個位址的 TCP 綁不起來，整個位址略過）：記成這一輪沒用到，`sweep` 時關掉
pub fn unuse(tag: &'static str, proto: Proto, addr: SocketAddr) {
    if let Some(e) = bank().map.get_mut(&(tag, proto, addr)) {
        e.used = false;
    }
}

/// 新的一輪開始：把「這一輪用過」的記號清掉
pub fn begin() {
    bank().begin()
}

/// 新的一輪啟動完成：關掉這一輪沒有人拿的，回傳關掉幾個
pub fn sweep() -> usize {
    bank().sweep()
}

pub fn len() -> usize {
    bank().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_bind(addr: SocketAddr) -> io::Result<Sock> {
        let s = UdpSocket::bind(addr)?;
        s.set_nonblocking(true)?;
        Ok(Sock::Udp(s))
    }

    fn tcp_bind(addr: SocketAddr) -> io::Result<Sock> {
        // std 的 bind 已經 listen
        let s = TcpListener::bind(addr)?;
        s.set_nonblocking(true)?;
        Ok(Sock::Tcp(s))
    }

    fn local(s: &Sock) -> SocketAddr {
        match s {
            Sock::Udp(s) => s.local_addr().unwrap(),
            Sock::Tcp(s) => s.local_addr().unwrap(),
        }
    }

    /// 拿一個目前沒人用的埠（UDP 與 TCP 都空著）
    fn free_port() -> u16 {
        loop {
            let t = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = t.local_addr().unwrap().port();
            if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
                return port;
            }
        }
    }

    #[test]
    fn bank_reuses_and_sweeps() {
        let mut b = Bank::default();
        let port = free_port();
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();

        // 第一輪：綁定、留一份在表裡
        b.begin();
        let mut binds = 0;
        let u1 = b
            .take(("plain", Proto::Udp, addr), || {
                binds += 1;
                udp_bind(addr)
            })
            .unwrap();
        let t1 = b.take(("plain", Proto::Tcp, addr), || tcp_bind(addr)).unwrap();
        assert_eq!(binds, 1);
        assert_eq!(b.len(), 2);
        assert_eq!(b.sweep(), 0, "這一輪都用到了");
        // 舊的一輪結束：只關掉自己的複製品
        drop((u1, t1));
        // 核心裡的 socket 還開著：TCP 連得上（進 accept 佇列），埠也還被占著
        std::net::TcpStream::connect(addr).expect("空窗期間 TCP 不拒絕連線");
        assert!(UdpSocket::bind(addr).is_err(), "UDP 埠還在表裡");

        // 第二輪：同一個鍵拿到的是同一個核心 socket（本機位址相同），不再綁定
        b.begin();
        let u2 = b
            .take(("plain", Proto::Udp, addr), || {
                binds += 1;
                udp_bind(addr)
            })
            .unwrap();
        assert_eq!(binds, 1, "沿用表裡的，不重新綁定");
        assert_eq!(local(&u2), addr);
        // 同一個核心 socket：從外面送的封包，第二輪的複製品收得到（第一輪結束後才送也一樣）
        let c = UdpSocket::bind("127.0.0.1:0").unwrap();
        c.send_to(b"ping", addr).unwrap();
        let Sock::Udp(u2s) = &u2 else { unreachable!() };
        u2s.set_nonblocking(false).unwrap();
        u2s.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(u2s.recv_from(&mut buf).unwrap().0, 4);
        // 同一輪重複要同一個位址：照舊直接綁定（UDP 沒設 SO_REUSEADDR → 失敗），不給第二個複製品
        assert!(b.take(("plain", Proto::Udp, addr), || udp_bind(addr)).is_err());

        // 這一輪沒有人拿 TCP：sweep 關掉，埠可以重新綁定
        assert_eq!(b.sweep(), 1);
        assert_eq!(b.len(), 1);
        TcpListener::bind(addr).expect("sweep 後 TCP 埠可以重新綁定");

        // 下一輪都沒人拿：全部關掉，表不會一直長大
        drop(u2);
        b.begin();
        assert_eq!(b.sweep(), 1);
        assert_eq!(b.len(), 0);
        UdpSocket::bind(addr).expect("sweep 後 UDP 埠可以重新綁定");

        // port 0 不進表：每次都直接綁定
        let zero: SocketAddr = ([127, 0, 0, 1], 0).into();
        let z1 = b.take(("plain", Proto::Udp, zero), || udp_bind(zero)).unwrap();
        let z2 = b.take(("plain", Proto::Udp, zero), || udp_bind(zero)).unwrap();
        assert_ne!(local(&z1), local(&z2));
        assert_eq!(b.len(), 0, "port 0 不進表");
    }

    /// 上一輪留著的監聽擋住新的位址（同一個埠換了用途）：先關掉舊的再綁
    #[test]
    fn conflicting_leftover_is_released() {
        let mut b = Bank::default();
        let port = free_port();
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        b.begin();
        drop(b.take(("doh", Proto::Tcp, addr), || tcp_bind(addr)).unwrap());
        b.begin();
        let t = b.take(("dot", Proto::Tcp, addr), || tcp_bind(addr)).expect("換用途：關掉舊的再綁");
        assert_eq!(local(&t), addr);
        assert_eq!(b.len(), 1);
        assert_eq!(b.sweep(), 0);
        // 這一輪已經用到的不會被讓出去
        let other: SocketAddr = ([127, 0, 0, 1], port).into();
        assert!(b.take(("doh", Proto::Tcp, other), || tcp_bind(other)).is_err());
        assert_eq!(b.len(), 1);
    }
}
