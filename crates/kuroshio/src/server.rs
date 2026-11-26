//! 區網 DNS 監聽（UDP / TCP）與轉發。
//!
//! 查詢交給 `Resolver`（過濾、快取、並行上游、IP 測速）。

use crate::acl::Acl;
use crate::ipfilter::Kind;
use crate::resolver::{Ctx, Resolver};
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, info};

pub struct Server {
    pub resolver: Arc<Resolver>,
    pub acl: Arc<Acl>,
}

/// 重新載入時交出 DNS 快取之前，先等處理中的查詢做完最多這麼久（規格 10 第 7.3 節）。
/// 這段時間監聽已經停下來，新的封包留在核心的接收緩衝區、TCP 連線留在 accept 佇列，給新的一輪
pub const QUIESCE_MAX: Duration = Duration::from_secs(1);

/// 剛接受、第一筆查詢還沒回完的 TCP／TLS 連線最多幾條算進「處理中」（3.5.1，[`Serving::accept`]）。
/// 超過的照以前：不算、交接時不等。連線數本身另有上限（DoT、DoH 的 `maxTlsConnections`）
pub const FRESH_MAX: u32 = 64;
/// 剛接受的連線每一個階段（連上之後送第一個位元組、TLS 握手完成之後送第一筆查詢）最多等這麼久；
/// 這段時間都沒有動靜的（預先連上、閒著的連線）就不再算進處理中，交接時不等它（3.5.1）
pub const FRESH_GRACE: Duration = Duration::from_millis(200);
/// 剛接受的 TLS 連線的握手最多算進處理中這麼久（3.5.1）：握手卡住的不讓交接等滿 [`QUIESCE_MAX`]
pub const FRESH_HANDSHAKE: Duration = Duration::from_millis(500);

/// 這一輪的監聽迴圈與處理中的查詢（3.5.1）。
///
/// 重新載入時舊的一輪要先**停止收新的查詢**、等處理中的做完，才把快取交給下一輪
/// （[`Serving::quiesce`]）。以前快取交出去之後舊的一輪還在讀同一個（`listenbank` 共用的）監聽 socket：
/// 查詢一律沒命中、改問上游；剛好碰上舊的執行環境關閉時，問上游的工作開不起來，回了 SERVFAIL；
/// 或是查詢讀進來了卻跟著執行環境一起被丟掉，用戶端要等逾時重送。
///
/// 剛接受、第一筆查詢還沒讀進來的 TCP／DoT／DoH 連線也算（[`Serving::accept`]、[`Fresh`]）：以前查詢讀完才算，
/// 「已經接受、查詢還沒到」的連線交接時看起來是 0 筆，舊的執行環境結束時連線被關掉，核心回 RST
/// （Windows 測試機重新載入 40 次裡 3 次各有 1 筆 TCP 查詢收到 10054、要重送）。
///
/// 每筆查詢多兩個 32 位元原子操作（MT7621 沒有 64 位元原子操作），不加鎖；每條 TCP／TLS 連線多幾個原子操作與一個計時器；
/// 監聽迴圈的登記只在啟動時。
#[derive(Default)]
pub struct Serving {
    /// 收查詢的迴圈（一般 DNS 的 UDP、TCP accept，DoT、DoH 的 accept）：停止時 abort
    loops: Mutex<Vec<tokio::task::AbortHandle>>,
    /// 處理中的查詢（一般 DNS：讀進來到送出回應）
    pending: AtomicU32,
    /// 剛接受、第一筆查詢還沒回完的連線（最多 [`FRESH_MAX`]）
    fresh: Arc<AtomicU32>,
    /// 快取已經交給下一輪：這一輪不再回 SERVFAIL（見 `Resolver::handle_inner`）
    retired: AtomicBool,
}

/// 一筆處理中的查詢；結束（含被取消）時減回去
pub struct Pending<'a>(&'a Serving);

/// 收的迴圈已經算進「處理中」、還沒交給處理的工作（[`Serving::track`] 接手）
#[must_use]
pub struct Entered(());

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.0.pending.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 剛接受的一條連線（3.5.1，[`Serving::accept`]）：第一筆查詢回完、某個階段等了太久沒有動靜（[`hold_while`]）、
/// 或連線結束（含工作被取消）時放掉，只放一次
pub struct Fresh {
    count: Arc<AtomicU32>,
    held: AtomicBool,
    /// 第一筆查詢已經開始處理（DoH：請求進來了）：之後階段的時間到也不放，等它回完
    started: AtomicBool,
}

impl Fresh {
    /// 還算在處理中
    pub fn held(&self) -> bool {
        self.held.load(Ordering::Relaxed)
    }

    /// 第一筆查詢開始處理
    pub fn start(&self) {
        self.started.store(true, Ordering::Relaxed);
    }

    /// 不再算進處理中（第一筆回完、閒著太久）；重複呼叫沒有作用
    pub fn release(&self) {
        if self.held.swap(false, Ordering::Relaxed) {
            self.count.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl Drop for Fresh {
    fn drop(&mut self) {
        self.release();
    }
}

/// 等 `fut` 做完；`grace` 內還沒做完、第一筆查詢也還沒開始處理，就先放掉 `fresh`（不再算進處理中），
/// 再繼續等同一個 `fut`（不取消：讀到一半的資料不會丟）。`fresh` 是 None 或已經放掉時直接等
pub async fn hold_while<F: std::future::Future>(fresh: Option<&Fresh>, grace: Duration, fut: F) -> F::Output {
    let Some(f) = fresh.filter(|f| f.held()) else {
        return fut.await;
    };
    tokio::pin!(fut);
    tokio::select! {
        biased;
        r = &mut fut => r,
        _ = tokio::time::sleep(grace) => {
            if !f.started.load(Ordering::Relaxed) {
                f.release();
            }
            fut.await
        }
    }
}

impl Serving {
    /// 登記一個收查詢的迴圈（重新載入時 [`Serving::quiesce`] 停掉它）
    pub fn add_loop(&self, h: tokio::task::AbortHandle) {
        self.loops.lock().unwrap_or_else(|e| e.into_inner()).push(h);
    }

    /// 開始處理一筆查詢（同一個工作裡處理完）
    pub fn begin(&self) -> Pending<'_> {
        self.pending.fetch_add(1, Ordering::Relaxed);
        Pending(self)
    }

    /// 收的迴圈讀到一筆查詢、交給另一個工作之前先算進處理中（不然工作還沒開始跑時 [`Serving::quiesce`] 看不到它）
    pub fn enter(&self) -> Entered {
        self.pending.fetch_add(1, Ordering::Relaxed);
        Entered(())
    }

    /// 處理的工作接手 [`Serving::enter`] 算進去的那一筆
    pub fn track(&self, _e: Entered) -> Pending<'_> {
        Pending(self)
    }

    /// 接受一條 TCP／TLS 連線：第一筆查詢回完之前算進處理中（[`Serving::quiesce`] 會等它）。
    /// accept 迴圈接到連線、交給另一個工作之前呼叫（同 [`Serving::enter`]）。已經有 [`FRESH_MAX`] 條時回 None（照以前，不等）
    pub fn accept(&self) -> Option<Fresh> {
        if self.fresh.fetch_add(1, Ordering::Relaxed) >= FRESH_MAX {
            self.fresh.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(Fresh {
            count: self.fresh.clone(),
            held: AtomicBool::new(true),
            started: AtomicBool::new(false),
        })
    }

    /// 處理中的查詢數
    pub fn pending(&self) -> u32 {
        self.pending.load(Ordering::Relaxed)
    }

    /// 剛接受、第一筆查詢還沒回完的連線數
    pub fn fresh(&self) -> u32 {
        self.fresh.load(Ordering::Relaxed)
    }

    /// 快取已經交給下一輪
    pub fn retired(&self) -> bool {
        self.retired.load(Ordering::Relaxed)
    }

    pub fn retire(&self) {
        self.retired.store(true, Ordering::Relaxed);
    }

    /// 停止收新的查詢（停在等封包、等連線的地方，不會丟掉已經讀進來的），再等處理中的查詢、剛接受的連線的第一筆
    /// 做完，最多 `max`。回傳（停掉幾個迴圈, 時間到還沒做完的查詢與剛接受的連線數）。
    /// 已經建立的 TCP／TLS 連線不在這裡斷，跟以前一樣隨執行環境結束
    pub async fn quiesce(&self, max: Duration) -> (usize, u32) {
        let loops = std::mem::take(&mut *self.loops.lock().unwrap_or_else(|e| e.into_inner()));
        for h in &loops {
            h.abort();
        }
        // 先等迴圈真的停下來（abort 只在下一個等待點生效：正在別的執行緒上把剛讀到的查詢交出去的，交完才停），
        // 再等處理中的查詢做完
        let end = Instant::now() + max;
        let busy = || self.pending() > 0 || self.fresh() > 0;
        while (loops.iter().any(|h| !h.is_finished()) || busy()) && Instant::now() < end {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        (loops.len(), self.pending() + self.fresh())
    }
}

fn bind_socket(addr: SocketAddr, ty: Type, proto: Protocol) -> std::io::Result<Socket> {
    let s = Socket::new(Domain::for_address(addr), ty, Some(proto))?;
    if addr.is_ipv6() {
        s.set_only_v6(true)?; // 0.0.0.0 與 :: 可以同時綁同一個埠
    }
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    Ok(s)
}

impl Server {
    /// `open` = 不檢查來源（綁在 ULA 上：外網連不進來，劫持來的查詢常用公網位址當來源）
    pub async fn listen(self: &Arc<Self>, addr: SocketAddr, open: bool) -> Result<Vec<SocketAddr>> {
        let (udp, tcp) = if addr.port() != 0 {
            Self::bind_banked(addr)?
        } else {
            Self::bind_pair(addr)?
        };
        let udp = UdpSocket::from_std(udp)?;
        let tcp = TcpListener::from_std(tcp)?;
        let bound = vec![udp.local_addr()?, tcp.local_addr()?];
        info!("監聽 {} (UDP/TCP)", bound[0]);
        let serving = &self.resolver.serving;
        serving.add_loop(tokio::spawn(self.clone().serve_udp(Arc::new(udp), open)).abort_handle());
        serving.add_loop(tokio::spawn(self.clone().serve_tcp(tcp, open)).abort_handle());
        Ok(bound)
    }

    /// 固定的埠：UDP 與 TCP 各自經過 `listenbank`（重新載入時沿用上一輪的核心 socket，不拒絕連線）
    fn bind_banked(addr: SocketAddr) -> Result<(std::net::UdpSocket, std::net::TcpListener)> {
        use crate::listenbank;
        let udp = listenbank::udp("plain", addr, || Ok(bind_socket(addr, Type::DGRAM, Protocol::UDP)?.into()))
            .with_context(|| format!("UDP 綁定 {addr} 失敗"))?;
        let tcp = listenbank::tcp("plain", addr, || {
            let ts = bind_socket(addr, Type::STREAM, Protocol::TCP)?;
            ts.listen(256)?; // 放進表之前就要 listen：空窗期間的連線才進得了 accept 佇列
            Ok(ts.into())
        });
        match tcp {
            Ok(tcp) => Ok((udp, tcp)),
            Err(e) => {
                // TCP 綁不起來：這個位址整個略過（同以前）。UDP 不能留著沒人讀，交給 sweep 關掉
                drop(udp);
                listenbank::unuse("plain", listenbank::Proto::Udp, addr);
                Err(anyhow::Error::from(e).context(format!("TCP 綁定 {addr} 失敗")))
            }
        }
    }

    /// port 0（測試）：直接綁定，不進 `listenbank`
    fn bind_pair(addr: SocketAddr) -> Result<(std::net::UdpSocket, std::net::TcpListener)> {
        // port 0（測試）：UDP 與 TCP 要同一個埠號。先讓其中一邊拿系統配的埠，再用同一個號碼綁另一邊；
        // 剛好被占用就換一個再試。兩種順序輪流：Windows 常把整段 TCP 埠號保留給 Hyper-V 等元件
        // （netsh int ipv4 show excludedportrange protocol=tcp），只用「UDP 先」可能連續好幾次都落在保留範圍裡
        let mut tries = if addr.port() == 0 { 32 } else { 1 };
        let mut udp_first = true;
        let (udp, ts) = loop {
            let attempt = if udp_first {
                let us = bind_socket(addr, Type::DGRAM, Protocol::UDP).with_context(|| format!("UDP 綁定 {addr} 失敗"))?;
                let port = us.local_addr()?.as_socket().map(|a| a.port()).unwrap_or(0);
                let tcp_addr = SocketAddr::new(addr.ip(), port);
                bind_socket(tcp_addr, Type::STREAM, Protocol::TCP)
                    .map(|ts| (us, ts))
                    .with_context(|| format!("TCP 綁定 {tcp_addr} 失敗"))
            } else {
                let ts = bind_socket(addr, Type::STREAM, Protocol::TCP).with_context(|| format!("TCP 綁定 {addr} 失敗"))?;
                let port = ts.local_addr()?.as_socket().map(|a| a.port()).unwrap_or(0);
                let udp_addr = SocketAddr::new(addr.ip(), port);
                bind_socket(udp_addr, Type::DGRAM, Protocol::UDP)
                    .map(|us| (us, ts))
                    .with_context(|| format!("UDP 綁定 {udp_addr} 失敗"))
            };
            match attempt {
                Ok(pair) => break pair,
                Err(e) => {
                    tries -= 1;
                    if tries == 0 {
                        return Err(e);
                    }
                    udp_first = !udp_first;
                }
            }
        };
        ts.listen(256)?;
        Ok((udp.into(), ts.into()))
    }

    async fn serve_udp(self: Arc<Self>, sock: Arc<UdpSocket>, open: bool) {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    debug!("UDP 接收錯誤：{e}");
                    continue;
                }
            };
            if !open && !(self.acl.allows(peer.ip()) && self.resolver.access_allows(Kind::Plain, peer.ip())) {
                continue; // 不在允許清單：不回應
            }
            let q = buf[..n].to_vec();
            let (me, sock) = (self.clone(), sock.clone());
            // 讀進來到送出回應都算「處理中」：重新載入時交出快取之前等它送完
            let entered = self.resolver.serving.enter();
            tokio::spawn(async move {
                let _pending = me.resolver.serving.track(entered);
                let ctx = Ctx {
                    proto: "udp",
                    client: peer.ip(),
                };
                if let Some(resp) = me.resolver.handle(&q, &ctx).await {
                    let resp = truncate_for_udp(&q, resp);
                    let _ = sock.send_to(&resp, peer).await;
                }
            });
        }
    }

    async fn serve_tcp(self: Arc<Self>, l: TcpListener, open: bool) {
        loop {
            let (s, peer) = match l.accept().await {
                Ok(x) => x,
                Err(e) => {
                    debug!("TCP accept 錯誤：{e}");
                    continue;
                }
            };
            if !open && !(self.acl.allows(peer.ip()) && self.resolver.access_allows(Kind::Plain, peer.ip())) {
                continue;
            }
            let me = self.clone();
            // 接受了就算進處理中，第一筆查詢回完才放（重新載入時交接會等它，3.5.1）
            let fresh = self.resolver.serving.accept();
            tokio::spawn(async move {
                let _ = me.tcp_conn(s, peer.ip(), fresh).await;
            });
        }
    }

    /// `fresh`：剛接受、第一筆查詢還沒回完（[`Serving::accept`]）。[`FRESH_GRACE`] 內沒送查詢的就不再算進處理中
    async fn tcp_conn(&self, mut s: TcpStream, client: std::net::IpAddr, mut fresh: Option<Fresh>) -> Result<()> {
        let ctx = Ctx { proto: "tcp", client };
        loop {
            let read = tokio::time::timeout(Duration::from_secs(10), s.read_u16());
            let len = match hold_while(fresh.as_ref(), FRESH_GRACE, read).await {
                Ok(Ok(l)) => l as usize,
                _ => return Ok(()), // 閒置逾時或對方關閉
            };
            let mut q = vec![0u8; len];
            s.read_exact(&mut q).await?;
            let _pending = self.resolver.serving.begin();
            let Some(resp) = self.resolver.handle(&q, &ctx).await else {
                return Ok(());
            };
            let mut out = Vec::with_capacity(resp.len() + 2);
            out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
            out.extend_from_slice(&resp);
            s.write_all(&out).await?;
            // 第一筆回完了：之後跟一般的連線一樣
            fresh = None;
        }
    }
}

/// UDP 回應超過用戶端能收的大小 → 只回標頭與問題並設 TC，讓用戶端改用 TCP。
/// 上限：沒有 EDNS 是 512；有 EDNS 用它宣告的大小，最多 1232（不讓回應被 IP 分片，也限制放大倍數）
fn truncate_for_udp(query: &[u8], resp: Vec<u8>) -> Vec<u8> {
    if resp.len() <= kuroshio_proto::udp_limit(query) {
        return resp;
    }
    kuroshio_proto::truncated_response(query, &resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 剛接受的連線最多算 FRESH_MAX 條；放掉只減一次（第一筆回完、時間到、連線結束可能都會放）
    #[test]
    fn fresh_is_capped_and_released_once() {
        let s = Serving::default();
        let held: Vec<Fresh> = (0..FRESH_MAX).map(|_| s.accept().unwrap()).collect();
        assert!(s.accept().is_none(), "超過上限的照以前，不算");
        assert_eq!(s.fresh(), FRESH_MAX);
        held[0].release();
        held[0].release();
        assert_eq!(s.fresh(), FRESH_MAX - 1);
        drop(held);
        assert_eq!(s.fresh(), 0);
        assert!(s.accept().is_some(), "放掉之後又可以算");
    }

    /// 時間到還沒動靜就放掉、但繼續等同一個 future；第一筆已經開始處理的不放
    #[tokio::test]
    async fn hold_while_releases_idle_connections_only() {
        let s = Serving::default();
        let f = s.accept().unwrap();
        let v = hold_while(Some(&f), Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_millis(40)).await;
            7
        })
        .await;
        assert_eq!(v, 7, "不取消原本的 future");
        assert!(!f.held() && s.fresh() == 0, "閒著太久：不再算進處理中");
        let g = s.accept().unwrap();
        g.start();
        hold_while(Some(&g), Duration::from_millis(10), tokio::time::sleep(Duration::from_millis(40))).await;
        assert!(g.held() && s.fresh() == 1, "已經開始處理：等它回完");
        let h = s.accept().unwrap();
        hold_while(Some(&h), Duration::from_millis(200), async {}).await;
        assert!(h.held(), "時間內有動靜：照樣算");
    }
}
