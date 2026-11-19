//! 區網 DNS 監聽（UDP / TCP）與轉發。
//!
//! 查詢交給 `Resolver`（過濾、快取、並行上游、IP 測速）。

use crate::acl::Acl;
use crate::ipfilter::Kind;
use crate::resolver::{Ctx, Resolver};
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, info};

pub struct Server {
    pub resolver: Arc<Resolver>,
    pub acl: Arc<Acl>,
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
        tokio::spawn(self.clone().serve_udp(Arc::new(udp), open));
        tokio::spawn(self.clone().serve_tcp(tcp, open));
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
            tokio::spawn(async move {
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
            tokio::spawn(async move {
                let _ = me.tcp_conn(s, peer.ip()).await;
            });
        }
    }

    async fn tcp_conn(&self, mut s: TcpStream, client: std::net::IpAddr) -> Result<()> {
        let ctx = Ctx { proto: "tcp", client };
        loop {
            let len = match tokio::time::timeout(Duration::from_secs(10), s.read_u16()).await {
                Ok(Ok(l)) => l as usize,
                _ => return Ok(()), // 閒置逾時或對方關閉
            };
            let mut q = vec![0u8; len];
            s.read_exact(&mut q).await?;
            let Some(resp) = self.resolver.handle(&q, &ctx).await else {
                return Ok(());
            };
            let mut out = Vec::with_capacity(resp.len() + 2);
            out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
            out.extend_from_slice(&resp);
            s.write_all(&out).await?;
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
