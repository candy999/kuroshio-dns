//! 區網 DNS 監聽（UDP / TCP）與轉發。
//!
//! 查詢交給 `Resolver`（過濾、快取、並行上游、IP 測速）。

use crate::acl::Acl;
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

fn bind_socket(addr: SocketAddr, ty: Type, proto: Protocol) -> Result<Socket> {
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
        // port 0（測試）：TCP 用 UDP 實際拿到的埠；那個 TCP 埠剛好被占用時換一個再試
        let mut tries = if addr.port() == 0 { 8 } else { 1 };
        let (udp, ts) = loop {
            let udp = UdpSocket::from_std(
                bind_socket(addr, Type::DGRAM, Protocol::UDP)
                    .with_context(|| format!("UDP 綁定 {addr} 失敗"))?
                    .into(),
            )?;
            let tcp_addr = SocketAddr::new(addr.ip(), udp.local_addr()?.port());
            match bind_socket(tcp_addr, Type::STREAM, Protocol::TCP) {
                Ok(ts) => break (udp, ts),
                Err(e) => {
                    tries -= 1;
                    if tries == 0 {
                        return Err(e.context(format!("TCP 綁定 {tcp_addr} 失敗")));
                    }
                }
            }
        };
        ts.listen(256)?;
        let tcp = TcpListener::from_std(ts.into())?;
        let bound = vec![udp.local_addr()?, tcp.local_addr()?];
        info!("監聽 {} (UDP/TCP)", bound[0]);
        tokio::spawn(self.clone().serve_udp(Arc::new(udp), open));
        tokio::spawn(self.clone().serve_tcp(tcp, open));
        Ok(bound)
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
            if !open && !self.acl.allows(peer.ip()) {
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
            if !open && !self.acl.allows(peer.ip()) {
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
