//! QUIC 上游（規格 01 第 1.2 節）：DoQ（RFC 9250，UDP 853，ALPN `doq`）與 DoH3（RFC 8484 over HTTP/3，ALPN `h3`）
//!
//! - 每個上游一條持久 QUIC 連線，每筆查詢一條串流（多工，不會互相卡住）
//! - 連線斷掉就重新連線再試一次
//! - 用戶端端點（UDP socket）IPv4 / IPv6 各一個，全部上游共用

use crate::tls::{client_config, resolve_host};
use anyhow::{anyhow, bail, Context, Result};
use bytes::{Buf, Bytes};
use quinn::crypto::rustls::QuicClientConfig;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tracing::debug;

type Endpoints = Mutex<(Option<quinn::Endpoint>, Option<quinn::Endpoint>)>;

fn endpoints() -> &'static Endpoints {
    static E: OnceLock<Endpoints> = OnceLock::new();
    E.get_or_init(|| Mutex::new((None, None)))
}

/// 用戶端端點（依位址家族共用）
fn endpoint(v6: bool) -> Result<quinn::Endpoint> {
    let mut e = endpoints().lock().unwrap();
    let slot = if v6 { &mut e.1 } else { &mut e.0 };
    if let Some(ep) = slot {
        return Ok(ep.clone());
    }
    let bind: SocketAddr = if v6 { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let ep = quinn::Endpoint::client(bind).context("建立 QUIC 端點失敗")?;
    *slot = Some(ep.clone());
    Ok(ep)
}

fn quic_config(alpn: &[u8]) -> Result<quinn::ClientConfig> {
    let tls = client_config(&[alpn]);
    let mut c = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).map_err(|e| anyhow!("QUIC TLS 設定：{e}"))?,
    ));
    let mut t = quinn::TransportConfig::default();
    // 閒置 30 秒關閉；每 10 秒送 keep-alive，避免 NAT 對應表過期
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    t.keep_alive_interval(Some(Duration::from_secs(10)));
    c.transport_config(Arc::new(t));
    Ok(c)
}

async fn connect(host: &str, port: u16, alpn: &[u8], timeout: Duration) -> Result<quinn::Connection> {
    let ips = resolve_host(host).await?;
    let cfg = quic_config(alpn)?;
    let sni = host.trim_matches(|c| c == '[' || c == ']');
    let mut last = anyhow!("沒有可用的位址");
    for ip in ips {
        let ep = endpoint(matches!(ip, IpAddr::V6(_)))?;
        let r = async {
            let connecting = ep.connect_with(cfg.clone(), SocketAddr::new(ip, port), sni)?;
            Ok::<_, anyhow::Error>(connecting.await?)
        };
        match tokio::time::timeout(timeout, r).await {
            Ok(Ok(c)) => return Ok(c),
            Ok(Err(e)) => last = e,
            Err(_) => last = anyhow!("QUIC 連線逾時 {ip}:{port}"),
        }
    }
    Err(last)
}

/// 指定位址建立 QUIC 連線（呼叫者自己解析主機名稱），SNI 與憑證驗證一律用 `host`；社群共享（ALPN `kuroshio/2`）用
pub async fn connect_addrs(host: &str, addrs: &[SocketAddr], alpn: &[u8], timeout: Duration) -> Result<quinn::Connection> {
    let cfg = quic_config(alpn)?;
    let sni = host.trim_matches(|c| c == '[' || c == ']');
    let mut last = anyhow!("沒有可用的位址");
    for addr in addrs {
        let ep = endpoint(addr.is_ipv6())?;
        let r = async {
            let connecting = ep.connect_with(cfg.clone(), *addr, sni)?;
            Ok::<_, anyhow::Error>(connecting.await?)
        };
        match tokio::time::timeout(timeout, r).await {
            Ok(Ok(c)) => return Ok(c),
            Ok(Err(e)) => last = e,
            Err(_) => last = anyhow!("QUIC 連線逾時 {addr}"),
        }
    }
    Err(last)
}

// ---------------- DoQ ----------------

#[derive(Default)]
pub struct Doq {
    conn: tokio::sync::Mutex<Option<quinn::Connection>>,
}

impl Doq {
    async fn get(&self, host: &str, port: u16, timeout: Duration, fresh: bool) -> Result<quinn::Connection> {
        let mut slot = self.conn.lock().await;
        if !fresh {
            if let Some(c) = slot.as_ref().filter(|c| c.close_reason().is_none()) {
                return Ok(c.clone());
            }
        }
        let c = connect(host, port, b"doq", timeout).await?;
        *slot = Some(c.clone());
        Ok(c)
    }

    /// 一筆查詢一條雙向串流：2 bytes 長度 + 訊息（id 必須是 0），送完關閉送出端
    pub async fn exchange(&self, host: &str, port: u16, q: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        let orig = [q[0], q[1]];
        let mut msg = (q.len() as u16).to_be_bytes().to_vec();
        msg.extend_from_slice(q);
        msg[2..4].copy_from_slice(&[0, 0]);
        let mut last = anyhow!("DoQ 失敗");
        for attempt in 0..2 {
            let conn = self.get(host, port, timeout, attempt > 0).await?;
            let r = tokio::time::timeout(timeout, async {
                let (mut send, mut recv) = conn.open_bi().await?;
                send.write_all(&msg).await?;
                send.finish()?;
                let buf = recv.read_to_end(65537).await?;
                Ok::<_, anyhow::Error>(buf)
            })
            .await;
            match r {
                Ok(Ok(buf)) if buf.len() >= 14 => {
                    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    if buf.len() < 2 + len {
                        bail!("DoQ 回應不完整");
                    }
                    let mut resp = buf[2..2 + len].to_vec();
                    resp[..2].copy_from_slice(&orig);
                    return Ok(resp);
                }
                Ok(Ok(_)) => bail!("DoQ 回應太短"),
                Ok(Err(e)) => {
                    debug!("DoQ {host} 失敗，重新連線：{e}");
                    last = e;
                }
                Err(_) => bail!("DoQ 逾時"),
            }
        }
        Err(last)
    }
}

// ---------------- DoH3 ----------------

type H3Send = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

#[derive(Default)]
pub struct Doh3 {
    send: tokio::sync::Mutex<Option<(H3Send, quinn::Connection)>>,
}

impl Doh3 {
    async fn get(&self, host: &str, port: u16, timeout: Duration, fresh: bool) -> Result<H3Send> {
        let mut slot = self.send.lock().await;
        if !fresh {
            if let Some((s, c)) = slot.as_ref() {
                if c.close_reason().is_none() {
                    return Ok(s.clone());
                }
            }
        }
        let conn = connect(host, port, b"h3", timeout).await?;
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .map_err(|e| anyhow!("HTTP/3 握手失敗：{e}"))?;
        tokio::spawn(async move {
            let e = driver.wait_idle().await;
            debug!("DoH3 連線結束：{e}");
        });
        *slot = Some((send.clone(), conn));
        Ok(send)
    }

    pub async fn exchange(&self, host: &str, port: u16, path: &str, q: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        let orig = [q[0], q[1]];
        let mut body = q.to_vec();
        body[..2].copy_from_slice(&[0, 0]);
        let body = Bytes::from(body);
        let authority = if port == 443 { host.to_string() } else { format!("{host}:{port}") };
        let mut last = anyhow!("DoH3 失敗");
        for attempt in 0..2 {
            let mut send = self.get(host, port, timeout, attempt > 0).await?;
            let r = tokio::time::timeout(timeout, async {
                let req = http::Request::builder()
                    .method("POST")
                    .uri(format!("https://{authority}{path}"))
                    .header("content-type", "application/dns-message")
                    .header("accept", "application/dns-message")
                    .body(())?;
                let mut stream = send.send_request(req).await?;
                stream.send_data(body.clone()).await?;
                stream.finish().await?;
                let resp = stream.recv_response().await?;
                if resp.status() != 200 {
                    bail!("DoH3 HTTP {}", resp.status());
                }
                let mut out = Vec::new();
                while let Some(mut chunk) = stream.recv_data().await? {
                    let n = chunk.remaining();
                    out.extend_from_slice(&chunk.copy_to_bytes(n));
                    if out.len() > 65535 {
                        bail!("DoH3 回應太大");
                    }
                }
                Ok::<_, anyhow::Error>(out)
            })
            .await;
            match r {
                Ok(Ok(mut resp)) if resp.len() >= 12 => {
                    resp[..2].copy_from_slice(&orig);
                    return Ok(resp);
                }
                Ok(Ok(_)) => bail!("DoH3 回應太短"),
                Ok(Err(e)) => {
                    debug!("DoH3 {host} 失敗，重新連線：{e}");
                    last = e;
                }
                Err(_) => bail!("DoH3 逾時"),
            }
        }
        Err(last)
    }
}
