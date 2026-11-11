//! 下載過濾清單等檔案：HTTP/1.1，邊收邊交給呼叫者（不把整個檔案放進記憶體，規格 05 第 3.2 節）
//!
//! - http:// 與 https://（憑證驗證同加密上游）
//! - 轉址最多 5 次；content-length、chunked、讀到連線關閉三種長度
//! - If-None-Match / If-Modified-Since：清單沒變回 304，不必重新下載
//! - 大小上限，超過就中止

use anyhow::{anyhow, bail, Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use crate::tls::LocalBind;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Validators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// 下載完成：狀態碼、總位元組數與新的驗證資訊
    Done { status: u16, bytes: u64, validators: Validators },
    /// 304：沒有變更
    NotModified,
}

pub(crate) struct Url {
    pub(crate) tls: bool,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) path: String,
}

pub(crate) fn parse_url(u: &str) -> Result<Url> {
    let (tls, rest) = if let Some(r) = u.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = u.strip_prefix("http://") {
        (false, r)
    } else {
        bail!("只支援 http:// 與 https://：{u}");
    };
    let (auth, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match auth.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || h.ends_with(']') => {
            (h.trim_matches(|c| c == '[' || c == ']').to_string(), p.parse().context("埠號錯誤")?)
        }
        _ => (auth.trim_matches(|c| c == '[' || c == ']').to_string(), if tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        bail!("網址缺少主機：{u}");
    }
    Ok(Url {
        tls,
        host,
        port,
        path: path.to_string(),
    })
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

async fn open(u: &Url, timeout: Duration, from: Option<&LocalBind>) -> Result<Box<dyn Io>> {
    if u.tls {
        // 下載不用 h2：只提供 http/1.1 的 ALPN
        Ok(Box::new(crate::tls::connect_h1_from(&u.host, u.port, timeout, from).await?))
    } else {
        let mut ips = crate::tls::resolve_host(&u.host).await?;
        if let Some(b) = from {
            ips.retain(|ip| ip.is_ipv4() == b.ip.is_ipv4());
        }
        let mut last = anyhow!("沒有可用的位址");
        for ip in ips {
            match tokio::time::timeout(timeout, crate::tls::tcp_connect(SocketAddr::new(ip, u.port), from)).await {
                Ok(Ok(s)) => return Ok(Box::new(s)),
                Ok(Err(e)) => last = e.into(),
                Err(_) => last = anyhow!("連線逾時"),
            }
        }
        Err(last)
    }
}

async fn read(s: &mut Box<dyn Io>, tmp: &mut [u8], timeout: Duration) -> Result<usize> {
    Ok(tokio::time::timeout(timeout, s.read(tmp))
        .await
        .map_err(|_| anyhow!("讀取逾時"))??)
}

/// 請求內容（API 呼叫用；一般下載用 `get`）
#[derive(Debug, Clone, Default)]
pub struct Request<'a> {
    pub method: &'a str,
    pub headers: Vec<(String, String)>,
    pub body: Option<&'a [u8]>,
}

/// 下載 `url`，每收到一段資料就呼叫 `on_chunk`；`max` 是大小上限（位元組）
pub async fn get(url: &str, prev: &Validators, max: u64, timeout: Duration, on_chunk: impl FnMut(&[u8]) -> Result<()>) -> Result<Outcome> {
    stream(
        url,
        &Request {
            method: "GET",
            ..Default::default()
        },
        prev,
        max,
        timeout,
        false,
        None,
        None,
        on_chunk,
    )
    .await
}

/// `get_status` 的結果：狀態碼與 `Retry-After`（429 / 503 時才有意義）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub code: u16,
    pub retry_after: Option<String>,
}

/// 同 `get`，但不是 200 也不當成錯誤：回傳狀態碼與 `Retry-After`（只有 200 的內容會交給 `on_chunk`）。
/// 背景工作要自己處理 429（照對方要求的時間再試）時用
pub async fn get_status(
    url: &str,
    headers: &[(String, String)],
    max: u64,
    timeout: Duration,
    on_chunk: impl FnMut(&[u8]) -> Result<()>,
) -> Result<Status> {
    let mut st = Status {
        code: 0,
        retry_after: None,
    };
    let r = Request {
        method: "GET",
        headers: headers.to_vec(),
        body: None,
    };
    if let Outcome::Done { status, .. } = stream(url, &r, &Validators::default(), max, timeout, true, None, Some(&mut st), on_chunk).await? {
        st.code = status;
    }
    Ok(st)
}

/// 送出請求並把整個回應讀進記憶體（API 用，回應小）；任何狀態碼都回傳
pub async fn request(url: &str, req: &Request<'_>, max: u64, timeout: Duration) -> Result<(u16, Vec<u8>)> {
    request_from(url, req, max, timeout, None).await
}

/// 同 `request`，但指定從哪個本機位址 / 網卡連出去（`None` = 系統預設路由）。
/// 多出口（多網卡、多條對外線路）時，用來偵測每個出口各自的公網 IP。
pub async fn request_from(url: &str, req: &Request<'_>, max: u64, timeout: Duration, from: Option<&LocalBind>) -> Result<(u16, Vec<u8>)> {
    let mut body = Vec::new();
    match stream(url, req, &Validators::default(), max, timeout, true, from, None, |c| {
        body.extend_from_slice(c);
        Ok(())
    })
    .await?
    {
        Outcome::Done { status, .. } => Ok((status, body)),
        Outcome::NotModified => Ok((304, body)),
    }
}

#[allow(clippy::too_many_arguments)]
async fn stream(
    url: &str,
    r: &Request<'_>,
    prev: &Validators,
    max: u64,
    timeout: Duration,
    any_status: bool,
    from: Option<&LocalBind>,
    mut early: Option<&mut Status>,
    mut on_chunk: impl FnMut(&[u8]) -> Result<()>,
) -> Result<Outcome> {
    let mut url = url.to_string();
    for _ in 0..6 {
        let u = parse_url(&url)?;
        let mut s = open(&u, timeout, from).await?;
        let mut req = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: kuroshio/{}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
            r.method,
            u.path,
            u.host,
            env!("CARGO_PKG_VERSION")
        );
        for (k, v) in &r.headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        if let Some(b) = r.body {
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        if let Some(e) = &prev.etag {
            req.push_str(&format!("If-None-Match: {e}\r\n"));
        }
        if let Some(m) = &prev.last_modified {
            req.push_str(&format!("If-Modified-Since: {m}\r\n"));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).await?;
        if let Some(b) = r.body {
            s.write_all(b).await?;
        }

        // 標頭
        let mut buf = Vec::with_capacity(8192);
        let mut tmp = vec![0u8; 16384];
        let end = loop {
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p + 4;
            }
            if buf.len() > 65536 {
                bail!("標頭太大");
            }
            let n = tokio::time::timeout(timeout, s.read(&mut tmp))
                .await
                .map_err(|_| anyhow!("讀取逾時"))??;
            if n == 0 {
                bail!("連線在標頭前被關閉");
            }
            buf.extend_from_slice(&tmp[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..end]).to_string();
        let status: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
        let header = |name: &str| {
            head.lines().skip(1).find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
            })
        };
        match status {
            301 | 302 | 303 | 307 | 308 if r.method == "GET" => {
                let loc = header("location").ok_or_else(|| anyhow!("轉址沒有 Location"))?;
                url = if loc.starts_with("http://") || loc.starts_with("https://") {
                    loc
                } else if loc.starts_with('/') {
                    format!("{}://{}:{}{loc}", if u.tls { "https" } else { "http" }, u.host, u.port)
                } else {
                    bail!("不支援的轉址：{loc}");
                };
                continue;
            }
            304 => return Ok(Outcome::NotModified),
            200 => {}
            // `get_status`：不是 200 就不讀內容，把狀態碼與 Retry-After 交回去
            _ if early.is_some() => {
                if let Some(st) = early.as_deref_mut() {
                    st.retry_after = header("retry-after");
                }
                return Ok(Outcome::Done {
                    status,
                    bytes: 0,
                    validators: Validators::default(),
                });
            }
            _ if any_status => {}
            _ => bail!("HTTP {status}"),
        }
        let validators = Validators {
            etag: header("etag"),
            last_modified: header("last-modified"),
        };
        let mut rest = buf[end..].to_vec();
        let mut total: u64 = 0;
        let mut emit = |d: &[u8], total: &mut u64| -> Result<()> {
            *total += d.len() as u64;
            if *total > max {
                bail!("檔案超過上限 {} MB", max / 1_048_576);
            }
            on_chunk(d)
        };
        if header("transfer-encoding")
            .map(|v| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false)
        {
            loop {
                while !rest.windows(2).any(|w| w == b"\r\n") {
                    let n = read(&mut s, &mut tmp, timeout).await?;
                    if n == 0 {
                        bail!("chunk 不完整");
                    }
                    rest.extend_from_slice(&tmp[..n]);
                }
                let p = rest.windows(2).position(|w| w == b"\r\n").unwrap();
                let size = usize::from_str_radix(String::from_utf8_lossy(&rest[..p]).split(';').next().unwrap_or("").trim(), 16)
                    .context("chunk 長度錯誤")?;
                rest.drain(..p + 2);
                if size == 0 {
                    break;
                }
                let mut left = size;
                loop {
                    let take = left.min(rest.len());
                    if take > 0 {
                        emit(&rest[..take], &mut total)?;
                        rest.drain(..take);
                        left -= take;
                    }
                    if left == 0 {
                        break;
                    }
                    let n = read(&mut s, &mut tmp, timeout).await?;
                    if n == 0 {
                        bail!("chunk 不完整");
                    }
                    rest.extend_from_slice(&tmp[..n]);
                }
                while rest.len() < 2 {
                    let n = read(&mut s, &mut tmp, timeout).await?;
                    if n == 0 {
                        bail!("chunk 不完整");
                    }
                    rest.extend_from_slice(&tmp[..n]);
                }
                rest.drain(..2);
            }
        } else {
            let len = header("content-length").and_then(|v| v.parse::<u64>().ok());
            if !rest.is_empty() {
                emit(&rest, &mut total)?;
            }
            loop {
                if len.map(|l| total >= l).unwrap_or(false) {
                    break;
                }
                let n = read(&mut s, &mut tmp, timeout).await?;
                if n == 0 {
                    if let Some(l) = len {
                        if total < l {
                            bail!("下載不完整（{total} / {l}）");
                        }
                    }
                    break;
                }
                emit(&tmp[..n], &mut total)?;
            }
        }
        return Ok(Outcome::Done {
            status,
            bytes: total,
            validators,
        });
    }
    bail!("轉址太多次")
}

/// 現在時間（Unix 毫秒），狀態 JSON 用
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_url("https://raw.githubusercontent.com/a/b/main/list.txt").unwrap();
        assert!(u.tls);
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("raw.githubusercontent.com", 443, "/a/b/main/list.txt")
        );
        let u = parse_url("http://127.0.0.1:8080").unwrap();
        assert_eq!((u.port, u.path.as_str()), (8080, "/"));
        let u = parse_url("http://[::1]:81/x").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 81));
        assert!(parse_url("ftp://x").is_err());
    }
}
