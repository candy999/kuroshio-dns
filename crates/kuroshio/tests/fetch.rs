//! 清單下載：content-length、chunked、轉址、304、大小上限、邊收邊處理

use kuroshio::fetch::{get, Outcome, Validators};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// 小型 HTTP 伺服器：依路徑回不同內容
async fn server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut b = [0u8; 1];
                while !buf.ends_with(b"\r\n\r\n") {
                    if s.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    buf.push(b[0]);
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let path = head.split_whitespace().nth(1).unwrap().to_string();
                let body = "||ads.example^\n||track.example^\n".repeat(1000);
                let resp: Vec<u8> = match path.as_str() {
                    "/plain" => format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"v1\"\r\n\r\n{body}", body.len()).into_bytes(),
                    "/chunked" => {
                        let mut o = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
                        for part in body.as_bytes().chunks(777) {
                            o.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
                            o.extend_from_slice(part);
                            o.extend_from_slice(b"\r\n");
                        }
                        o.extend_from_slice(b"0\r\n\r\n");
                        o
                    }
                    "/moved" => b"HTTP/1.1 302 Found\r\nLocation: /plain\r\nContent-Length: 0\r\n\r\n".to_vec(),
                    "/close" => format!("HTTP/1.1 200 OK\r\n\r\n{body}").into_bytes(),
                    _ if head.contains("If-None-Match: \"v1\"") => b"HTTP/1.1 304 Not Modified\r\n\r\n".to_vec(),
                    "/etag" => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nETag: \"v1\"\r\n\r\nok".to_vec(),
                    _ => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
                };
                // 分小段寫，模擬慢速網路
                for part in resp.chunks(1000) {
                    if s.write_all(part).await.is_err() {
                        return;
                    }
                }
                s.shutdown().await.ok();
            });
        }
    });
    addr
}

async fn fetch(url: String, max: u64) -> (anyhow::Result<Outcome>, Vec<u8>, usize) {
    let mut data = Vec::new();
    let mut calls = 0;
    let r = get(&url, &Validators::default(), max, Duration::from_secs(5), |c| {
        calls += 1;
        data.extend_from_slice(c);
        Ok(())
    })
    .await;
    (r, data, calls)
}

#[tokio::test]
async fn lengths_redirect_and_streaming() {
    let a = server().await;
    let expect = "||ads.example^\n||track.example^\n".repeat(1000);
    for p in ["/plain", "/chunked", "/moved", "/close"] {
        let (r, data, calls) = fetch(format!("http://{a}{p}"), 1 << 20).await;
        let r = r.unwrap_or_else(|e| panic!("{p}: {e}"));
        assert_eq!(String::from_utf8(data).unwrap(), expect, "{p}");
        assert!(calls > 1, "{p}: 邊收邊處理，不是一次拿到全部");
        match r {
            Outcome::Done { bytes, .. } => assert_eq!(bytes as usize, expect.len()),
            _ => panic!("{p}"),
        }
    }
}

#[tokio::test]
async fn not_modified_and_limits() {
    let a = server().await;
    let r = get(
        &format!("http://{a}/etag"),
        &Validators::default(),
        1000,
        Duration::from_secs(5),
        |_| Ok(()),
    )
    .await
    .unwrap();
    let Outcome::Done { validators, .. } = r else { panic!() };
    assert_eq!(validators.etag.as_deref(), Some("\"v1\""));
    let r = get(&format!("http://{a}/etag"), &validators, 1000, Duration::from_secs(5), |_| {
        panic!("沒變不該收到資料")
    })
    .await
    .unwrap();
    assert_eq!(r, Outcome::NotModified);
    let (r, _, _) = fetch(format!("http://{a}/plain"), 1000).await;
    assert!(r.unwrap_err().to_string().contains("上限"));
    let (r, _, _) = fetch(format!("http://{a}/nope"), 1000).await;
    assert!(r.unwrap_err().to_string().contains("404"));
}
