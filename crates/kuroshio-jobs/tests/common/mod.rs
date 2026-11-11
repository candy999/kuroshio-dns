//! 台灣 IP 清單測試共用：本機假的 RIR / RIPEstat 伺服器與小型資料
#![allow(dead_code)]

use kuroshio_jobs::twip::{all_asns, RIRS};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// 某個路徑接下來要怎麼回應（用完就恢復正常）
#[derive(Clone, Debug)]
pub enum Fault {
    /// 回這個狀態碼（429 帶 Retry-After）
    Status(u16, Option<&'static str>),
}

#[derive(Default)]
pub struct Mock {
    /// 路徑（不含查詢字串）→ 內容
    pub files: HashMap<String, Arc<Vec<u8>>>,
    /// 路徑 → 接下來幾次的錯誤
    pub faults: HashMap<String, Vec<Fault>>,
    /// 一直失敗的路徑
    pub always_fail: Vec<String>,
    /// 收到的請求（完整的路徑 + 查詢字串）
    pub log: Vec<String>,
}

impl Mock {
    pub fn count(&self, prefix: &str) -> usize {
        self.log.iter().filter(|l| l.starts_with(prefix)).count()
    }
}

pub type Shared = Arc<Mutex<Mock>>;

/// 啟動伺服器：內容用 chunked 分小段送（測試邊收邊解析）
pub async fn serve(mock: Shared) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let mock = mock.clone();
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
                let full = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let path = full.split('?').next().unwrap().to_string();
                // RIPEstat：用 resource 參數區分
                let key = if path == "/data/announced-prefixes/data.json" {
                    let res = full.split("resource=").nth(1).unwrap_or("").split('&').next().unwrap_or("");
                    format!("/ripestat/{res}")
                } else {
                    path.clone()
                };
                let (fault, body) = {
                    let mut m = mock.lock().unwrap();
                    m.log.push(full.clone());
                    let f = m.faults.get_mut(&key).and_then(|v| (!v.is_empty()).then(|| v.remove(0)));
                    let f = f.or_else(|| m.always_fail.contains(&key).then_some(Fault::Status(500, None)));
                    (f, m.files.get(&key).cloned())
                };
                let head = match (&fault, &body) {
                    (Some(Fault::Status(code, ra)), _) => {
                        let ra = ra.map(|r| format!("Retry-After: {r}\r\n")).unwrap_or_default();
                        format!("HTTP/1.1 {code} Error\r\n{ra}Content-Length: 5\r\n\r\nerror")
                    }
                    (None, Some(_)) => "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_string(),
                    (None, None) => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string(),
                };
                if s.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                if let (None, Some(body)) = (fault, body) {
                    for part in body.chunks(4093) {
                        let mut o = format!("{:x}\r\n", part.len()).into_bytes();
                        o.extend_from_slice(part);
                        o.extend_from_slice(b"\r\n");
                        if s.write_all(&o).await.is_err() {
                            return;
                        }
                    }
                    let _ = s.write_all(b"0\r\n\r\n").await;
                }
                s.shutdown().await.ok();
            });
        }
    });
    addr
}

/// 一個 RIR 檔：`tw` 是 (位址, 數量) 的 IPv4 配發，另外塞 `filler` 筆別國的紀錄
pub fn rir_file(rir: &str, tw: &[(&str, u64)], tw6: &[&str], filler: usize) -> Vec<u8> {
    let n = tw.len() + tw6.len() + filler;
    let mut s = format!("# {rir}\n2|{rir}|20261110|{n}|19830613|20261110|+1000\n{rir}|*|ipv4|*|{n}|summary\n");
    for (ip, c) in tw {
        s += &format!("{rir}|TW|ipv4|{ip}|{c}|20090908|allocated|A91A|e-stats\n");
    }
    for p in tw6 {
        let (a, l) = p.split_once('/').unwrap();
        s += &format!("{rir}|TW|ipv6|{a}|{l}|20090908|allocated|A91A|e-stats\n");
    }
    for i in 0..filler {
        s += &format!(
            "{rir}|JP|ipv4|{}.{}.{}.0|256|20110412|allocated|B{i:06}|e-stats\n",
            100 + (i >> 16) % 100,
            (i >> 8) & 255,
            i & 255
        );
    }
    s.into_bytes()
}

/// RIPEstat 回應
pub fn ripestat(prefixes: &[&str]) -> Vec<u8> {
    let p: Vec<String> = prefixes
        .iter()
        .map(|p| format!(r#"{{"prefix":"{p}","timelines":[{{"starttime":"2026-10-28T08:00:00","endtime":"2026-11-11T08:00:00"}}]}}"#))
        .collect();
    format!(
        r#"{{"messages":[],"see_also":[],"version":"1.2","data_call_status":"supported","status":"ok","status_code":200,"data":{{"prefixes":[{}],"resource":"x"}}}}"#,
        p.join(",")
    )
    .into_bytes()
}

/// 小型資料：台灣 = 1.160.0.0/12 + 61.216.0.0/14 + 2001:b000::/20；HiNet、凱擘、TANet 有宣告，其他 ASN 都沒有
pub fn small_fixture(filler: usize) -> Mock {
    let mut m = Mock::default();
    for (rir, _) in RIRS {
        let body = match rir {
            "apnic" => rir_file(rir, &[("1.160.0.0", 1 << 20), ("61.216.0.0", 1 << 18)], &["2001:b000::/20"], filler),
            "arin" => rir_file(rir, &[("140.112.0.0", 1 << 16)], &[], filler),
            _ => rir_file(rir, &[], &[], filler),
        };
        m.files.insert(format!("/delegated-{rir}-extended-latest"), Arc::new(body));
    }
    for a in all_asns() {
        let p: &[&str] = match a {
            3462 => &["1.160.0.0/13", "61.216.0.0/15", "8.8.8.0/24", "2001:b000::/24"],
            38841 => &["1.168.0.0/16"],
            1659 => &["140.112.0.0/16"],
            9674 => &["61.218.0.0/16"],
            _ => &[],
        };
        m.files.insert(format!("/ripestat/AS{a}"), Arc::new(ripestat(p)));
    }
    m
}
