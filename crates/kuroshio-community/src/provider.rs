//! 跟其他模組的介面：分享什麼（我的資料）、收到之後交給誰（候選），以及網域解析
//!
//! 社群模組不依賴 CDN、背景工作模組；整合時實作 [`DataProvider`] 接上：
//! - `local_records`：CDN 台灣節點池、網站驗證結果、跨 CDN 結果、每日評測選出的上游（只放本機驗證過的）
//! - `in_range`：CDN 官方 IP 範圍
//! - `on_received`：好友的資料（全部只是候選，用之前一定在本機驗證）
//! - 驗證結果用 [`crate::Community::report`] 回饋，算進好友的資料品質分數

use crate::envelope::NetInfo;
use anyhow::Result;
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Mutex;

/// 我要分享的一筆資料
#[derive(Debug, Clone, PartialEq)]
pub enum LocalRecord {
    /// CDN 台灣節點；`permanent` = v6 永久節點（有效 30 天）
    Node {
        p: String,
        ip: IpAddr,
        pop: String,
        ms: Option<u32>,
        obs: u64,
        permanent: bool,
    },
    /// 網站驗證結果（網域只會以雜湊分享）
    Site {
        name: String,
        p: String,
        fam: u8,
        ips: Vec<IpAddr>,
        pop: String,
        obs: u64,
    },
    /// 跨 CDN 結果
    Cross {
        name: String,
        from: String,
        to: String,
        ips: Vec<IpAddr>,
        obs: u64,
    },
    /// 上游：proto = udp / tcp / dot / doh / doh3 / doq / dnscrypt；ok = 成功率（0–1）
    Upstream {
        url: String,
        proto: String,
        ms: Option<u32>,
        ok: f32,
        obs: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeCheck {
    /// 在該 CDN 的官方範圍內
    InRange,
    /// 該 CDN 我認識，但這個 IP 不在官方範圍內
    OutOfRange,
    /// 我不認識這家 CDN
    UnknownProvider,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NodeCandidate {
    pub p: String,
    pub ip: IpAddr,
    pub pop: String,
    pub ms: Option<u32>,
    /// 在官方範圍內；false = 待驗證（交給每日節點池工作實測）
    pub in_range: bool,
    pub obs: u64,
    pub exp: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SiteHint {
    pub h: [u8; 12],
    pub p: String,
    pub fam: u8,
    pub ips: Vec<IpAddr>,
    pub pop: String,
    pub obs: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CrossHint {
    pub h: [u8; 12],
    pub from: String,
    pub to: String,
    pub ips: Vec<IpAddr>,
    pub obs: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamCandidate {
    pub url: String,
    pub proto: String,
    pub ms: Option<u32>,
    pub ok: f32,
}

/// 一次同步收到、檢查過的資料（只有新增或變更的；被暫停的 kind 不會出現）
#[derive(Debug, Clone, Default)]
pub struct Received {
    pub from: String,
    /// 觀測者自報的網路（同一家電信業者的觀測可以優先）
    pub ctx: NetInfo,
    pub full: bool,
    pub nodes: Vec<NodeCandidate>,
    pub sites: Vec<SiteHint>,
    pub cross: Vec<CrossHint>,
    pub upstreams: Vec<UpstreamCandidate>,
    /// 好友刪除的記錄（kind, key）
    pub deleted: Vec<(String, String)>,
}

pub trait DataProvider: Send + Sync {
    /// 我的分享集合來源（每 10 分鐘取一次）
    fn local_records(&self) -> Vec<LocalRecord> {
        vec![]
    }
    /// 我的網路（ASN、Cloudflare 機房），放在身分文件與同步回應
    fn net_ctx(&self) -> NetInfo {
        NetInfo::default()
    }
    fn in_range(&self, _provider: &str, _ip: IpAddr) -> RangeCheck {
        RangeCheck::UnknownProvider
    }
    /// 來源 IP 的 ASN（自動規則用；查不到回 None）
    fn asn_of(&self, _ip: IpAddr) -> Option<u32> {
        None
    }
    /// 好友的資料（候選）
    fn on_received(&self, _batch: &Received) {}
}

/// 什麼都不分享、收到也不處理（還沒接上其他模組時用）
pub struct NoData;
impl DataProvider for NoData {}

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// 網域解析：A/AAAA（回連、來源 IP 比對）與 TXT（`_kuroshio` 第二管道）
pub trait Resolver: Send + Sync {
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFut<'a, Result<Vec<IpAddr>>>;
    fn txt<'a>(&'a self, name: &'a str) -> BoxFut<'a, Result<Vec<String>>>;
}

/// 正式用：公共 DNS（kuroshio-net 的 bootstrap 伺服器），不經過本機的快取與改寫
pub struct PublicResolver;

impl Resolver for PublicResolver {
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFut<'a, Result<Vec<IpAddr>>> {
        // 好友的網域是對方給的：只連公開網路上的位址（不讓別人叫這台機器去連本機 / 區網）
        Box::pin(async move {
            let all = kuroshio_net::tls::resolve_host(host).await?;
            let ips: Vec<IpAddr> = all.into_iter().filter(|ip| crate::transport::is_public_ip(*ip)).collect();
            if ips.is_empty() {
                anyhow::bail!("{host} 解析到的不是公開網路上的位址");
            }
            Ok(ips)
        })
    }
    fn txt<'a>(&'a self, name: &'a str) -> BoxFut<'a, Result<Vec<String>>> {
        Box::pin(kuroshio_net::tls::lookup_txt(name))
    }
}

/// 固定對照表（測試、或使用者指定的 hosts）：查不到的回錯誤，不會退回公共 DNS
#[derive(Default)]
pub struct StaticResolver {
    pub hosts: Mutex<HashMap<String, Vec<IpAddr>>>,
    pub txts: Mutex<HashMap<String, Vec<String>>>,
}

impl StaticResolver {
    pub fn set(&self, host: &str, ips: &[IpAddr]) {
        self.hosts.lock().unwrap().insert(host.to_ascii_lowercase(), ips.to_vec());
    }
    pub fn set_txt(&self, name: &str, v: &[&str]) {
        self.txts
            .lock()
            .unwrap()
            .insert(name.to_ascii_lowercase(), v.iter().map(|s| s.to_string()).collect());
    }
}

impl Resolver for StaticResolver {
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFut<'a, Result<Vec<IpAddr>>> {
        let r = self.hosts.lock().unwrap().get(&host.to_ascii_lowercase()).cloned();
        Box::pin(async move { r.filter(|v| !v.is_empty()).ok_or_else(|| anyhow::anyhow!("解析不到 {host}")) })
    }
    fn txt<'a>(&'a self, name: &'a str) -> BoxFut<'a, Result<Vec<String>>> {
        let r = self
            .txts
            .lock()
            .unwrap()
            .get(&name.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default();
        Box::pin(async move { Ok(r) })
    }
}
