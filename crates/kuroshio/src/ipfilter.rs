//! 來源 IP 存取控制：只讓台灣（依 ISP 勾選）與自訂名單的 IP 連進公開的監聽（規格 08）
//!
//! 判斷順序（第一個符合的決定結果）：
//! 1. 迴路位址（127.0.0.0/8、::1）→ 允許（永遠不會把自己鎖在外面）
//! 2. 自訂封鎖 `access.deny` → 拒絕（勝過下面全部）
//! 3. 私有 / 鏈路本地 / CGNAT / ULA、本機各網卡所在的網段 → 允許
//! 4. 社群好友目前的 IP → 允許
//! 5. 自訂允許 `access.allow` → 允許
//! 6. `access.mode`：`open` → 允許；`taiwan` → 全部台灣網段；`custom` → `access.groups` 勾選的群組
//! 7. 其他 → 拒絕
//!
//! 台灣 IP 資料（`tw-ip.json`）讀不到或格式錯誤時「不擋」（fail open），在狀態裡顯示警告。
//!
//! 查詢：建立時把所有網段合併成排序、不重疊的區間（IPv4 `u32`、IPv6 `u128`），每次連線二分搜尋。
//! IPv4 對應的 IPv6（`::ffff:a.b.c.d`）當成 IPv4。

use kuroshio_config::get;
use kuroshio_jobs::geo::{canonical, Dual, TwIp};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tracing::{info, warn};

/// 快照目錄裡自動更新下載的台灣 IP 資料
pub const STATE_FILE: &str = "tw-ip.json";

/// 測試用：把迴路位址當成公網位址（只有整合測試會打開；同一個行程裡全部生效）
#[doc(hidden)]
pub static TEST_LOOPBACK_PUBLIC: AtomicBool = AtomicBool::new(false);

/// 套用存取控制的服務
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Dot = 0,
    Doh = 1,
    Doq = 2,
    Doh3 = 3,
    Site = 4,
    Community = 5,
    Plain = 6,
}

impl Kind {
    pub const ALL: [Kind; 7] = [
        Kind::Dot,
        Kind::Doh,
        Kind::Doq,
        Kind::Doh3,
        Kind::Site,
        Kind::Community,
        Kind::Plain,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Kind::Dot => "dot",
            Kind::Doh => "doh",
            Kind::Doq => "doq",
            Kind::Doh3 => "doh3",
            Kind::Site => "site",
            Kind::Community => "community",
            Kind::Plain => "plain",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.name().eq_ignore_ascii_case(s.trim()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// 全部台灣網段（含「其他台灣網段」）
    Taiwan,
    /// 只有勾選的群組
    Custom,
    /// 全開放（自訂封鎖照樣有效）
    Open,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Taiwan => "taiwan",
            Mode::Custom => "custom",
            Mode::Open => "open",
        }
    }
}

/// `access.*` 設定
#[derive(Debug, Clone)]
pub struct Settings {
    pub mode: Mode,
    /// `custom` 模式勾選的群組；`*` = 全部（之後資料新增的群組也算）
    pub groups: Vec<String>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub apply: [bool; 7],
    pub log: bool,
    pub auto_update: bool,
    pub update_url: String,
    /// 指定資料檔（空白 = 唯讀資料目錄的 geo/tw-ip.json）
    pub data_file: String,
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

impl Settings {
    pub fn from_cfg(cfg: &Value) -> Settings {
        let s = |k: &str| {
            get(cfg, &format!("access.{k}"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string()
        };
        let mode = match s("mode").to_ascii_lowercase().as_str() {
            "custom" => Mode::Custom,
            "open" => Mode::Open,
            "taiwan" | "" => Mode::Taiwan,
            other => {
                warn!("access.mode「{other}」不認得，改用 taiwan");
                Mode::Taiwan
            }
        };
        let mut apply = [false; 7];
        let list = get(cfg, "access.applyTo");
        let names = if list.is_some() {
            strings(list)
        } else {
            ["dot", "doh", "doq", "doh3", "site"].map(String::from).to_vec()
        };
        for n in names {
            match Kind::parse(&n) {
                Some(k) => apply[k as usize] = true,
                None => warn!("access.applyTo「{n}」不認得，略過"),
            }
        }
        let flag = |k: &str, d: bool| get(cfg, &format!("access.{k}")).and_then(Value::as_bool).unwrap_or(d);
        Settings {
            mode,
            groups: get(cfg, "access.groups")
                .map(|g| strings(Some(g)))
                .unwrap_or_else(|| vec!["*".into()]),
            allow: strings(get(cfg, "access.allow")),
            deny: strings(get(cfg, "access.deny")),
            apply,
            log: flag("log", true),
            auto_update: flag("autoUpdate", false),
            update_url: s("updateUrl"),
            data_file: s("dataFile"),
        }
    }

    pub fn applies(&self, k: Kind) -> bool {
        self.apply[k as usize]
    }

    fn applied_names(&self) -> Vec<&'static str> {
        Kind::ALL.into_iter().filter(|k| self.applies(*k)).map(Kind::name).collect()
    }
}

/// 判斷結果的原因
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    Loopback,
    CustomDeny(String),
    Private,
    LocalNet,
    Friend,
    CustomAllow(String),
    Open,
    /// 台灣 IP 資料讀不到：不擋
    NoData,
    Group(String),
    NotAllowed,
}

impl Reason {
    pub fn text(&self) -> String {
        match self {
            Reason::Loopback => "本機迴路位址（永遠允許）".into(),
            Reason::CustomDeny(c) => format!("自訂封鎖 {c}"),
            Reason::Private => "私有 / 區網位址（永遠允許）".into(),
            Reason::LocalNet => "本機網卡所在的網段（永遠允許）".into(),
            Reason::Friend => "社群好友目前的 IP".into(),
            Reason::CustomAllow(c) => format!("自訂允許 {c}"),
            Reason::Open => "全開放模式".into(),
            Reason::NoData => "台灣 IP 資料讀不到，暫時不擋".into(),
            Reason::Group(g) => format!("台灣網段：{g}"),
            Reason::NotAllowed => "不在允許的網段".into(),
        }
    }
}

/// 永遠允許的私有網段（區網、CGNAT、鏈路本地、ULA）
const PRIVATE: [&str; 9] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
    "127.0.0.0/8",
    "::1/128",
];

/// 編譯好的規則（設定 + 資料 + 本機網段 + 好友 IP）。任何一項變動就重建一份換上去
pub struct Rules {
    pub mode: Mode,
    deny: Dual,
    deny_src: Vec<String>,
    allow: Dual,
    allow_src: Vec<String>,
    private: Dual,
    local: Dual,
    friends: Dual,
    /// 允許的台灣網段（勾選的群組聯集）；None = 不用台灣網段（open 模式或資料讀不到）
    geo: Option<Dual>,
    data: Option<Arc<TwIp>>,
    /// 實際生效的群組 id
    pub groups: Vec<String>,
}

impl Rules {
    pub fn build(st: &Settings, data: Option<Arc<TwIp>>, local: Dual, friends: Dual) -> Rules {
        let (deny, bad_d) = Dual::parse(st.deny.iter().map(String::as_str));
        let (allow, bad_a) = Dual::parse(st.allow.iter().map(String::as_str));
        for b in bad_d.iter().chain(bad_a.iter()) {
            warn!("存取控制：網段格式錯誤「{b}」，略過");
        }
        let (private, _) = Dual::parse(PRIVATE);
        let mut groups = Vec::new();
        let geo = match (st.mode, &data) {
            (Mode::Open, _) | (_, None) => None,
            (mode, Some(d)) => {
                let all = mode == Mode::Taiwan || st.groups.iter().any(|g| g == "*");
                let (mut v4, mut v6) = (Vec::new(), Vec::new());
                for g in &d.groups {
                    if all || st.groups.iter().any(|x| x == &g.id) {
                        groups.push(g.id.clone());
                        v4.extend_from_slice(g.nets.v4.ranges());
                        v6.extend_from_slice(g.nets.v6.ranges());
                    }
                }
                for want in &st.groups {
                    if want != "*" && d.group(want).is_none() {
                        warn!("access.groups「{want}」不在台灣 IP 資料裡，略過");
                    }
                }
                Some(Dual::from_ranges(v4, v6))
            }
        };
        Rules {
            mode: st.mode,
            deny,
            deny_src: st.deny.clone(),
            allow,
            allow_src: st.allow.clone(),
            private,
            local,
            friends,
            geo,
            data,
            groups,
        }
    }

    fn which(src: &[String], ip: IpAddr) -> String {
        src.iter()
            .find(|s| Dual::parse([s.as_str()]).0.contains(ip))
            .cloned()
            .unwrap_or_default()
    }

    /// 允許與否（不記錄統計）
    pub fn allows(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        if ip.is_loopback() && !TEST_LOOPBACK_PUBLIC.load(Ordering::Relaxed) {
            return true;
        }
        if self.deny.contains(ip) {
            return false;
        }
        if (self.private.contains(ip) && !ip.is_loopback())
            || self.local.contains(ip)
            || self.friends.contains(ip)
            || self.allow.contains(ip)
        {
            return true;
        }
        match &self.geo {
            None => true, // open 模式，或資料讀不到（fail open）
            Some(g) => g.contains(ip),
        }
    }

    /// 判斷並說明原因（CLI `kuroshio access check`、`/api/access?ip=` 用；比 `allows` 慢）
    pub fn explain(&self, ip: IpAddr) -> (bool, Reason) {
        let ip = canonical(ip);
        let lo_public = TEST_LOOPBACK_PUBLIC.load(Ordering::Relaxed);
        if ip.is_loopback() && !lo_public {
            return (true, Reason::Loopback);
        }
        if self.deny.contains(ip) {
            return (false, Reason::CustomDeny(Self::which(&self.deny_src, ip)));
        }
        if self.private.contains(ip) && !ip.is_loopback() {
            return (true, Reason::Private);
        }
        if self.local.contains(ip) {
            return (true, Reason::LocalNet);
        }
        if self.friends.contains(ip) {
            return (true, Reason::Friend);
        }
        if self.allow.contains(ip) {
            return (true, Reason::CustomAllow(Self::which(&self.allow_src, ip)));
        }
        match (&self.geo, self.mode) {
            (None, Mode::Open) => (true, Reason::Open),
            (None, _) => (true, Reason::NoData),
            (Some(g), _) => {
                // 屬於哪一組（不管有沒有勾選，方便說明）
                let grp = self
                    .data
                    .as_ref()
                    .and_then(|d| d.groups.iter().find(|x| x.nets.contains(ip)))
                    .map(|x| (x.id.clone(), x.name.clone()));
                match (g.contains(ip), grp) {
                    (true, Some((_, name))) => (true, Reason::Group(name)),
                    (true, None) => (true, Reason::Group(String::new())),
                    (false, Some((id, name))) => (false, Reason::Group(format!("{name}（{id}，沒有勾選）"))),
                    (false, None) => (false, Reason::NotAllowed),
                }
            }
        }
    }

    /// 合併後的區間數與大約占用的記憶體（位元組）
    pub fn footprint(&self) -> (usize, usize) {
        let sets = [&self.deny, &self.allow, &self.private, &self.local, &self.friends];
        let mut n: usize = sets.iter().map(|d| d.v4.len() + d.v6.len()).sum();
        let mut b: usize = sets.iter().map(|d| d.heap_bytes()).sum();
        if let Some(g) = &self.geo {
            n += g.v4.len() + g.v6.len();
            b += g.heap_bytes();
        }
        (n, b)
    }
}

/// 拒絕統計：每個服務的次數，以及被拒絕最多的 /24（IPv6 /48）
#[derive(Default)]
struct Denied {
    by_kind: [AtomicU32; 7],
    /// (是否 IPv6, 網段起點) → 次數；最多 TOP_MAX 筆
    top: Mutex<HashMap<(bool, u128), u32>>,
    /// 記錄頻率限制：(上次記錄的時間（秒）, 之後累積的次數)
    log: Mutex<(u64, u32)>,
}

const TOP_MAX: usize = 512;

/// 存取控制（每一輪設定一份）。規則可以在執行中換掉（好友 IP、自動更新的資料）
pub struct Access {
    pub settings: Settings,
    rules: RwLock<Arc<Rules>>,
    /// 目前的資料與來源說明（內建 / 自動更新）
    data: RwLock<(Option<Arc<TwIp>>, String)>,
    data_error: RwLock<Option<String>>,
    local: RwLock<Dual>,
    friends: RwLock<Dual>,
    denied: Denied,
}

impl Access {
    /// 什麼都不擋（沒有設定時、測試）
    pub fn open() -> Arc<Access> {
        Self::new(
            Settings {
                mode: Mode::Open,
                groups: vec![],
                allow: vec![],
                deny: vec![],
                apply: [false; 7],
                log: false,
                auto_update: false,
                update_url: String::new(),
                data_file: String::new(),
            },
            None,
            String::new(),
            None,
        )
    }

    pub fn new(settings: Settings, data: Option<Arc<TwIp>>, source: String, error: Option<String>) -> Arc<Access> {
        let a = Access {
            rules: RwLock::new(Arc::new(Rules::build(&settings, data.clone(), Dual::default(), Dual::default()))),
            settings,
            data: RwLock::new((data, source)),
            data_error: RwLock::new(error),
            local: RwLock::new(Dual::default()),
            friends: RwLock::new(Dual::default()),
            denied: Denied::default(),
        };
        Arc::new(a)
    }

    /// 依設定載入：自動更新下載的（較新的）→ `access.dataFile` → 唯讀資料目錄的 geo/tw-ip.json
    pub fn from_cfg(cfg: &Value, share_dir: &Path, persisted: Option<Vec<u8>>) -> Arc<Access> {
        let st = Settings::from_cfg(cfg);
        let path = if st.data_file.is_empty() {
            share_dir.join("geo").join("tw-ip.json")
        } else {
            PathBuf::from(&st.data_file)
        };
        let (mut data, mut source, mut error) = match std::fs::read(&path) {
            Ok(b) => match TwIp::parse(&b) {
                Ok(t) => (Some(Arc::new(t)), path.display().to_string(), None),
                Err(e) => (None, String::new(), Some(format!("{} 格式錯誤：{e:#}", path.display()))),
            },
            Err(e) => (None, String::new(), Some(format!("讀不到 {}：{e}", path.display()))),
        };
        if st.auto_update {
            if let Some(t) = persisted.and_then(|b| TwIp::parse(&b).ok()) {
                let newer = data.as_ref().map(|d| t.generated_at > d.generated_at).unwrap_or(true);
                let sane = data.as_ref().map(|d| sane_size(d, &t)).unwrap_or(true);
                if newer && sane {
                    data = Some(Arc::new(t));
                    source = format!("自動更新（{STATE_FILE}）");
                    error = None;
                }
            }
        }
        if let Some(e) = &error {
            if st.mode != Mode::Open {
                warn!("存取控制：{e}；台灣 IP 資料不能用，暫時不擋任何來源");
            }
        }
        let a = Access::new(st, data, source, error);
        a.refresh_local();
        if a.settings.mode != Mode::Open || !a.settings.deny.is_empty() {
            let r = a.rules();
            let (n, b) = r.footprint();
            info!(
                "存取控制：{}模式，套用在 {}，{} 個區間（約 {} KB）",
                a.settings.mode.name(),
                a.settings.applied_names().join("、"),
                n,
                b / 1024
            );
        }
        a
    }

    pub fn rules(&self) -> Arc<Rules> {
        self.rules.read().unwrap().clone()
    }

    fn rebuild(&self) {
        let r = Rules::build(
            &self.settings,
            self.data.read().unwrap().0.clone(),
            self.local.read().unwrap().clone(),
            self.friends.read().unwrap().clone(),
        );
        *self.rules.write().unwrap() = Arc::new(r);
    }

    /// 重新讀本機網卡的網段（啟動時；網卡位址變了可以再呼叫）
    pub fn refresh_local(&self) {
        let nets = local_networks();
        if *self.local.read().unwrap() != nets {
            *self.local.write().unwrap() = nets;
            self.rebuild();
        }
    }

    /// 社群好友目前的 IP（定時解析好友網域後呼叫）
    pub fn set_friends(&self, ips: &[IpAddr]) {
        let list: Vec<String> = ips.iter().map(|i| canonical(*i).to_string()).collect();
        let (d, _) = Dual::parse(list.iter().map(String::as_str));
        if *self.friends.read().unwrap() != d {
            *self.friends.write().unwrap() = d;
            self.rebuild();
        }
    }

    /// 換上新的台灣 IP 資料（自動更新）
    pub fn set_data(&self, t: TwIp, source: &str) {
        *self.data.write().unwrap() = (Some(Arc::new(t)), source.to_string());
        *self.data_error.write().unwrap() = None;
        self.rebuild();
    }

    pub fn data(&self) -> Option<Arc<TwIp>> {
        self.data.read().unwrap().0.clone()
    }

    /// 這個服務要不要檢查來源
    pub fn applies(&self, k: Kind) -> bool {
        self.settings.applies(k)
    }

    /// 單一服務：允許就回 true；拒絕會記錄統計
    pub fn allow(&self, k: Kind, ip: IpAddr) -> bool {
        if !self.applies(k) {
            return true;
        }
        if self.rules.read().unwrap().allows(ip) {
            return true;
        }
        self.record(k, ip);
        false
    }

    /// 連線剛接受時（還沒握手）：同一個埠上的服務「全部」都要檢查而且都不允許，才在這裡就拒絕；
    /// 有任一服務不檢查（例如社群共享沒套用）就放行，等知道是哪個服務時再用 `allow` 判斷。
    /// 記錄統計時算在 `kinds[0]`。
    pub fn gate(&self, kinds: &[Kind], ip: IpAddr) -> bool {
        if kinds.is_empty() || kinds.iter().any(|k| !self.applies(*k)) {
            return true;
        }
        if self.rules.read().unwrap().allows(ip) {
            return true;
        }
        self.record(kinds[0], ip);
        false
    }

    /// 不記錄統計的判斷（例如先看公開頁能不能給，不能再算別的服務）
    pub fn quiet_allows(&self, k: Kind, ip: IpAddr) -> bool {
        !self.applies(k) || self.rules.read().unwrap().allows(ip)
    }

    /// 記一筆拒絕（配合 `quiet_allows`）
    pub fn record(&self, k: Kind, ip: IpAddr) {
        self.denied.by_kind[k as usize].fetch_add(1, Ordering::Relaxed);
        let key = match canonical(ip) {
            IpAddr::V4(a) => (false, (u32::from(a) & 0xffff_ff00) as u128),
            IpAddr::V6(a) => (true, u128::from(a) & !((1u128 << 80) - 1)),
        };
        {
            let mut top = self.denied.top.lock().unwrap();
            if let Some(n) = top.get_mut(&key) {
                *n = n.saturating_add(1);
            } else {
                if top.len() >= TOP_MAX {
                    // 滿了：丟掉只出現過一次的（大部分是掃描），還是滿的就不收新的
                    top.retain(|_, n| *n > 1);
                }
                if top.len() < TOP_MAX {
                    top.insert(key, 1);
                }
            }
        }
        if self.settings.log {
            let now = crate::persist::now_secs();
            let mut l = self.denied.log.lock().unwrap();
            l.1 += 1;
            // 每分鐘最多記錄一次
            if now >= l.0 + 60 {
                info!("存取控制：拒絕 {ip}（{}），最近一分鐘共拒絕 {} 次", k.name(), l.1);
                *l = (now, 0);
            }
        }
    }

    fn top_json(&self, n: usize) -> Value {
        let top = self.denied.top.lock().unwrap();
        let mut v: Vec<(&(bool, u128), &u32)> = top.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        Value::Array(
            v.into_iter()
                .take(n)
                .map(|((v6, net), c)| {
                    let net = if *v6 {
                        format!("{}/48", std::net::Ipv6Addr::from(*net))
                    } else {
                        format!("{}/24", std::net::Ipv4Addr::from(*net as u32))
                    };
                    json!({ "net": net, "count": c })
                })
                .collect(),
        )
    }

    fn counters_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        let mut total = 0u64;
        for k in Kind::ALL {
            let n = self.denied.by_kind[k as usize].load(Ordering::Relaxed);
            total += n as u64;
            m.insert(k.name().into(), json!(n));
        }
        json!({ "total": total, "byListener": m })
    }

    /// `/api/status` 的 `access` 欄位（精簡）
    pub fn status_json(&self) -> Value {
        let r = self.rules();
        let (ranges, bytes) = r.footprint();
        json!({
            "mode": self.settings.mode.name(),
            "applyTo": self.settings.applied_names(),
            "active": self.settings.mode != Mode::Open || !self.settings.deny.is_empty(),
            "dataOk": self.data.read().unwrap().0.is_some(),
            "warning": self.data_error.read().unwrap().clone(),
            "failOpen": self.settings.mode != Mode::Open && self.data.read().unwrap().0.is_none(),
            "generatedAt": self.data.read().unwrap().0.as_ref().map(|d| d.generated_at.clone()),
            "ranges": ranges,
            "memoryBytes": bytes,
            // 各群組的網段（說明、/api/access 用）
            "dataBytes": self.data.read().unwrap().0.as_ref().map(|d| d.groups.iter().map(|g| g.nets.heap_bytes()).sum::<usize>()),
            "denied": self.counters_json(),
            "topDenied": self.top_json(10),
        })
    }

    /// `GET /api/access`：群組（名稱、大小、是否生效）、自訂名單、統計
    pub fn api_json(&self) -> Value {
        let r = self.rules();
        let (data, source) = self.data.read().unwrap().clone();
        let groups: Vec<Value> = data
            .as_ref()
            .map(|d| {
                d.groups
                    .iter()
                    .map(|g| {
                        json!({
                            "id": g.id, "name": g.name, "note": g.note, "asns": g.asns,
                            "size": g.nets.size_json(),
                            "cidrs": { "v4": g.nets.v4_cidrs().len(), "v6": g.nets.v6_cidrs().len() },
                            "enabled": r.groups.contains(&g.id),
                            "checked": self.settings.groups.iter().any(|x| x == "*" || x == &g.id),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut st = self.status_json();
        let o = st.as_object_mut().unwrap();
        o.insert("groups".into(), Value::Array(groups));
        o.insert("selected".into(), json!(self.settings.groups));
        o.insert("allow".into(), json!(self.settings.allow));
        o.insert("deny".into(), json!(self.settings.deny));
        o.insert("log".into(), json!(self.settings.log));
        o.insert("autoUpdate".into(), json!(self.settings.auto_update));
        o.insert("dataSource".into(), json!(source));
        o.insert("total".into(), data.as_ref().map(|d| d.all().size_json()).unwrap_or(Value::Null));
        o.insert("topDenied".into(), self.top_json(50));
        st
    }

    /// 說明某個 IP 的判斷結果
    pub fn check_json(&self, ip: IpAddr) -> Value {
        let (ok, why) = self.rules().explain(ip);
        let applied: Vec<&str> = Kind::ALL.into_iter().filter(|k| self.applies(*k)).map(Kind::name).collect();
        json!({ "ip": ip.to_string(), "allowed": ok, "reason": why.text(), "mode": self.settings.mode.name(), "applyTo": applied })
    }
}

// ---------------- 監聽端的呼叫點（每個都是一行，方便跟其他修改合併） ----------------

/// 同一個埠上還有哪些服務：社群共享（ALPN kuroshio/2 或 HTTPS 路徑）、公開頁
fn with_shared(r: &crate::resolver::Resolver, first: Kind, site: bool) -> ([Kind; 3], usize) {
    let mut k = [first; 3];
    let mut n = 1;
    if site && r.site.get().is_some() {
        k[n] = Kind::Site;
        n += 1;
    }
    if r.community.get().is_some() {
        k[n] = Kind::Community;
        n += 1;
    }
    (k, n)
}

/// DoT 剛接受 TCP 連線（還沒 TLS 握手）
pub fn accept_dot(r: &crate::resolver::Resolver, ip: IpAddr) -> bool {
    let (k, n) = with_shared(r, Kind::Dot, false);
    r.access_gate(&k[..n], ip)
}

/// DoH（HTTPS / HTTP）剛接受 TCP 連線：同一個埠也有公開頁、社群共享
pub fn accept_doh(r: &crate::resolver::Resolver, ip: IpAddr) -> bool {
    let (k, n) = with_shared(r, Kind::Doh, true);
    r.access_gate(&k[..n], ip)
}

/// DoQ 收到 QUIC 連線請求（握手前）
pub fn accept_doq(r: &crate::resolver::Resolver, ip: IpAddr) -> bool {
    let (k, n) = with_shared(r, Kind::Doq, false);
    r.access_gate(&k[..n], ip)
}

/// DoH3 收到 QUIC 連線請求（握手前）
pub fn accept_doh3(r: &crate::resolver::Resolver, ip: IpAddr) -> bool {
    let (k, n) = with_shared(r, Kind::Doh3, true);
    r.access_gate(&k[..n], ip)
}

/// 握手完成、知道是 DNS 還是社群共享（ALPN）之後
pub fn after_alpn(r: &crate::resolver::Resolver, dns: Kind, community: bool, ip: IpAddr) -> bool {
    r.access_allows(if community { Kind::Community } else { dns }, ip)
}

/// DoH / DoH3 / 公開頁 / 社群共享（HTTPS）的請求：`None` = 拒絕（回 403）；`Some(公開頁可不可以給)`
pub fn request_check(r: &crate::resolver::Resolver, path: &str, doh_path: &str, proto: &str, ip: IpAddr) -> Option<bool> {
    let Some(a) = r.access.get() else { return Some(true) };
    if path.starts_with(kuroshio_community::BASE_PATH) && r.community.get().is_some() {
        return a.allow(Kind::Community, ip).then_some(true);
    }
    if path == doh_path {
        let dns = if proto == "doh3" { Kind::Doh3 } else { Kind::Doh };
        return a.allow(dns, ip).then(|| a.quiet_allows(Kind::Site, ip));
    }
    let site_ok = a.quiet_allows(Kind::Site, ip);
    if !site_ok && r.site.get().is_some() {
        a.record(Kind::Site, ip);
        return None;
    }
    Some(site_ok)
}

/// 背景工作：每 10 分鐘重新讀本機網卡的網段；`access.autoUpdate` 開著時每天檢查一次新的台灣 IP 資料
pub fn spawn_tasks(a: Arc<Access>, persister: Arc<Mutex<crate::persist::Persister>>) {
    if a.settings.mode == Mode::Open && !a.settings.auto_update {
        return;
    }
    tokio::spawn(async move {
        let mut tick = 0u64;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
            tick += 1;
            a.refresh_local();
            // 啟動 10 分鐘後第一次，之後每 24 小時
            if a.settings.auto_update && tick % 144 == 1 {
                match fetch_update(&a).await {
                    Ok(Some((t, bytes))) => {
                        info!("存取控制：台灣 IP 資料更新到 {}", t.generated_at);
                        a.set_data(t, &format!("自動更新（{STATE_FILE}）"));
                        // 經過快照寫入器（跟其他狀態一樣受 Flash 寫入間隔與每日上限限制）
                        persister.lock().unwrap().stage(STATE_FILE, bytes);
                    }
                    Ok(None) => {}
                    Err(e) => warn!("存取控制：台灣 IP 資料更新失敗：{e:#}"),
                }
            }
        }
    });
}

/// 下載新的台灣 IP 資料；比目前的新、格式正確、IPv4 總量在 ±20% 以內才接受
async fn fetch_update(a: &Access) -> anyhow::Result<Option<(TwIp, Vec<u8>)>> {
    let url = &a.settings.update_url;
    if url.is_empty() {
        return Ok(None);
    }
    let req = kuroshio_net::fetch::Request {
        method: "GET",
        ..Default::default()
    };
    let (code, body) = kuroshio_net::fetch::request(url, &req, 4 << 20, std::time::Duration::from_secs(60)).await?;
    if code != 200 {
        anyhow::bail!("HTTP {code}");
    }
    let t = TwIp::parse(&body)?;
    Ok(accept_update(a.data().as_deref(), t).map(|t| (t, body)))
}

/// 自動更新的取捨（純函式）：比目前的新、而且大小合理才換
pub fn accept_update(cur: Option<&TwIp>, new: TwIp) -> Option<TwIp> {
    match cur {
        None => Some(new),
        Some(c) if new.generated_at <= c.generated_at => None,
        Some(c) if !sane_size(c, &new) => {
            warn!(
                "存取控制：下載的台灣 IP 資料大小跟目前的差超過 20%（{} → {}），不採用",
                c.all().v4.size(),
                new.all().v4.size()
            );
            None
        }
        Some(_) => Some(new),
    }
}

/// 自動更新的新資料是否合理：IPv4 總量跟目前的差在 ±20% 以內
pub fn sane_size(old: &TwIp, new: &TwIp) -> bool {
    let (a, b) = (old.all().v4.size() as f64, new.all().v4.size() as f64);
    a > 0.0 && (b - a).abs() <= a * 0.2
}

/// 本機各網卡所在的網段（迴路除外；IPv6 前綴短於 /48 的不算，避免把整個 ISP 放進來）
pub fn local_networks() -> Dual {
    let mut list = Vec::new();
    if let Ok(ifs) = if_addrs::get_if_addrs() {
        for i in ifs {
            if i.is_loopback() {
                continue;
            }
            match i.addr {
                if_addrs::IfAddr::V4(a) => {
                    let len = u32::from(a.netmask).leading_ones();
                    // 網段太大（短於 /16）的只放自己這個位址
                    list.push(format!("{}/{}", a.ip, if len >= 16 { len } else { 32 }));
                }
                if_addrs::IfAddr::V6(a) => {
                    let len = u128::from(a.netmask).leading_ones();
                    if len >= 48 {
                        list.push(format!("{}/{len}", a.ip));
                    } else {
                        list.push(format!("{}/128", a.ip));
                    }
                }
            }
        }
    }
    Dual::parse(list.iter().map(String::as_str)).0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> Arc<TwIp> {
        Arc::new(
            TwIp::parse(
                r#"{"generatedAt":"2026-11-11","groups":[
                {"id":"cht","name":"中華電信","v4":["1.160.0.0/12","168.95.0.0/16"],"v6":["2001:b000::/20"]},
                {"id":"kbro","name":"凱擘","v4":["118.232.0.0/14"],"v6":["2001:b030::/32"]},
                {"id":"other","name":"其他台灣網段","v4":["203.64.0.0/16"]}]}"#
                    .as_bytes(),
            )
            .unwrap(),
        )
    }

    fn st(v: Value) -> Settings {
        Settings::from_cfg(&json!({ "access": v }))
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn defaults_from_config_file() {
        let s = Settings::from_cfg(&kuroshio_config::defaults());
        assert_eq!(s.mode, Mode::Taiwan, "預設只開放台灣");
        assert_eq!(s.groups, vec!["*"]);
        assert!(s.applies(Kind::Dot) && s.applies(Kind::Doh) && s.applies(Kind::Doq) && s.applies(Kind::Doh3) && s.applies(Kind::Site));
        assert!(!s.applies(Kind::Plain) && !s.applies(Kind::Community));
        assert!(!s.auto_update);
        assert!(s.update_url.starts_with("https://"));
        // 沒有 access 區段（舊設定檔）也一樣
        let s = Settings::from_cfg(&json!({}));
        assert_eq!((s.mode, s.groups.clone()), (Mode::Taiwan, vec!["*".to_string()]));
        assert!(s.applies(Kind::Dot));
    }

    #[test]
    fn taiwan_mode_allows_every_group() {
        let r = Rules::build(&st(json!({})), Some(data()), Dual::default(), Dual::default());
        for ok in [
            "1.160.0.1",
            "168.95.1.1",
            "118.233.0.1",
            "203.64.5.5",
            "2001:b000::1",
            "::ffff:1.160.0.1",
        ] {
            assert!(r.allows(ip(ok)), "{ok}");
        }
        for no in ["8.8.8.8", "1.176.0.0", "2001:4860::8888", "::ffff:8.8.8.8"] {
            assert!(!r.allows(ip(no)), "{no}");
        }
        assert_eq!(r.groups, vec!["cht", "kbro", "other"]);
    }

    #[test]
    fn custom_mode_only_ticked() {
        let r = Rules::build(
            &st(json!({ "mode": "custom", "groups": ["kbro"] })),
            Some(data()),
            Dual::default(),
            Dual::default(),
        );
        assert!(r.allows(ip("118.232.1.1")));
        assert!(!r.allows(ip("1.160.0.1")), "沒勾中華電信");
        let (ok, why) = r.explain(ip("1.160.0.1"));
        assert!(!ok);
        assert_eq!(why, Reason::Group("中華電信（cht，沒有勾選）".into()));
        assert_eq!(r.explain(ip("8.8.8.8")), (false, Reason::NotAllowed));
        // 空清單 = 只有區網與自訂允許
        let r = Rules::build(
            &st(json!({ "mode": "custom", "groups": [], "allow": ["8.8.8.0/24"] })),
            Some(data()),
            Dual::default(),
            Dual::default(),
        );
        assert!(!r.allows(ip("118.232.1.1")));
        assert!(r.allows(ip("8.8.8.8")));
        assert!(r.allows(ip("192.168.1.10")), "區網永遠允許");
        // `*` = 全部（包含之後新增的群組）
        let r = Rules::build(
            &st(json!({ "mode": "custom", "groups": ["*"] })),
            Some(data()),
            Dual::default(),
            Dual::default(),
        );
        assert!(r.allows(ip("203.64.0.1")));
    }

    #[test]
    fn deny_wins_except_loopback() {
        let s = st(
            json!({ "mode": "open", "deny": ["1.160.0.0/16", "192.168.5.0/24", "127.0.0.0/8", "2001:b000::/32"], "allow": ["1.160.1.0/24"] }),
        );
        let r = Rules::build(
            &s,
            Some(data()),
            Dual::default(),
            Dual::from_ranges(
                vec![(
                    u32::from(std::net::Ipv4Addr::new(1, 160, 2, 2)),
                    u32::from(std::net::Ipv4Addr::new(1, 160, 2, 2)),
                )],
                vec![],
            ),
        );
        assert!(!r.allows(ip("1.160.1.1")), "封鎖勝過自訂允許");
        assert!(!r.allows(ip("1.160.2.2")), "封鎖勝過好友");
        assert!(!r.allows(ip("192.168.5.9")), "封鎖勝過區網");
        assert!(!r.allows(ip("::ffff:1.160.0.9")), "IPv4 對應的 IPv6 也擋");
        assert!(!r.allows(ip("2001:b000::1")));
        assert!(r.allows(ip("127.0.0.1")), "迴路位址永遠允許");
        assert!(r.allows(ip("::1")));
        assert!(r.allows(ip("8.8.8.8")), "全開放");
        assert_eq!(r.explain(ip("8.8.8.8")), (true, Reason::Open));
        assert_eq!(r.explain(ip("1.160.1.1")), (false, Reason::CustomDeny("1.160.0.0/16".into())));
    }

    #[test]
    fn lan_and_private_always_allowed() {
        let local = Dual::parse(["203.0.113.0/24", "2001:db8:1:2::/64"]).0;
        let r = Rules::build(&st(json!({ "mode": "custom", "groups": [] })), Some(data()), local, Dual::default());
        for ok in [
            "10.1.2.3",
            "172.31.0.1",
            "192.168.0.1",
            "100.64.1.1",
            "169.254.1.1",
            "fd00::1",
            "fe80::1",
            "203.0.113.9",
            "2001:db8:1:2::99",
            "::ffff:192.168.1.1",
        ] {
            assert!(r.allows(ip(ok)), "{ok}");
        }
        assert!(!r.allows(ip("2001:db8:1:3::1")));
        assert_eq!(r.explain(ip("203.0.113.9")), (true, Reason::LocalNet));
        assert_eq!(r.explain(ip("10.0.0.1")), (true, Reason::Private));
    }

    #[test]
    fn missing_data_fails_open() {
        let r = Rules::build(&st(json!({ "deny": ["9.9.9.9"] })), None, Dual::default(), Dual::default());
        assert!(r.allows(ip("8.8.8.8")), "資料讀不到不擋");
        assert!(!r.allows(ip("9.9.9.9")), "自訂封鎖照樣有效");
        assert_eq!(r.explain(ip("8.8.8.8")), (true, Reason::NoData));
        let dir = std::env::temp_dir().join(format!("kuroshio-access-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("geo")).unwrap();
        let a = Access::from_cfg(&json!({}), &dir, None);
        assert!(a.allow(Kind::Dot, ip("8.8.8.8")));
        let s = a.status_json();
        assert_eq!(s["failOpen"], json!(true));
        assert!(s["warning"].as_str().unwrap().contains("讀不到"));
        std::fs::write(dir.join("geo/tw-ip.json"), b"{broken").unwrap();
        let a = Access::from_cfg(&json!({}), &dir, None);
        assert!(a.status_json()["warning"].as_str().unwrap().contains("格式錯誤"));
        assert!(a.allow(Kind::Dot, ip("8.8.8.8")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gate_and_counters() {
        let a = Access::new(st(json!({ "applyTo": ["dot", "doh"] })), Some(data()), "test".into(), None);
        assert!(!a.allow(Kind::Dot, ip("8.8.8.8")));
        assert!(a.allow(Kind::Doq, ip("8.8.8.8")), "沒套用的服務不擋");
        assert!(a.allow(Kind::Dot, ip("1.160.0.1")));
        assert!(!a.gate(&[Kind::Doh], ip("8.8.4.4")));
        assert!(a.gate(&[Kind::Doh, Kind::Site], ip("8.8.4.4")), "同一個埠的公開頁沒套用：先放行");
        assert!(!a.allow(Kind::Dot, ip("2001:4860::1")));
        let s = a.status_json();
        assert_eq!(s["denied"]["byListener"]["dot"], json!(2));
        assert_eq!(s["denied"]["byListener"]["doh"], json!(1));
        assert_eq!(s["denied"]["total"], json!(3));
        assert_eq!(
            s["topDenied"][0],
            json!({ "net": "8.8.4.0/24", "count": 1 }),
            "次數相同時依網段排序"
        );
        let nets: Vec<&str> = s["topDenied"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["net"].as_str().unwrap())
            .collect();
        assert!(nets.contains(&"8.8.4.0/24") && nets.contains(&"2001:4860::/48"), "{nets:?}");
        let api = a.api_json();
        assert_eq!(api["groups"].as_array().unwrap().len(), 3);
        assert_eq!(api["groups"][0]["enabled"], json!(true));
        assert_eq!(api["groups"][0]["size"]["v4"], json!((1u64 << 20) + (1 << 16)));
        // 好友 IP 換上去馬上生效
        a.set_friends(&[ip("8.8.8.8")]);
        assert!(a.allow(Kind::Dot, ip("8.8.8.8")));
        assert_eq!(a.check_json(ip("8.8.8.8"))["reason"], json!("社群好友目前的 IP"));
        a.set_friends(&[]);
        assert!(!a.allow(Kind::Dot, ip("8.8.8.8")));
    }

    #[test]
    fn auto_update_sanity() {
        let old = data();
        let mut bigger = (*old).clone();
        bigger.groups[0].nets = Dual::parse(["1.0.0.0/8"]).0;
        assert!(!sane_size(&old, &bigger), "差太多不接受");
        let mut close = (*old).clone();
        close.groups[2].nets = Dual::parse(["203.64.0.0/15"]).0;
        assert!(sane_size(&old, &close));
        // 下載的：要比目前的新、大小合理才換
        let mut later = close.clone();
        later.generated_at = "2026-12-01".into();
        assert!(accept_update(Some(&old), later.clone()).is_some());
        assert!(accept_update(Some(&old), close.clone()).is_none(), "日期一樣：不換");
        let mut huge = bigger.clone();
        huge.generated_at = "2026-12-01".into();
        assert!(accept_update(Some(&old), huge).is_none(), "差超過 20%：不換");
        assert!(accept_update(None, later).is_some(), "原本沒有資料：直接用");
        // 快照裡較新的資料（自動更新）優先，但只有開了 autoUpdate
        let dir = std::env::temp_dir().join(format!("kuroshio-access-up-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("geo")).unwrap();
        std::fs::write(
            dir.join("geo/tw-ip.json"),
            br#"{"generatedAt":"2026-10-01","groups":[{"id":"a","name":"A","v4":["1.0.0.0/16"]}]}"#,
        )
        .unwrap();
        let newer = br#"{"generatedAt":"2026-11-01","groups":[{"id":"a","name":"A","v4":["1.0.0.0/16","2.0.0.0/20"]}]}"#.to_vec();
        let a = Access::from_cfg(&json!({ "access": { "autoUpdate": true } }), &dir, Some(newer.clone()));
        assert_eq!(a.data().unwrap().generated_at, "2026-11-01");
        let a = Access::from_cfg(&json!({ "access": { "autoUpdate": false } }), &dir, Some(newer));
        assert_eq!(a.data().unwrap().generated_at, "2026-10-01");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shipped_data_loads_and_is_small() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/geo/tw-ip.json");
        let t = TwIp::parse(&std::fs::read(path).unwrap()).unwrap();
        let all = t.all();
        assert!(all.v4.size() > 30_000_000, "台灣 IPv4 大約 3,500 萬個位址");
        assert!(t.group("other").is_some() && t.group("cht").is_some());
        // 全部台灣網段：常見的台灣位址在裡面，國外的不在
        for tw in ["168.95.1.1", "140.112.8.116", "1.164.0.1"] {
            assert!(all.contains(ip(tw)), "{tw}");
        }
        for foreign in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"] {
            assert!(!all.contains(ip(foreign)), "{foreign}");
        }
        let r = Rules::build(&st(json!({})), Some(Arc::new(t)), Dual::default(), Dual::default());
        let (n, bytes) = r.footprint();
        assert!(n < 10_000, "{n} 個區間");
        assert!(bytes < 200 * 1024, "全部群組約 {bytes} 位元組");
    }
}
