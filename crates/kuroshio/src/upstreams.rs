//! 上游管理（對齊 2.x `lib/upstreams.js`）：固定上游永不淘汰、每日評測選出的自動上游、備援、最後手段。
//! 自動上游連續失敗 5 次就暫停（1 → 2 → 4 … 分鐘，最長 30 分鐘），成功一次就歸零。
//!
//! 3.4.0 串接模式（規格 10 的 1.6）：串接上游（`Role::Chain`）由串接模組用 [`Manager::set_chain`] 設定，
//! 不寫進設定檔。串接中只問串接上游＋固定上游；串接上游連續失敗 3 次暫停 30 秒，期間跟沒串接一樣。
//! 沒有串接上游時，所有行為跟 3.3.7 完全一樣。

use crate::upstream::{Kind, Upstream};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Pinned,
    Auto,
    Fallback,
    LastResort,
    /// 串接模式（3.4.0）：驗證過的上游黑潮，第一順位
    Chain,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Pinned => "pinned",
            Role::Auto => "auto",
            Role::Fallback => "fallback",
            Role::LastResort => "lastResort",
            Role::Chain => "chain",
        }
    }
}

/// 串接上游連續失敗幾次就暫停
pub const CHAIN_FAIL_LIMIT: u32 = 3;
/// 串接上游暫停多久
pub const CHAIN_PAUSE: Duration = Duration::from_secs(30);

/// 串接上游連續失敗時的通知（串接模組立刻補一次心跳）
pub type TroubleFn = Arc<dyn Fn() + Send + Sync>;

#[derive(Default)]
struct Trouble(RwLock<Option<TroubleFn>>);

impl std::fmt::Debug for Trouble {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Trouble")
    }
}

#[derive(Debug, Default)]
struct Stats {
    ok: u64,
    fail: u64,
    ewma: Option<f64>,
    consec_fail: u32,
    trips: u32,
    open_until: Option<Instant>,
}

#[derive(Debug)]
pub struct Up {
    pub up: Upstream,
    pub role: Role,
    stats: Mutex<Stats>,
    /// 每日評測選上的原因（最快、覆蓋）
    reason: Mutex<Option<String>>,
    /// 評測判斷的所在地區（ISO 國碼，3.4.0；沒有是 None）
    region: Mutex<Option<String>>,
    /// 只有串接上游：連續失敗時通知誰
    trouble: Option<Arc<Trouble>>,
}

impl Up {
    fn new(up: Upstream, role: Role) -> Arc<Up> {
        Arc::new(Up {
            up,
            role,
            stats: Mutex::new(Stats::default()),
            reason: Mutex::new(None),
            region: Mutex::new(None),
            trouble: None,
        })
    }

    fn new_chain(up: Upstream, trouble: Arc<Trouble>) -> Arc<Up> {
        Arc::new(Up {
            up,
            role: Role::Chain,
            stats: Mutex::new(Stats::default()),
            reason: Mutex::new(None),
            region: Mutex::new(None),
            trouble: Some(trouble),
        })
    }

    /// 路徑檢查（3.3.6）判斷現在不能用：協定整條被擋、IPv6 位址但這台沒有 IPv6
    pub fn path_blocked(&self) -> bool {
        use kuroshio_net::path::{self, Proto};
        let proto = match self.up.kind {
            Kind::Dot => Some(Proto::Dot),
            Kind::Doh => Some(Proto::Doh),
            Kind::Doq | Kind::Doh3 => Some(Proto::Quic),
            _ => None,
        };
        if proto.is_some_and(path::blocked) {
            return true;
        }
        matches!(self.up.host.parse::<std::net::IpAddr>(), Ok(ip) if !path::addr_usable(ip))
    }

    /// 一般 DNS 而且路上有攔截者：實際回答的是攔截者，不是這台。
    /// 串接上游不算（它就是我們要的那台，`decide()` 不能把它的答案排到後面）
    pub fn via_interceptor(&self) -> bool {
        self.role != Role::Chain
            && is_plain(self.up.kind)
            && self
                .up
                .host
                .parse::<std::net::IpAddr>()
                .is_ok_and(kuroshio_net::path::plain_intercepted_for)
    }

    fn paused(&self, now: Instant) -> bool {
        self.stats.lock().unwrap().open_until.map(|t| t > now).unwrap_or(false)
    }

    /// 平均延遲（毫秒）；還沒有成功紀錄是 None
    pub fn ewma(&self) -> Option<f64> {
        self.stats.lock().unwrap().ewma
    }

    pub fn record(&self, ok: bool, ms: f64) {
        let mut notify = None;
        self.record_inner(ok, ms, &mut notify);
        // 放掉 stats 的鎖之後才通知（回呼可能會讀這個上游的狀態）
        if let Some(f) = notify {
            f();
        }
    }

    fn record_inner(&self, ok: bool, ms: f64, notify: &mut Option<TroubleFn>) {
        let mut s = self.stats.lock().unwrap();
        if ok {
            s.ok += 1;
            s.consec_fail = 0;
            s.trips = 0;
            s.ewma = Some(s.ewma.map(|e| e * 0.8 + ms * 0.2).unwrap_or(ms));
        } else {
            s.fail += 1;
            s.consec_fail += 1;
            let now = Instant::now();
            if self.role == Role::Auto && s.consec_fail >= 5 && s.open_until.map(|t| t < now).unwrap_or(true) {
                s.trips += 1;
                let min = 30u64.min(1 << (s.trips - 1).min(5));
                s.open_until = Some(now + Duration::from_secs(min * 60));
                s.consec_fail = 0;
                warn!(
                    "{} 連續失敗，暫停 {min} 分鐘{}",
                    self.up.id,
                    if s.ok > 0 { "" } else { "（上線以來從未成功）" }
                );
            }
            if self.role == Role::Chain && s.consec_fail >= CHAIN_FAIL_LIMIT {
                s.open_until = Some(now + CHAIN_PAUSE);
                s.consec_fail = 0;
                warn!(
                    "串接：上游黑潮 {} 連續失敗 {CHAIN_FAIL_LIMIT} 次，暫停 {} 秒，先用自己的上游",
                    self.up.id,
                    CHAIN_PAUSE.as_secs()
                );
                *notify = self.trouble.as_ref().and_then(|t| t.0.read().unwrap().clone());
            }
        }
    }

    pub fn json(&self) -> Value {
        let s = self.stats.lock().unwrap();
        json!({
            "id": self.up.id, "type": kind_name(self.up.kind), "role": self.role.name(),
            "ok": s.ok, "fail": s.fail,
            "avgMs": s.ewma.map(|e| (e * 10.0).round() / 10.0),
            "paused": s.open_until.map(|t| t > Instant::now()).unwrap_or(false),
            // 3.3.6：選上的原因、路徑檢查判斷不能用、經由攔截者（一般 DNS 被接走時）
            "reason": self.reason.lock().unwrap().clone(),
            "region": self.region.lock().unwrap().clone(),
            "pathBlocked": self.path_blocked(),
            "via": if self.via_interceptor() { Value::from("interceptor") } else { Value::Null },
        })
    }
}

pub fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Udp => "udp",
        Kind::Tcp => "tcp",
        Kind::Dot => "dot",
        Kind::Doh => "doh",
        Kind::Doh3 => "doh3",
        Kind::Doq => "doq",
        Kind::DnsCrypt => "dnscrypt",
    }
}

/// 明文上游（UDP / TCP）：不需要 TLS，系統時間沒對時也能用
pub fn is_plain(k: Kind) -> bool {
    matches!(k, Kind::Udp | Kind::Tcp)
}

/// 純函式（3.4.0 串接模式，規格 1.6）：(主要上游, 備援)。之後主要上游再過 [`select_active`]。
///
/// - 沒有串接上游：固定 + 自動；備援 = 備援 + 最後手段（3.3.7 的行為）
/// - 串接中、沒暫停：[串接上游] + 固定上游（自動上游不問）；備援 = 自動 + 備援 + 最後手段
/// - 串接上游暫停中：主要上游跟沒串接時一樣；備援 = 備援 + 最後手段
///
/// 串接時備援都去掉 `via_interceptor()` 為真的（一般 DNS 會回到同一台掛掉的上游）。
/// `auto` 是已經去掉暫停中、路徑檢查判斷不能用的自動上游。
pub fn select_chain(
    chain: Option<&Arc<Up>>,
    suspended: bool,
    pinned: &[Arc<Up>],
    auto: Vec<Arc<Up>>,
    fallback: &[Arc<Up>],
    last_resort: &[Arc<Up>],
) -> (Vec<Arc<Up>>, Vec<Arc<Up>>) {
    let rest = || fallback.iter().chain(last_resort).cloned();
    let Some(chain) = chain else {
        let mut active = pinned.to_vec();
        active.extend(auto);
        return (active, rest().collect());
    };
    let independent = |v: Vec<Arc<Up>>| -> Vec<Arc<Up>> { v.into_iter().filter(|u| !u.via_interceptor()).collect() };
    if suspended {
        let mut active = pinned.to_vec();
        active.extend(auto);
        return (active, independent(rest().collect()));
    }
    let mut active = vec![chain.clone()];
    active.extend(pinned.iter().filter(|p| !Arc::ptr_eq(p, chain)).cloned());
    let backup = independent(auto.into_iter().chain(rest()).collect());
    (active, backup)
}

/// 純函式：這次查詢要用的上游。
/// - 已對時：`list`（固定 + 自動），空的就用備援（原本的行為）
/// - 沒對時：加密上游的憑證驗不過，只留明文的；`list` 裡沒有明文上游時依序改用備援、最後手段裡的明文上游。
///   加密上游完全不問，所以也不會被記成失敗、暫停
pub fn select_active(list: Vec<Arc<Up>>, fallback: &[Arc<Up>], last_resort: &[Arc<Up>], synced: bool) -> Vec<Arc<Up>> {
    if synced {
        return if list.is_empty() { fallback.to_vec() } else { list };
    }
    let plain = |v: &[Arc<Up>]| -> Vec<Arc<Up>> { v.iter().filter(|u| is_plain(u.up.kind)).cloned().collect() };
    for v in [plain(&list), plain(fallback), plain(last_resort)] {
        if !v.is_empty() {
            return v;
        }
    }
    Vec::new()
}

fn build(specs: &[String], role: Role) -> Vec<Arc<Up>> {
    let mut out = Vec::new();
    for s in specs {
        match Upstream::parse(s) {
            Ok(u) if u.supported() => out.push(Up::new(u, role)),
            Ok(u) => warn!("這個版本還不支援 {}，略過", u.id),
            Err(e) => warn!("無法解析上游 {s}：{e}"),
        }
    }
    out
}

struct Auto {
    list: Vec<Arc<Up>>,
    generated_at: Option<String>,
    mtime: Option<SystemTime>,
}

pub struct Manager {
    pub pinned: Vec<Arc<Up>>,
    pub fallback: Vec<Arc<Up>>,
    pub last_resort: Vec<Arc<Up>>,
    auto: RwLock<Auto>,
    state_file: PathBuf,
    auto_types: Vec<String>,
    auto_max: usize,
    /// 串接上游（3.4.0）：由串接模組設定，不寫進設定檔
    chain: RwLock<Option<Arc<Up>>>,
    chain_trouble: Arc<Trouble>,
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

impl Manager {
    pub fn new(cfg: &Value, state_file: PathBuf) -> Manager {
        let g = |k| kuroshio_config::get(cfg, k);
        let m = Manager {
            pinned: build(&strings(g("upstream.pinned")), Role::Pinned),
            fallback: build(&strings(g("upstream.fallback")), Role::Fallback),
            last_resort: build(&strings(g("resolver.lastResort")), Role::LastResort),
            auto: RwLock::new(Auto {
                list: Vec::new(),
                generated_at: None,
                mtime: None,
            }),
            state_file,
            auto_types: strings(g("upstream.autoTypes")),
            auto_max: g("upstream.autoMax").and_then(Value::as_u64).unwrap_or(6) as usize,
            chain: RwLock::new(None),
            chain_trouble: Arc::new(Trouble::default()),
        };
        m.reload_auto();
        m
    }

    /// 讀每日評測結果；檔案沒變就不重讀
    pub fn reload_auto(&self) {
        let mtime = std::fs::metadata(&self.state_file).and_then(|m| m.modified()).ok();
        if mtime.is_some() && mtime == self.auto.read().unwrap().mtime {
            return;
        }
        let st: Option<Value> = std::fs::read(&self.state_file).ok().and_then(|b| serde_json::from_slice(&b).ok());
        let Some(st) = st.filter(|v| v.get("selected").map(Value::is_array).unwrap_or(false)) else {
            let mut a = self.auto.write().unwrap();
            if a.mtime.is_none() && a.generated_at.is_none() {
                warn!("尚無每日評測結果（{}），暫時只用固定上游與備援", self.state_file.display());
            }
            a.mtime = mtime;
            return;
        };
        let pinned: Vec<&str> = self.pinned.iter().map(|p| p.up.id.as_str()).collect();
        let old: Vec<Arc<Up>> = self.auto.read().unwrap().list.clone();
        let mut list = Vec::new();
        for s in st["selected"].as_array().unwrap() {
            // 先檢查上限：autoMax = 0 時一台都不載入（以前先 push 才檢查，0 也會載入 1 台）
            if list.len() >= self.auto_max {
                break;
            }
            let (Some(id), ty) = (
                s.get("id").and_then(Value::as_str),
                s.get("type").and_then(Value::as_str).unwrap_or("udp"),
            ) else {
                continue;
            };
            if !self.auto_types.iter().any(|t| t == ty) {
                continue;
            }
            let Ok(u) = Upstream::parse(id) else { continue };
            if pinned.contains(&u.id.as_str()) || !u.supported() {
                continue;
            }
            let up = old
                .iter()
                .find(|o| o.up.id == u.id)
                .cloned()
                .unwrap_or_else(|| Up::new(u, Role::Auto));
            *up.reason.lock().unwrap() = s.get("reason").and_then(Value::as_str).map(str::to_string);
            // 上游多樣性（3.4.0）：評測判斷的所在地區
            *up.region.lock().unwrap() = s
                .get("region")
                .and_then(Value::as_str)
                .filter(|r| !r.is_empty())
                .map(str::to_string);
            list.push(up);
        }
        let generated_at = st.get("generatedAt").and_then(Value::as_str).map(str::to_string);
        info!(
            "自動上游已載入（{}）：{}",
            generated_at.as_deref().unwrap_or("?"),
            if list.is_empty() {
                "無".to_string()
            } else {
                list.iter().map(|u| u.up.id.clone()).collect::<Vec<_>>().join(", ")
            }
        );
        *self.auto.write().unwrap() = Auto { list, generated_at, mtime };
    }

    /// 這次查詢要用的上游：固定上游一律參與、暫停中的自動上游跳過；都沒有就用備援。
    /// 系統時間還沒對時（見 `crate::clock`）：只用明文上游，見 [`select_active`]。
    /// 串接中（3.4.0）：串接上游 + 固定上游，見 [`select_chain`]
    pub fn active(&self) -> Vec<Arc<Up>> {
        let (list, _) = self.select();
        select_active(list, &self.fallback, &self.last_resort, crate::clock::synced())
    }

    /// 主要上游都失敗時改問的：備援 + 最後手段（沒對時只用其中的明文上游）；
    /// 串接中另外加上自己的自動上游（上游黑潮掛掉時退回自己的加密上游，固定行為）
    pub fn backup(&self) -> Vec<Arc<Up>> {
        let synced = crate::clock::synced();
        let (_, backup) = self.select();
        backup.into_iter().filter(|u| synced || is_plain(u.up.kind)).collect()
    }

    fn select(&self) -> (Vec<Arc<Up>>, Vec<Arc<Up>>) {
        let now = Instant::now();
        // 路徑檢查判斷不能用的（協定被擋、沒有 IPv6）先不用；路恢復了（下一次檢查）自動加回
        let auto: Vec<Arc<Up>> = self
            .auto
            .read()
            .unwrap()
            .list
            .iter()
            .filter(|u| !u.paused(now) && !u.path_blocked())
            .cloned()
            .collect();
        let chain = self.chain();
        let suspended = chain.as_ref().is_some_and(|c| c.role == Role::Chain && c.paused(now));
        select_chain(chain.as_ref(), suspended, &self.pinned, auto, &self.fallback, &self.last_resort)
    }

    /// 設定／清除串接上游（串接模組在綁定、解除時呼叫）。跟某個固定上游的 `id` 相同時不新增：
    /// 那個固定上游就當成串接上游（`chain()` 回它，角色維持 `Pinned`，不暫停）
    pub fn set_chain(&self, up: Option<Upstream>) {
        let mut c = self.chain.write().unwrap();
        let Some(u) = up else {
            *c = None;
            return;
        };
        if c.as_ref().is_some_and(|x| x.up.id == u.id) {
            return;
        }
        *c = Some(match self.pinned.iter().find(|p| p.up.id == u.id) {
            Some(p) => p.clone(),
            None => Up::new_chain(u, self.chain_trouble.clone()),
        });
    }

    /// 目前的串接上游
    pub fn chain(&self) -> Option<Arc<Up>> {
        self.chain.read().unwrap().clone()
    }

    /// 串接上游連續失敗後的 30 秒暫停中
    pub fn chain_suspended(&self) -> bool {
        self.chain().is_some_and(|c| c.role == Role::Chain && c.paused(Instant::now()))
    }

    /// 串接上游連續失敗 3 次時呼叫（通知串接模組補心跳）
    pub fn on_chain_trouble(&self, f: TroubleFn) {
        *self.chain_trouble.0.write().unwrap() = Some(f);
    }

    pub fn list_json(&self) -> Value {
        let auto = self.auto.read().unwrap();
        // 串接上游排第一個（跟固定上游相同的那種已經在固定上游裡，不重複列）
        let chain = self.chain().filter(|c| c.role == Role::Chain);
        Value::Array(
            chain
                .iter()
                .chain(&self.pinned)
                .chain(&auto.list)
                .chain(&self.fallback)
                .map(|u| u.json())
                .collect(),
        )
    }

    /// 社群分享用：每日評測選出、而且實際用過有成功的上游（網址、協議、平均毫秒、成功率）
    pub fn auto_shared(&self) -> Vec<(String, String, Option<u32>, f32)> {
        self.auto
            .read()
            .unwrap()
            .list
            .iter()
            .filter_map(|u| {
                let s = u.stats.lock().unwrap();
                let total = s.ok + s.fail;
                (s.ok > 0).then(|| {
                    (
                        u.up.id.clone(),
                        kind_name(u.up.kind).to_string(),
                        s.ewma.map(|e| e.round() as u32),
                        s.ok as f32 / total.max(1) as f32,
                    )
                })
            })
            .take(50)
            .collect()
    }

    pub fn auto_info(&self) -> Value {
        let a = self.auto.read().unwrap();
        match &a.generated_at {
            Some(g) => json!({ "generatedAt": g, "count": a.list.len() }),
            None => Value::Null,
        }
    }

    pub fn state_file(&self) -> &Path {
        &self.state_file
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Value {
        kuroshio_config::with_overrides(&json!({
            "upstream": { "pinned": ["udp://10.0.0.1"], "fallback": ["udp://1.0.0.2"], "autoTypes": ["udp", "doh"], "autoMax": 2 },
            "resolver": { "lastResort": ["udp://8.8.8.8"] }
        }))
    }

    /// autoMax = 0：一台自動上游都不載入；selected[].region 帶到狀態
    #[test]
    fn auto_max_zero_and_region() {
        let dir = std::env::temp_dir().join(format!("kuroshio-up0-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("upstreams.json");
        std::fs::write(
            &f,
            r#"{"generatedAt":"2026-11-10 04:30","selected":[
                {"id":"udp://192.0.2.10","type":"udp","region":"TW","near":true},
                {"id":"udp://192.0.2.11","type":"udp","region":""}]}"#,
        )
        .unwrap();
        let mut c = cfg();
        c["upstream"]["autoMax"] = json!(0);
        let m = Manager::new(&c, f.clone());
        assert_eq!(m.active().len(), 1, "只有固定上游");
        let m = Manager::new(&cfg(), f);
        let list = m.list_json();
        let by = |id: &str| list.as_array().unwrap().iter().find(|u| u["id"] == id).cloned().unwrap();
        assert_eq!(by("udp://192.0.2.10:53")["region"], "TW");
        assert_eq!(by("udp://192.0.2.11:53")["region"], Value::Null);
    }

    #[test]
    fn auto_list_and_breaker() {
        let dir = std::env::temp_dir().join(format!("kuroshio-up-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("upstreams.json");
        std::fs::write(
            &f,
            r#"{"generatedAt":"2026-11-10 04:30","selected":[
                {"id":"udp://10.0.0.1","type":"udp"},
                {"id":"tls://dns.example","type":"dot"},
                {"id":"udp://168.95.1.1","type":"udp"},
                {"id":"udp://101.101.101.101","type":"udp"},
                {"id":"udp://9.9.9.9","type":"udp"}]}"#,
        )
        .unwrap();
        let m = Manager::new(&cfg(), f.clone());
        let ids: Vec<String> = m.active().iter().map(|u| u.up.id.clone()).collect();
        // 固定上游在前；評測結果裡跟固定上游重複的、類型不允許的略過；最多 autoMax 個
        assert_eq!(ids, vec!["udp://10.0.0.1:53", "udp://168.95.1.1:53", "udp://101.101.101.101:53"]);
        assert_eq!(m.backup().len(), 2);

        // 自動上游連續失敗 5 次 → 暫停
        let a = m.active()[1].clone();
        for _ in 0..5 {
            a.record(false, 0.0);
        }
        assert_eq!(m.active().len(), 2);
        assert_eq!(a.json()["paused"], json!(true));
        // 固定上游永不暫停
        for _ in 0..20 {
            m.pinned[0].record(false, 0.0);
        }
        assert_eq!(m.active()[0].up.id, "udp://10.0.0.1:53");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unsynced_clock_uses_plain_only() {
        let ups = |specs: &[&str], role| build(&specs.iter().map(|s| s.to_string()).collect::<Vec<_>>(), role);
        let ids = |v: Vec<Arc<Up>>| v.iter().map(|u| u.up.id.clone()).collect::<Vec<_>>();
        let list = ups(
            &["https://dns.example.net/dns-query", "udp://192.0.2.1", "tls://dns.example.com"],
            Role::Auto,
        );
        let fb = ups(&["https://dns.example.org/dns-query", "udp://198.51.100.1"], Role::Fallback);
        let lr = ups(&["tcp://203.0.113.1"], Role::LastResort);
        // 已對時：原本的行為
        assert_eq!(select_active(list.clone(), &fb, &lr, true).len(), 3);
        assert_eq!(ids(select_active(vec![], &fb, &lr, true)).len(), 2);
        // 沒對時：只留明文的
        assert_eq!(ids(select_active(list.clone(), &fb, &lr, false)), vec!["udp://192.0.2.1:53"]);
        // 主要上游全是加密的：改用備援裡的明文上游，再沒有就用最後手段
        let enc = ups(&["https://dns.example.net/dns-query", "quic://dns.example.com"], Role::Pinned);
        assert_eq!(ids(select_active(enc.clone(), &fb, &lr, false)), vec!["udp://198.51.100.1:53"]);
        let fb_enc = ups(&["https://dns.example.org/dns-query"], Role::Fallback);
        assert_eq!(ids(select_active(enc.clone(), &fb_enc, &lr, false)), vec!["tcp://203.0.113.1:53"]);
        // 全都是加密的：不問（問了也只會憑證錯誤、把上游記成失敗）
        assert!(select_active(enc, &fb_enc, &[], false).is_empty());
    }

    #[test]
    fn no_state_uses_pinned_or_fallback() {
        let m = Manager::new(&cfg(), PathBuf::from("/nonexistent/upstreams.json"));
        assert_eq!(m.active().len(), 1);
        let c = kuroshio_config::with_overrides(&json!({ "upstream": { "pinned": [], "fallback": ["udp://1.0.0.2"] } }));
        let m = Manager::new(&c, PathBuf::from("/nonexistent/upstreams.json"));
        assert_eq!(m.active()[0].role, Role::Fallback);
    }

    fn ups(specs: &[&str], role: Role) -> Vec<Arc<Up>> {
        build(&specs.iter().map(|s| s.to_string()).collect::<Vec<_>>(), role)
    }

    fn ids(v: &[Arc<Up>]) -> Vec<String> {
        v.iter().map(|u| u.up.id.clone()).collect()
    }

    fn chain_up(spec: &str) -> Arc<Up> {
        Up::new_chain(Upstream::parse(spec).unwrap(), Arc::new(Trouble::default()))
    }

    #[test]
    fn chain_active_and_backup_rules() {
        let pinned = ups(&["tls://dns.example.com"], Role::Pinned);
        let auto = ups(&["https://dns.example.net/dns-query", "udp://203.0.113.53"], Role::Auto);
        let fb = ups(&["udp://198.51.100.53"], Role::Fallback);
        let lr = ups(&["tcp://192.0.2.53"], Role::LastResort);
        let chain = chain_up("udp://192.168.1.1:53");

        // 沒有串接上游：跟 3.3.7 一樣（固定 + 自動；備援 + 最後手段）
        let (a, b) = select_chain(None, false, &pinned, auto.clone(), &fb, &lr);
        assert_eq!(ids(&a), [ids(&pinned), ids(&auto)].concat());
        assert_eq!(ids(&b), [ids(&fb), ids(&lr)].concat());

        // 串接中、健康：只有串接上游 + 固定上游；自動上游移到備援
        let (a, b) = select_chain(Some(&chain), false, &pinned, auto.clone(), &fb, &lr);
        assert_eq!(
            ids(&a),
            vec!["udp://192.168.1.1:53".to_string(), "tls://dns.example.com:853".into()]
        );
        assert_eq!(a[0].role, Role::Chain);
        assert!(ids(&b).contains(&"https://dns.example.net/dns-query".to_string()), "{:?}", ids(&b));
        assert!(b.iter().all(|u| u.role != Role::Chain));

        // 暫停中：主要上游跟沒串接時一樣
        let (a, _) = select_chain(Some(&chain), true, &pinned, auto.clone(), &fb, &lr);
        assert_eq!(ids(&a), [ids(&pinned), ids(&auto)].concat());

        // 一般 DNS 被接走：備援去掉經由攔截者的明文上游，留下自己的加密上游
        let mut r = kuroshio_net::path::Report::default();
        r.plain_v4.udp = true;
        kuroshio_net::path::apply(&r, false);
        let (_, b) = select_chain(Some(&chain), false, &pinned, auto.clone(), &fb, &lr);
        assert_eq!(ids(&b), vec!["https://dns.example.net/dns-query".to_string()]);
        assert!(!chain.via_interceptor(), "串接上游不算經由攔截者");
        let (_, b) = select_chain(None, false, &pinned, auto.clone(), &fb, &lr);
        assert_eq!(b.len(), 2, "沒串接時備援照舊");
        kuroshio_net::path::clear();
    }

    #[test]
    fn chain_breaker_trips_after_three() {
        let m = Manager::new(&cfg(), PathBuf::from("/nonexistent/upstreams.json"));
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let n2 = n.clone();
        m.on_chain_trouble(Arc::new(move || {
            n2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
        m.set_chain(Some(Upstream::parse("udp://192.168.1.1:53").unwrap()));
        let c = m.chain().unwrap();
        assert_eq!(m.active()[0].role, Role::Chain);
        c.record(false, 0.0);
        c.record(false, 0.0);
        c.record(true, 5.0);
        c.record(false, 0.0);
        c.record(false, 0.0);
        assert!(!m.chain_suspended(), "成功一次就歸零");
        c.record(false, 0.0);
        assert!(m.chain_suspended());
        assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 1, "回呼被呼叫一次");
        assert!(m.active().iter().all(|u| u.role != Role::Chain), "暫停中不問串接上游");
        assert_eq!(c.json()["role"], "chain");
        assert_eq!(m.list_json()[0]["role"], "chain");
        m.set_chain(None);
        assert!(m.chain().is_none() && !m.chain_suspended());
    }

    #[test]
    fn chain_same_as_pinned_not_duplicated() {
        let m = Manager::new(&cfg(), PathBuf::from("/nonexistent/upstreams.json"));
        m.set_chain(Some(Upstream::parse("udp://10.0.0.1").unwrap()));
        let a = m.active();
        assert_eq!(ids(&a), vec!["udp://10.0.0.1:53"]);
        assert_eq!(m.chain().unwrap().role, Role::Pinned, "角色維持固定上游");
        assert_eq!(m.list_json().as_array().unwrap().len(), 2, "固定 + 備援，沒有重複");
        // 固定上游永不暫停
        for _ in 0..10 {
            m.chain().unwrap().record(false, 0.0);
        }
        assert!(!m.chain_suspended());
    }

    #[test]
    fn unsynced_clock_keeps_chain() {
        let pinned = ups(&["https://dns.example.com/dns-query"], Role::Pinned);
        let chain = chain_up("udp://192.168.1.1:53");
        let (a, _) = select_chain(Some(&chain), false, &pinned, vec![], &[], &[]);
        let a = select_active(a, &[], &[], false);
        assert_eq!(ids(&a), vec!["udp://192.168.1.1:53"], "串接上游是明文，沒對時也能用");
        let tcp = chain_up("tcp://192.168.1.1:53");
        let (a, _) = select_chain(Some(&tcp), false, &pinned, vec![], &[], &[]);
        assert_eq!(select_active(a, &[], &[], false)[0].role, Role::Chain);
    }
}
