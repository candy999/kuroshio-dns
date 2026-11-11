//! 上游管理（對齊 2.x `lib/upstreams.js`）：固定上游永不淘汰、每日評測選出的自動上游、備援、最後手段。
//! 自動上游連續失敗 5 次就暫停（1 → 2 → 4 … 分鐘，最長 30 分鐘），成功一次就歸零。

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
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Pinned => "pinned",
            Role::Auto => "auto",
            Role::Fallback => "fallback",
            Role::LastResort => "lastResort",
        }
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
}

impl Up {
    fn new(up: Upstream, role: Role) -> Arc<Up> {
        Arc::new(Up {
            up,
            role,
            stats: Mutex::new(Stats::default()),
        })
    }

    fn paused(&self, now: Instant) -> bool {
        self.stats.lock().unwrap().open_until.map(|t| t > now).unwrap_or(false)
    }

    /// 平均延遲（毫秒）；還沒有成功紀錄是 None
    pub fn ewma(&self) -> Option<f64> {
        self.stats.lock().unwrap().ewma
    }

    pub fn record(&self, ok: bool, ms: f64) {
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
        }
    }

    pub fn json(&self) -> Value {
        let s = self.stats.lock().unwrap();
        json!({
            "id": self.up.id, "type": kind_name(self.up.kind), "role": self.role.name(),
            "ok": s.ok, "fail": s.fail,
            "avgMs": s.ewma.map(|e| (e * 10.0).round() / 10.0),
            "paused": s.open_until.map(|t| t > Instant::now()).unwrap_or(false),
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
            list.push(
                old.iter()
                    .find(|o| o.up.id == u.id)
                    .cloned()
                    .unwrap_or_else(|| Up::new(u, Role::Auto)),
            );
            if list.len() >= self.auto_max {
                break;
            }
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

    /// 這次查詢要用的上游：固定上游一律參與、暫停中的自動上游跳過；都沒有就用備援
    pub fn active(&self) -> Vec<Arc<Up>> {
        let now = Instant::now();
        let mut list: Vec<Arc<Up>> = self.pinned.clone();
        list.extend(self.auto.read().unwrap().list.iter().filter(|u| !u.paused(now)).cloned());
        if list.is_empty() {
            self.fallback.clone()
        } else {
            list
        }
    }

    /// 主要上游都失敗時改問的：備援 + 最後手段
    pub fn backup(&self) -> Vec<Arc<Up>> {
        self.fallback.iter().chain(&self.last_resort).cloned().collect()
    }

    pub fn list_json(&self) -> Value {
        let auto = self.auto.read().unwrap();
        Value::Array(
            self.pinned
                .iter()
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
    fn no_state_uses_pinned_or_fallback() {
        let m = Manager::new(&cfg(), PathBuf::from("/nonexistent/upstreams.json"));
        assert_eq!(m.active().len(), 1);
        let c = kuroshio_config::with_overrides(&json!({ "upstream": { "pinned": [], "fallback": ["udp://1.0.0.2"] } }));
        let m = Manager::new(&c, PathBuf::from("/nonexistent/upstreams.json"));
        assert_eq!(m.active()[0].role, Role::Fallback);
    }
}
