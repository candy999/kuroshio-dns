//! 過濾服務：自訂規則與訂閱清單分成兩份過濾器（規格 05 第 3.2 節、2.x 的 filter.js）
//!
//! - 自訂規則永遠先比對，命中就不看清單（2.x「自訂規則是最高原則」）
//! - 自訂規則檔存檔後 3 秒內生效，不必重新下載清單
//! - 清單邊下載邊解析；任何一份下載失敗就保留舊的過濾器（第一次載入除外），30 分鐘後重試
//! - 清單都沒變（全部 304）就不重建；有變就整個重建，建好才替換（尖峰 = 新舊兩份並存）

use crate::fetch::{self, Outcome, Validators};
use crate::resolver::{FilterCheck, Verdict};
use kuroshio_filter::{BuildOptions, Category, Filter, FilterBuilder, ListSpec, SourceStatus};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

/// 安裝時附帶的預設自訂規則（設定的自訂規則檔不存在時寫出這份）
pub const DEFAULT_CUSTOM_RULES: &str = include_str!("../../../rules/default-custom-rules.txt");

#[derive(Debug, Clone)]
pub struct ListSource {
    pub url: String,
    pub name: String,
    pub category: Category,
}

pub struct FilterService {
    opts: BuildOptions,
    custom_paths: Vec<PathBuf>,
    sources: Vec<ListSource>,
    custom: RwLock<Arc<Filter>>,
    lists: RwLock<Arc<Filter>>,
    custom_mtime: Mutex<Vec<Option<SystemTime>>>,
    validators: Mutex<Vec<Validators>>,
    status: Mutex<Value>,
    pub interval: Duration,
    max_bytes: u64,
}

impl FilterService {
    pub fn from_cfg(cfg: &Value, base_dir: &Path) -> Option<Arc<FilterService>> {
        let g = |k: &str| kuroshio_config::get(cfg, &format!("filter.{k}"));
        if g("enabled").and_then(Value::as_bool) == Some(false) {
            return None;
        }
        let custom_paths: Vec<PathBuf> = g("customRules")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(|p| resolve(base_dir, p)).collect())
            .unwrap_or_default();
        let sources: Vec<ListSource> = g("lists")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter(|l| l.get("enabled") != Some(&Value::Bool(false)))
                    .filter_map(|l| {
                        let url = l.get("url")?.as_str()?.to_string();
                        let category = l
                            .get("category")
                            .and_then(Value::as_str)
                            .and_then(Category::parse)
                            .filter(|c| *c != Category::Custom)
                            .unwrap_or(Category::Ads);
                        let name = l.get("name").and_then(Value::as_str).unwrap_or(&url).to_string();
                        Some(ListSource { url, name, category })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let opts = BuildOptions {
            max_domains: g("maxDomains").and_then(Value::as_u64).unwrap_or(10_000_000),
            max_complex: g("maxComplex").and_then(Value::as_u64).unwrap_or(20_000),
            relaxed_modifiers: g("relaxedModifiers").and_then(Value::as_bool).unwrap_or(false),
        };
        let hours = g("updateIntervalHours").and_then(Value::as_u64).unwrap_or(24).max(1);
        let n = sources.len();
        Some(Arc::new(FilterService {
            opts,
            custom_mtime: Mutex::new(vec![None; custom_paths.len()]),
            custom_paths,
            sources,
            custom: RwLock::new(Arc::new(Filter::empty())),
            lists: RwLock::new(Arc::new(Filter::empty())),
            validators: Mutex::new(vec![Validators::default(); n]),
            status: Mutex::new(json!({ "updatedAt": null, "errors": [] })),
            interval: Duration::from_secs(hours * 3600),
            max_bytes: 64 << 20,
        }))
    }

    /// 自訂規則檔有變就重建（第一次呼叫一定建）；設定的檔案不存在時寫出預設規則
    pub fn reload_custom(&self, force: bool) -> bool {
        let mtimes: Vec<Option<SystemTime>> = self
            .custom_paths
            .iter()
            .map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
            .collect();
        {
            let mut cur = self.custom_mtime.lock().unwrap();
            if !force && *cur == mtimes {
                return false;
            }
            *cur = mtimes;
        }
        let mut b = FilterBuilder::new(BuildOptions {
            max_domains: u64::MAX,
            ..self.opts
        });
        {
            let mut w = b.custom();
            for p in &self.custom_paths {
                match std::fs::read(p) {
                    Ok(bytes) => {
                        w.feed(&bytes);
                        w.feed(b"\n");
                    }
                    Err(_) if !p.exists() => {
                        if let Some(dir) = p.parent() {
                            let _ = std::fs::create_dir_all(dir);
                        }
                        match std::fs::write(p, DEFAULT_CUSTOM_RULES) {
                            Ok(()) => info!("自訂規則檔 {} 不存在，寫入預設規則", p.display()),
                            Err(e) => warn!("自訂規則檔 {} 不存在，也無法建立：{e}（先用預設規則）", p.display()),
                        }
                        w.feed(DEFAULT_CUSTOM_RULES.as_bytes());
                    }
                    Err(e) => warn!("讀不到自訂規則 {}：{e}", p.display()),
                }
            }
        }
        let f = b.finish();
        info!("自訂規則已載入：{} 條", f.stats().custom);
        *self.custom.write().unwrap() = Arc::new(f);
        true
    }

    /// 更新訂閱清單；回傳是否重建。`force` = 不管有沒有變都重新下載
    pub async fn update_lists(&self, force: bool) -> anyhow::Result<bool> {
        if self.sources.is_empty() {
            *self.lists.write().unwrap() = Arc::new(Filter::empty());
            return Ok(false);
        }
        let timeout = Duration::from_secs(30);
        let have = self.lists.read().unwrap().stats().lists > 0;
        // 1. 都有驗證資訊時先問「有沒有變」：全部 304 就不重建
        let prev = self.validators.lock().unwrap().clone();
        if !force && have && prev.iter().all(|v| v.etag.is_some() || v.last_modified.is_some()) {
            let mut changed = false;
            for (s, v) in self.sources.iter().zip(&prev) {
                match fetch::get(&s.url, v, self.max_bytes, timeout, |_| Ok(())).await {
                    Ok(Outcome::NotModified) => {}
                    _ => {
                        changed = true;
                        break;
                    }
                }
            }
            if !changed {
                self.status.lock().unwrap()["checkedAt"] = json!(crate::persist::now_secs() * 1000);
                return Ok(false);
            }
        }
        // 2. 重建：自訂規則的網域數也算在預算裡
        let custom_n = self.custom.read().unwrap().stats().custom;
        let mut b = FilterBuilder::new(BuildOptions {
            max_domains: self.opts.max_domains.saturating_sub(custom_n),
            ..self.opts
        });
        let mut errors = Vec::new();
        let mut validators = Vec::new();
        for s in &self.sources {
            let mut w = b.list(ListSpec::new(s.name.clone(), s.category))?;
            let r = fetch::get(&s.url, &Validators::default(), self.max_bytes, timeout, |c| {
                w.feed(c);
                Ok(())
            })
            .await;
            w.end();
            match r {
                Ok(Outcome::Done { validators: v, .. }) => validators.push(v),
                Ok(Outcome::NotModified) => validators.push(Validators::default()),
                Err(e) => {
                    warn!("下載清單「{}」失敗：{e}", s.name);
                    errors.push(json!({ "name": s.name, "url": s.url, "error": e.to_string() }));
                    validators.push(Validators::default());
                }
            }
        }
        let f = b.finish();
        let st = f.stats();
        for s in st.over_budget() {
            if let SourceStatus::OverBudget { rules, remaining } = s.status {
                warn!("清單「{}」超過記憶體預算，未載入（{rules} 條，剩餘額度 {remaining}）", s.name);
            }
        }
        if !errors.is_empty() && have {
            // 有清單下載失敗：保留舊的，避免少掉一整份清單
            self.status.lock().unwrap()["errors"] = json!(errors);
            anyhow::bail!("{} 份清單下載失敗，保留舊的過濾器", errors.len());
        }
        info!(
            "訂閱清單已載入：{} 條（廣告 {}、遙測 {}、惡意 {}），約 {} KB",
            st.lists,
            st.by_category.get(Category::Ads),
            st.by_category.get(Category::Telemetry),
            st.by_category.get(Category::Malware),
            f.memory_bytes() / 1024
        );
        *self.lists.write().unwrap() = Arc::new(f);
        *self.validators.lock().unwrap() = validators;
        let mut status = self.status.lock().unwrap();
        status["updatedAt"] = json!(crate::persist::now_secs() * 1000);
        status["errors"] = json!(errors);
        Ok(true)
    }

    /// 背景工作：清單定時更新、自訂規則每 3 秒檢查
    pub fn spawn(self: &Arc<Self>) {
        self.reload_custom(true);
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                me.reload_custom(false);
            }
        });
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            loop {
                // 記憶體吃緊時延後（重建時新舊兩份會同時存在）
                let wait = if crate::app::pressure() == crate::sysinfo::Pressure::Critical {
                    warn!("記憶體不足，延後更新過濾清單");
                    Duration::from_secs(1800)
                } else {
                    match me.update_lists(false).await {
                        Ok(_) => me.interval,
                        Err(e) => {
                            warn!("{e:#}；30 分鐘後重試");
                            Duration::from_secs(1800)
                        }
                    }
                };
                tokio::time::sleep(wait).await;
            }
        });
    }
}

fn resolve(base: &Path, p: &str) -> PathBuf {
    let p = Path::new(p);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p.strip_prefix("./").unwrap_or(p))
    }
}

fn verdict(v: kuroshio_filter::Verdict<'_>) -> Verdict {
    Verdict {
        block: v.is_block(),
        allow: v.is_allow(),
        category: v.category.as_str(),
        rule: v.rule().into_owned(),
    }
}

impl FilterCheck for FilterService {
    fn check(&self, name: &str, qtype: u16) -> Option<Verdict> {
        let custom = self.custom.read().unwrap().clone();
        if let Some(v) = custom.check(name, qtype) {
            return Some(verdict(v));
        }
        let lists = self.lists.read().unwrap().clone();
        lists.check(name, qtype).map(verdict)
    }

    /// 對齊 2.x `filter.stats`（LuCI 狀態頁用 lists / custom），另外附上來源明細與記憶體
    fn stats(&self) -> Value {
        let c = self.custom.read().unwrap().clone();
        let l = self.lists.read().unwrap().clone();
        let (cs, ls) = (c.stats(), l.stats());
        let sources: Vec<Value> = ls
            .sources
            .iter()
            .map(|s| {
                json!({
                    "name": s.name, "category": s.category.as_str(), "rules": s.domain_rules + s.complex_rules,
                    "status": match s.status { SourceStatus::Loaded => "loaded", SourceStatus::Disabled => "disabled", SourceStatus::OverBudget { .. } => "overBudget" },
                })
            })
            .collect();
        let status = self.status.lock().unwrap().clone();
        json!({
            "custom": cs.custom, "lists": ls.lists,
            "byCategory": { "ads": ls.by_category.get(Category::Ads), "telemetry": ls.by_category.get(Category::Telemetry), "malware": ls.by_category.get(Category::Malware) },
            "customByCategory": { "custom": cs.custom_by_category.get(Category::Custom), "ads": cs.custom_by_category.get(Category::Ads), "telemetry": cs.custom_by_category.get(Category::Telemetry), "malware": cs.custom_by_category.get(Category::Malware) },
            "skipped": cs.skipped + ls.skipped,
            "domains": c.domain_count() + l.domain_count(),
            "memoryBytes": c.memory_bytes() + l.memory_bytes(),
            "maxDomains": self.opts.max_domains,
            "sources": sources,
            "updatedAt": status["updatedAt"], "errors": status["errors"],
        })
    }
}
