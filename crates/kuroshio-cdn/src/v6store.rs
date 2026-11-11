//! 台灣 IPv6 節點永久紀錄（對齊 2.x `lib/cdn/v6store.js`）：`state/cdn/v6-nodes.json`
//!
//! 運氣好發現的 CDN IPv6 台灣 POP 節點會一直保存，只有確認失效才移除：
//!   - 探測到 POP 已經不是台灣 → 立即移除
//!   - 連續 `FAIL_LIMIT` 次完全連不上 → 移除（同一輪所有 v6 都連不上視為本機網路問題，由呼叫端決定不計次）
//!
//! 2.x 是伺服器與每日工作（子程序）各自讀寫檔案；3.0 的工作在同一個程序裡，共用記憶體裡這一份。

use crate::util::{self, de_opt_string, de_opt_u32, now_ms, Extra, Num};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const FAIL_LIMIT: u32 = 3;
pub const FILE: &str = "cdn/v6-nodes.json";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct V6Node {
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_string")]
    pub first_seen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_string")]
    pub pop: Option<String>,
    #[serde(default, skip_serializing_if = "Num::is_absent")]
    pub ms: Num,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_string")]
    pub last_ok: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_u32")]
    pub fails: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "de_opt_string")]
    pub last_fail: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// 檔案格式：`{ providers: { cloudflare: { "<ip>": {...} } }, savedAt }`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileFmt {
    #[serde(default)]
    providers: IndexMap<String, IndexMap<String, V6Node>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    saved_at: Option<String>,
    #[serde(flatten)]
    extra: Extra,
}

#[derive(Debug, Clone, Default)]
pub struct V6Store {
    providers: IndexMap<String, IndexMap<IpAddr, V6Node>>,
    saved_at: Option<String>,
    extra: Extra,
    /// 每家最多保存幾個（超過時丟掉最慢的）
    pub max: usize,
    pub dirty: bool,
}

/// 列出用：（IP，紀錄）
#[derive(Debug, Clone, PartialEq)]
pub struct V6Entry {
    pub ip: IpAddr,
    pub node: V6Node,
}

impl V6Store {
    pub fn new(max: usize) -> V6Store {
        V6Store {
            max: max.max(1),
            ..Default::default()
        }
    }

    pub fn from_json(b: &[u8], max: usize) -> anyhow::Result<V6Store> {
        let f: FileFmt = serde_json::from_slice(b)?;
        let mut s = V6Store::new(max);
        for (p, nodes) in f.providers {
            let m: IndexMap<IpAddr, V6Node> = nodes.into_iter().filter_map(|(k, v)| Some((util::parse_ip(&k)?, v))).collect();
            s.providers.insert(p, m);
        }
        s.saved_at = f.saved_at;
        s.extra = f.extra;
        Ok(s)
    }

    /// 2.x 的種子判斷：有任何一家有節點才算有資料
    pub fn is_empty(&self) -> bool {
        !self.providers.values().any(|p| !p.is_empty())
    }

    pub fn to_json(&self) -> Vec<u8> {
        let f = FileFmt {
            providers: self
                .providers
                .iter()
                .map(|(p, m)| (p.clone(), m.iter().map(|(ip, v)| (ip.to_string(), v.clone())).collect()))
                .collect(),
            saved_at: self.saved_at.clone(),
            extra: self.extra.clone(),
        };
        serde_json::to_vec(&f).unwrap_or_default()
    }

    /// 整份（管理介面 `/api/cdn/v6nodes`）
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::from_slice(&self.to_json()).unwrap_or_default()
    }

    fn touch(&mut self) {
        self.saved_at = Some(util::iso(now_ms()));
        self.dirty = true;
    }

    /// 確認是台灣節點：新增或更新，回傳 true 代表是新發現
    pub fn mark_ok(&mut self, provider: &str, ip: IpAddr, pop: &str, ms: Option<f64>) -> bool {
        let now = util::iso(now_ms());
        let max = self.max;
        let p = self.providers.entry(provider.to_string()).or_default();
        let is_new = !p.contains_key(&ip);
        let e = p.entry(ip).or_insert_with(|| V6Node {
            first_seen: Some(now.clone()),
            ..Default::default()
        });
        e.pop = Some(pop.to_string());
        e.ms = match ms.filter(|m| m.is_finite()) {
            Some(m) => Num::V(util::round(m, 2)),
            None if e.ms.get().map(|m| m != 0.0).unwrap_or(false) => e.ms,
            None => Num::Null,
        };
        e.last_ok = Some(now);
        e.fails = Some(0);
        if p.len() > max {
            // 上限：丟掉最慢的（不會是剛加入的這個，除非它最慢）
            if let Some((&worst, _)) = p.iter().max_by(|a, b| a.1.ms.or(999.0).partial_cmp(&b.1.ms.or(999.0)).unwrap()) {
                p.shift_remove(&worst);
            }
        }
        self.touch();
        is_new
    }

    /// POP 已不在台灣：移除；回傳是否有移除
    pub fn mark_not_tw(&mut self, provider: &str, ip: IpAddr) -> bool {
        let removed = self.providers.get_mut(provider).and_then(|p| p.shift_remove(&ip)).is_some();
        self.touch();
        removed
    }

    /// 連不上：累計失敗，達上限才移除；回傳是否已移除
    pub fn mark_dead(&mut self, provider: &str, ip: IpAddr) -> bool {
        let now = util::iso(now_ms());
        let mut removed = false;
        if let Some(p) = self.providers.get_mut(provider) {
            if let Some(e) = p.get_mut(&ip) {
                let f = e.fails.unwrap_or(0) + 1;
                e.fails = Some(f);
                e.last_fail = Some(now);
                if f >= FAIL_LIMIT {
                    p.shift_remove(&ip);
                    removed = true;
                }
            }
        }
        self.touch();
        removed
    }

    /// 某家 CDN 的所有永久節點，依延遲排序
    pub fn list(&self, provider: &str) -> Vec<V6Entry> {
        let mut v: Vec<V6Entry> = self
            .providers
            .get(provider)
            .map(|p| p.iter().map(|(ip, n)| V6Entry { ip: *ip, node: n.clone() }).collect())
            .unwrap_or_default();
        v.sort_by(|a, b| {
            a.node
                .ms
                .or(999.0)
                .partial_cmp(&b.node.ms.or(999.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v
    }

    pub fn contains(&self, provider: &str, ip: IpAddr) -> bool {
        self.providers.get(provider).map(|p| p.contains_key(&ip)).unwrap_or(false)
    }

    pub fn count(&self, provider: &str) -> usize {
        self.providers.get(provider).map(|p| p.len()).unwrap_or(0)
    }

    /// 測試用：整家移除
    pub fn remove_provider(&mut self, provider: &str) {
        self.providers.shift_remove(provider);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selftest_v6_permanent() {
        // 對照 2.x selftest「IPv6 永久紀錄」
        let mut s = V6Store::new(100);
        let a: IpAddr = "2606:4700:10::99".parse().unwrap();
        assert!(s.mark_ok("zz-test", a, "TPE", Some(3.2)), "新發現的台灣 v6 節點會保存");
        assert!(!s.mark_ok("zz-test", a, "TPE", Some(3.0)));
        assert_eq!(s.list("zz-test").len(), 1);
        // 連不上未達上限不移除，達上限才移除
        assert!(!s.mark_dead("zz-test", a));
        assert!(!s.mark_dead("zz-test", a));
        assert_eq!(s.list("zz-test").len(), 1);
        assert!(s.mark_dead("zz-test", a));
        assert_eq!(s.list("zz-test").len(), 0);
        // 再次確認可用會重置失敗次數；POP 移出台灣立即移除
        let b: IpAddr = "2606:4700:20::1".parse().unwrap();
        s.mark_ok("zz-test", b, "KHH", Some(5.0));
        s.mark_dead("zz-test", b);
        s.mark_dead("zz-test", b);
        s.mark_ok("zz-test", b, "KHH", Some(5.0));
        assert_eq!(s.list("zz-test")[0].node.fails, Some(0));
        assert!(s.mark_not_tw("zz-test", b));
        assert_eq!(s.list("zz-test").len(), 0);
    }

    #[test]
    fn cap_drops_slowest() {
        let mut s = V6Store::new(2);
        s.mark_ok("cf", "2606::1".parse().unwrap(), "TPE", Some(3.0));
        s.mark_ok("cf", "2606::2".parse().unwrap(), "TPE", Some(9.0));
        s.mark_ok("cf", "2606::3".parse().unwrap(), "TPE", Some(5.0));
        let l: Vec<String> = s.list("cf").iter().map(|e| e.ip.to_string()).collect();
        assert_eq!(l, vec!["2606::1", "2606::3"]);
    }
}
