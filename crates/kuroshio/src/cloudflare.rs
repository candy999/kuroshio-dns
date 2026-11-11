//! Cloudflare API（DDNS 與內建 ACME 的 DNS-01 驗證共用）：Bearer Token、zone 自動尋找

use anyhow::{bail, Result};
use kuroshio_net::fetch::{request, Request};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

pub struct Cloudflare {
    api: String,
    token: String,
    /// 手動指定的 zone（空白 = 從記錄名稱逐層往上找）
    zone: String,
    zone_ids: Mutex<HashMap<String, String>>,
}

impl Cloudflare {
    pub fn new(api: &str, token: &str, zone: &str) -> Cloudflare {
        Cloudflare {
            api: api.trim_end_matches('/').to_string(),
            token: token.to_string(),
            zone: zone.to_string(),
            zone_ids: Mutex::new(HashMap::new()),
        }
    }

    pub async fn api(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        Ok(self.api_raw(method, path, body).await?["result"].clone())
    }

    /// 同 `api`，但回傳整個回應（含 `result_info`，分頁用）
    pub async fn api_raw(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        let b = body.map(|v| serde_json::to_vec(v).unwrap());
        let req = Request {
            method,
            headers: vec![
                ("Authorization".into(), format!("Bearer {}", self.token)),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: b.as_deref(),
        };
        let (status, out) = request(&format!("{}{path}", self.api), &req, 1 << 20, Duration::from_secs(15)).await?;
        let j: Value = serde_json::from_slice(&out).unwrap_or(Value::Null);
        if !(200..300).contains(&status) || j.get("success") == Some(&Value::Bool(false)) {
            let msg = j["errors"]
                .as_array()
                .map(|e| {
                    e.iter()
                        .map(|x| format!("{} {}", x["code"], x["message"].as_str().unwrap_or("")))
                        .collect::<Vec<_>>()
                        .join("; ")
                })
                .filter(|m| !m.is_empty())
                .unwrap_or(format!("HTTP {status}"));
            bail!("Cloudflare API {method} {}：{msg}", path.split('?').next().unwrap_or(path));
        }
        Ok(j)
    }

    /// 列出某個名稱、某種類型的全部記錄（一頁 100 筆，照 `result_info.total_pages` 讀完；最多 20 頁）
    pub async fn list_records(&self, zone_id: &str, rtype: &str, name: &str) -> Result<Vec<Value>> {
        const PER_PAGE: usize = 100;
        const MAX_PAGES: u64 = 20;
        let mut out = Vec::new();
        for page in 1..=MAX_PAGES {
            let j = self
                .api_raw(
                    "GET",
                    &format!("/zones/{zone_id}/dns_records?type={rtype}&name={name}&per_page={PER_PAGE}&page={page}"),
                    None,
                )
                .await?;
            let items = j["result"].as_array().cloned().unwrap_or_default();
            let n = items.len();
            out.extend(items);
            // 有 result_info 就照總頁數；沒有（或這一頁沒滿）就是最後一頁
            let more = match j["result_info"]["total_pages"].as_u64() {
                Some(total) => page < total,
                None => n >= PER_PAGE,
            };
            if !more || n == 0 {
                return Ok(out);
            }
        }
        bail!("{name} 的 {rtype} 記錄超過 {} 筆，不處理", PER_PAGE as u64 * MAX_PAGES)
    }

    /// 找出記錄所屬的 zone：有設定 zone 就用它，否則從記錄名稱逐層往上試
    pub async fn zone_id(&self, name: &str) -> Result<String> {
        let labels: Vec<&str> = name.split('.').collect();
        let cands: Vec<String> = if self.zone.is_empty() {
            (0..labels.len())
                .map(|i| labels[i..].join("."))
                .filter(|z| z.contains('.'))
                .collect()
        } else {
            vec![self.zone.clone()]
        };
        for z in cands {
            if let Some(id) = self.zone_ids.lock().unwrap().get(&z) {
                return Ok(id.clone());
            }
            let r = self.api("GET", &format!("/zones?name={z}"), None).await?;
            if let Some(id) = r.get(0).and_then(|x| x["id"].as_str()) {
                self.zone_ids.lock().unwrap().insert(z, id.to_string());
                return Ok(id.to_string());
            }
        }
        bail!("找不到 {name} 所屬的 Cloudflare zone（請確認 API Token 有 Zone:Read 權限，或手動填 zone）")
    }

    /// 新增 TXT 記錄（ACME DNS-01），回傳記錄 id
    pub async fn add_txt(&self, name: &str, content: &str) -> Result<String> {
        let zid = self.zone_id(name).await?;
        let body = serde_json::json!({ "type": "TXT", "name": name, "content": content, "ttl": 60 });
        let r = self.api("POST", &format!("/zones/{zid}/dns_records"), Some(&body)).await?;
        match r["id"].as_str() {
            Some(id) => Ok(id.to_string()),
            None => bail!("Cloudflare 沒有回傳記錄 id"),
        }
    }

    /// 刪除記錄（ACME 驗證完成後清掉 TXT）
    pub async fn delete_record(&self, name: &str, id: &str) -> Result<()> {
        let zid = self.zone_id(name).await?;
        self.api("DELETE", &format!("/zones/{zid}/dns_records/{id}"), None).await?;
        Ok(())
    }
}
