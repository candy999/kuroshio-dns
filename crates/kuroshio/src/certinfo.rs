//! 憑證資訊（取代 2.x acme.sh status 裡的 node 程式）

use serde_json::{json, Value};
use std::path::Path;

/// 讀 PEM 憑證（第一張），回傳主體、簽發者、網域、有效期間、剩幾天
pub fn read(path: &Path) -> Result<Value, String> {
    let pem = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err("還沒有憑證".into()),
        Err(e) => return Err(e.to_string()),
    };
    let (_, p) = x509_parser::pem::parse_x509_pem(&pem).map_err(|e| format!("憑證格式錯誤：{e}"))?;
    let cert = p.parse_x509().map_err(|e| format!("憑證格式錯誤：{e}"))?;
    let san: Vec<String> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|s| {
            s.value
                .general_names
                .iter()
                .map(|g| match g {
                    x509_parser::extensions::GeneralName::DNSName(d) => format!("DNS:{d}"),
                    x509_parser::extensions::GeneralName::IPAddress(ip) => format!("IP:{}", ip_text(ip)),
                    other => format!("{other}"),
                })
                .collect()
        })
        .unwrap_or_default();
    let v = cert.validity();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days_left = (v.not_after.timestamp() - now).div_euclid(86400);
    Ok(json!({
        "subject": cert.subject().to_string(),
        "issuer": cert.issuer().to_string(),
        "san": san.join(", "),
        "validFrom": v.not_before.to_rfc2822().unwrap_or_default(),
        "validTo": v.not_after.to_rfc2822().unwrap_or_default(),
        "daysLeft": days_left,
    }))
}

/// 憑證（`read` 的結果）有沒有涵蓋這個網域（含萬用字元 `*.example.com`）
pub fn covers(info: &Value, domain: &str) -> bool {
    let d = domain.trim().trim_end_matches('.').to_lowercase();
    info["san"]
        .as_str()
        .unwrap_or("")
        .split(", ")
        .filter_map(|n| n.strip_prefix("DNS:"))
        .map(str::to_lowercase)
        .any(|n| {
            n == d
                || n.strip_prefix("*.")
                    .is_some_and(|w| d.split_once('.').is_some_and(|(_, rest)| rest == w))
        })
}

/// 自備憑證的檢查：檔案不存在、讀不出來、過期（或 7 天內到期）、沒有涵蓋綁定網域。
/// 回傳要提醒使用者的訊息（沒問題時是空的）。只讀檔案，不會寫入或申請任何東西。
pub fn problems(cert: &Path, key: &Path, domain: &str) -> Vec<String> {
    let mut out = Vec::new();
    if !key.is_file() {
        out.push(format!("私鑰檔不存在：{}", key.display()));
    }
    if !cert.is_file() {
        out.push(format!("憑證檔不存在：{}", cert.display()));
        return out;
    }
    match read(cert) {
        Err(e) => out.push(format!("憑證 {} 讀不出來：{e}", cert.display())),
        Ok(info) => {
            let left = info["daysLeft"].as_i64().unwrap_or(0);
            let until = info["validTo"].as_str().unwrap_or("");
            if left < 0 {
                out.push(format!("憑證 {} 已經過期（{until}），用戶端會拒絕連線", cert.display()));
            } else if left < 7 {
                out.push(format!("憑證 {} 剩 {left} 天到期（{until}）", cert.display()));
            }
            if !domain.is_empty() && !covers(&info, domain) {
                out.push(format!(
                    "憑證 {} 沒有涵蓋綁定網域 {domain}（憑證裡的名稱：{}）",
                    cert.display(),
                    info["san"].as_str().filter(|s| !s.is_empty()).unwrap_or("沒有")
                ));
            }
        }
    }
    out
}

fn ip_text(b: &[u8]) -> String {
    match b.len() {
        4 => std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
        16 => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap()).to_string(),
        _ => format!("{b:?}"),
    }
}
