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

fn ip_text(b: &[u8]) -> String {
    match b.len() {
        4 => std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
        16 => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap()).to_string(),
        _ => format!("{b:?}"),
    }
}
