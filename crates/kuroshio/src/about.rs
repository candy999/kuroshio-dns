//! 關於：版本、授權、原始碼網址、QR 碼（公開頁、設定頁、LuCI 共用同一份資料）
//!
//! GPL-3.0-or-later：散布修改過的版本要提供對應的原始碼，所以原始碼網址可以用 `about.sourceUrl` 改成自己的分支。
//! QR 碼在本機產生（SVG），不靠外部服務。

use kuroshio_config::get;
use serde_json::{json, Value};

pub const NAME: &str = "黑潮 DNS（Kuroshio DNS）";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const LICENSE: &str = "GPL-3.0-or-later";
pub const LICENSE_URL: &str = "https://www.gnu.org/licenses/gpl-3.0.html";
/// 預設的原始碼網址（`about.sourceUrl` 可以改）
pub const DEFAULT_SOURCE: &str = "https://github.com/candy999/kuroshio-dns";

pub fn source_url(cfg: &Value) -> String {
    get(cfg, "about.sourceUrl")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| s.starts_with("https://") || s.starts_with("http://"))
        .unwrap_or(DEFAULT_SOURCE)
        .to_string()
}

/// 編進來的選用功能
pub fn features() -> Vec<&'static str> {
    let mut f = vec!["doh", "doh3", "dot", "doq", "cdn", "community", "filter"];
    if cfg!(feature = "acme") {
        f.push("acme");
    }
    if cfg!(windows) {
        f.push("windows-service");
    }
    f
}

pub fn json(cfg: &Value) -> Value {
    json!({
        "name": NAME,
        "version": VERSION,
        "license": LICENSE,
        "licenseUrl": LICENSE_URL,
        "source": source_url(cfg),
        "language": "Rust",
        "target": format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
        "features": features(),
    })
}

/// 文字轉成 QR 碼 SVG（中等容錯、深色在淺底上，四周留白）
pub fn qr_svg(text: &str) -> Option<String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M).ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(160, 160)
            .dark_color(svg::Color("#0b1f3a"))
            .light_color(svg::Color("#ffffff"))
            .quiet_zone(true)
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_override() {
        assert_eq!(source_url(&json!({})), DEFAULT_SOURCE);
        assert_eq!(
            source_url(&json!({ "about": { "sourceUrl": "https://git.example.net/me/kuroshio" } })),
            "https://git.example.net/me/kuroshio"
        );
        assert_eq!(
            source_url(&json!({ "about": { "sourceUrl": "javascript:alert(1)" } })),
            DEFAULT_SOURCE,
            "只接受 http(s)"
        );
        let a = json(&json!({}));
        assert_eq!(a["license"], LICENSE);
        assert_eq!(a["version"], VERSION);
    }

    #[test]
    fn qr() {
        let s = qr_svg("https://dns.example.net/").unwrap();
        assert!(s.starts_with("<?xml") && s.contains("<svg") && s.contains("#0b1f3a"));
        assert!(qr_svg(&"x".repeat(5000)).is_none(), "太長");
    }
}
