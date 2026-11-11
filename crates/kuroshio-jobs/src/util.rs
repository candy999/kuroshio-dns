//! 共用小工具：清單檔、JSON 讀寫、原子寫檔、跟 JavaScript 一致的數字格式

use serde_json::Value;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// 讀清單檔：去 BOM、去註解（# 或 // 開頭）、去空行（同 2.x 的 `readList`）；讀不到回空清單
pub fn read_list(path: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_list(&text)
}

pub fn parse_list(text: &str) -> Vec<String> {
    text.strip_prefix('\u{feff}')
        .unwrap_or(text)
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l).trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .map(str::to_string)
        .collect()
}

/// 讀 JSON（去 BOM）；讀不到或格式錯誤回 None
pub fn read_json(path: &Path) -> Option<Value> {
    let b = std::fs::read(path).ok()?;
    let b = b.strip_prefix("\u{feff}".as_bytes()).unwrap_or(&b);
    serde_json::from_slice(b).ok()
}

/// 先寫暫存檔、fsync、再改名：斷電不會留下半個檔案
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    let tmp = tmp_path(path);
    let res = (|| {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(format!(".{}.tmp", std::process::id()));
    path.with_file_name(name)
}

/// JSON 縮排 2 格寫檔（同 2.x 的 `writeJson`）
pub fn write_json(path: &Path, v: &Value) -> std::io::Result<()> {
    let b = serde_json::to_vec_pretty(v).map_err(std::io::Error::other)?;
    write_atomic(path, &b)
}

/// 2.x 的 `isBogonV4`：保留 / 私有 / 文件用位址
pub fn is_bogon_v4(ip: Ipv4Addr) -> bool {
    const BOGON: [([u8; 4], u32); 14] = [
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([192, 168, 0, 0], 16),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 4),
        ([240, 0, 0, 0], 4),
    ];
    let n = u32::from(ip);
    BOGON.iter().any(|(base, len)| {
        let mask = if *len == 0 { 0 } else { u32::MAX << (32 - len) };
        n & mask == u32::from_be_bytes(*base)
    })
}

/// 同 JavaScript 的 `Number.prototype.toFixed`：剛好在中間時取絕對值較大的那個
/// （Rust 的 `{:.2}` 是取偶數，0.125 會變成 0.12，JavaScript 是 0.13）
pub fn to_fixed(x: f64, digits: usize) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if x.abs() >= 1e21 {
        return js_number(x);
    }
    // 先印出（幾乎）精確的十進位展開，再自己四捨五入
    let exact = format!("{:.100}", x.abs());
    let (int_part, frac) = exact.split_once('.').unwrap_or((&exact, ""));
    let mut digits_vec: Vec<u8> = int_part.bytes().chain(frac.bytes().take(digits)).map(|c| c - b'0').collect();
    let round_up = frac.as_bytes().get(digits).map(|c| *c >= b'5').unwrap_or(false);
    if round_up {
        let mut i = digits_vec.len();
        loop {
            if i == 0 {
                digits_vec.insert(0, 1);
                break;
            }
            i -= 1;
            if digits_vec[i] == 9 {
                digits_vec[i] = 0;
            } else {
                digits_vec[i] += 1;
                break;
            }
        }
    }
    let s: String = digits_vec.iter().map(|d| (b'0' + d) as char).collect();
    let (ip, fp) = s.split_at(s.len() - digits);
    let neg = x < 0.0;
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    out.push_str(ip);
    if digits > 0 {
        out.push('.');
        out.push_str(fp);
    }
    out
}

/// `+x.toFixed(n)` 轉成 JSON 數字（整數不帶 .0，同 JavaScript）
pub fn fixed_num(x: f64, digits: usize) -> Value {
    num(to_fixed(x, digits).parse::<f64>().unwrap_or(x))
}

/// f64 → JSON 數字；整數印成整數（JavaScript 的 JSON.stringify 不會印出 7.0）
pub fn num(x: f64) -> Value {
    if x.fract() == 0.0 && x.abs() < 9_007_199_254_740_992.0 {
        Value::from(x as i64)
    } else {
        serde_json::Number::from_f64(x).map(Value::Number).unwrap_or(Value::Null)
    }
}

/// 數字轉字串（整數不帶小數點）
pub fn js_number(x: f64) -> String {
    match num(x) {
        Value::Number(n) => n.to_string(),
        _ => "NaN".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_parsing() {
        let l = parse_list("\u{feff}a.com\r\n# x\r\n  b.com  \n// y\n\n");
        assert_eq!(l, vec!["a.com", "b.com"]);
    }

    #[test]
    fn to_fixed_like_js() {
        assert_eq!(to_fixed(0.125, 2), "0.13");
        assert_eq!(to_fixed(1.005, 2), "1.00"); // 1.005 實際是 1.00499999…
        assert_eq!(to_fixed(9999.0, 2), "9999.00");
        assert_eq!(to_fixed(9.995, 2), "9.99");
        assert_eq!(to_fixed(9.9951, 2), "10.00");
        assert_eq!(to_fixed(0.5, 0), "1");
        assert_eq!(to_fixed(-0.0001, 2), "-0.00");
        assert_eq!(to_fixed(-1.5, 1), "-1.5");
        assert_eq!(to_fixed(f64::NAN, 2), "NaN");
        assert_eq!(fixed_num(7.0, 2), serde_json::json!(7));
        assert_eq!(fixed_num(7.444, 2), serde_json::json!(7.44));
    }

    #[test]
    fn bogon() {
        assert!(is_bogon_v4("10.1.2.3".parse().unwrap()));
        assert!(is_bogon_v4("198.19.0.1".parse().unwrap()));
        assert!(!is_bogon_v4("1.1.1.1".parse().unwrap()));
        assert!(!is_bogon_v4("172.32.0.1".parse().unwrap()));
    }
}
