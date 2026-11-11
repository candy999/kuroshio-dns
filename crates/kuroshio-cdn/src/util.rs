//! 共用小工具：時間、JSON 欄位（保留未知欄位、null 與「沒有這個欄位」的分別）、IP 網段

use serde::de::{Deserializer, Error as _};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// 目前時間（Unix 毫秒，同 2.x 的 `Date.now()`）
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub const HOUR_MS: u64 = 3_600_000;
pub const DAY_MS: u64 = 24 * HOUR_MS;

/// ISO 8601（`2026-10-27T07:35:11.859Z`，同 2.x 的 `new Date().toISOString()`）
pub fn iso(ms: u64) -> String {
    let secs = ms / 1000;
    let (h, mi, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    let (y, m, d) = civil_from_days((secs / 86400) as i64);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{:03}Z", ms % 1000)
}

/// 天數 → 年月日（Howard Hinnant 的演算法）
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 台北時間（固定 UTC+8，台灣沒有日光節約時間）的小時 0–23
pub fn taipei_hour(ms: u64) -> u32 {
    ((ms / HOUR_MS + 8) % 24) as u32
}

/// 四捨五入到小數 n 位（同 2.x 的 `+x.toFixed(n)`）
pub fn round(x: f64, n: i32) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let p = 10f64.powi(n);
    (x * p).round() / p
}

// ---------------------------------------------------------------- 字串共用

/// 少量重複出現的字串（CDN 名稱、POP、判定結果）共用同一份記憶體
pub fn intern(s: &str) -> Arc<str> {
    static POOL: OnceLock<Mutex<HashSet<Arc<str>>>> = OnceLock::new();
    let pool = POOL.get_or_init(|| Mutex::new(HashSet::new()));
    let mut p = pool.lock().unwrap();
    if let Some(a) = p.get(s) {
        return a.clone();
    }
    let a: Arc<str> = Arc::from(s);
    if p.len() < 4096 {
        p.insert(a.clone());
    }
    a
}

pub fn ser_arc<S: Serializer>(v: &Arc<str>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(v)
}

pub fn de_arc<'de, D: Deserializer<'de>>(d: D) -> Result<Arc<str>, D::Error> {
    let s = String::deserialize(d)?;
    Ok(intern(&s))
}

pub fn ser_opt_arc<S: Serializer>(v: &Option<Arc<str>>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(a) => s.serialize_str(a),
        None => s.serialize_none(),
    }
}

/// 字串以外（數字、物件）也接受，轉成字串；null → None
pub fn de_opt_arc<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Arc<str>>, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::Null => None,
        Value::String(s) => Some(intern(&s)),
        other => Some(intern(&other.to_string())),
    })
}

pub fn de_opt_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::Null => None,
        Value::String(s) => Some(s),
        other => Some(other.to_string()),
    })
}

// ---------------------------------------------------------------- 數字

/// 寫 JSON 數字：整數值寫成整數（JS 的 `4` 而不是 `4.0`），無限大寫成 null（同 `JSON.stringify`）
pub fn ser_f64<S: Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    if !v.is_finite() {
        s.serialize_none()
    } else if v.fract() == 0.0 && v.abs() < 9e15 {
        s.serialize_i64(*v as i64)
    } else {
        s.serialize_f64(*v)
    }
}

fn value_u64(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_f64().filter(|f| *f >= 0.0 && f.is_finite()).map(|f| f as u64))
}

/// 寬鬆的整數：整數、小數（取整）都接受；其他（null、字串）→ None
pub fn de_opt_u64<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    Ok(value_u64(&Value::deserialize(d)?))
}

pub fn de_u64<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    Ok(value_u64(&Value::deserialize(d)?).unwrap_or(0))
}

pub fn de_opt_u32<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u32>, D::Error> {
    Ok(value_u64(&Value::deserialize(d)?).map(|x| x.min(u32::MAX as u64) as u32))
}

pub fn de_u32<'de, D: Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
    Ok(de_opt_u32(d)?.unwrap_or(0))
}

pub fn de_opt_bool<'de, D: Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::Bool(b) => Some(b),
        _ => None,
    })
}

/// JSON 數字欄位：分得出「沒有這個欄位」、`null`、2.x 的 `'∞'`（`fmt(Infinity)`）與一般數字，
/// 讀進來再寫出去跟原本一樣
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum Num {
    #[default]
    Absent,
    Null,
    Inf,
    V(f64),
}

impl Num {
    pub fn is_absent(&self) -> bool {
        matches!(self, Num::Absent)
    }

    /// 數值（`null` / 沒有 → None；`'∞'` → 無限大）
    pub fn get(&self) -> Option<f64> {
        match self {
            Num::V(v) => Some(*v),
            Num::Inf => Some(f64::INFINITY),
            _ => None,
        }
    }

    /// JS 的 `x ?? d`
    pub fn or(&self, d: f64) -> f64 {
        self.get().unwrap_or(d)
    }

    /// 有限數字 → V；無限大 → Null（同 `JSON.stringify(Infinity)`）
    pub fn of(v: f64) -> Num {
        if v.is_finite() {
            Num::V(v)
        } else {
            Num::Null
        }
    }

    /// None → Null
    pub fn opt(v: Option<f64>) -> Num {
        v.map(Num::of).unwrap_or(Num::Null)
    }

    /// JS 的真值（`if (x.ms)`）：0 與 null 都是假
    pub fn truthy(&self) -> bool {
        matches!(self, Num::V(v) if *v != 0.0) || matches!(self, Num::Inf)
    }
}

impl Serialize for Num {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Num::Absent | Num::Null => s.serialize_none(),
            Num::Inf => s.serialize_str("∞"),
            Num::V(v) => ser_f64(v, s),
        }
    }
}

impl<'de> Deserialize<'de> for Num {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match Value::deserialize(d)? {
            Value::Null => Num::Null,
            Value::Number(n) => Num::V(n.as_f64().unwrap_or(0.0)),
            Value::String(s) if s == "∞" || s == "Infinity" => Num::Inf,
            Value::String(s) => s.parse().map(Num::V).unwrap_or(Num::Null),
            _ => Num::Null,
        })
    }
}

/// 可以是 `null` 的欄位（分得出「沒有這個欄位」與 `null`）
#[derive(Debug, Clone, Default, PartialEq)]
pub enum Field<T> {
    #[default]
    Absent,
    Null,
    Val(T),
}

impl<T> Field<T> {
    pub fn is_absent(&self) -> bool {
        matches!(self, Field::Absent)
    }
    pub fn val(&self) -> Option<&T> {
        match self {
            Field::Val(v) => Some(v),
            _ => None,
        }
    }
}

impl<T: Serialize> Serialize for Field<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Field::Val(v) => v.serialize(s),
            _ => s.serialize_none(),
        }
    }
}

impl<'de, T: serde::de::DeserializeOwned> Deserialize<'de> for Field<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        if v.is_null() {
            return Ok(Field::Null);
        }
        Ok(serde_json::from_value(v).map(Field::Val).unwrap_or(Field::Null))
    }
}

// ---------------------------------------------------------------- 未知欄位

/// 不認識的欄位：原封保留，寫回時照樣輸出（新舊版本可以互相讀寫同一份狀態檔）。
/// 平常沒有未知欄位，只佔一個指標的空間。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Extra(pub Option<Box<Map<String, Value>>>);

impl Extra {
    pub fn get(&self, k: &str) -> Option<&Value> {
        self.0.as_ref().and_then(|m| m.get(k))
    }
    pub fn is_empty(&self) -> bool {
        self.0.as_ref().map(|m| m.is_empty()).unwrap_or(true)
    }
}

impl Serialize for Extra {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let empty = Map::new();
        let m = self.0.as_deref().unwrap_or(&empty);
        let mut out = s.serialize_map(Some(m.len()))?;
        for (k, v) in m {
            out.serialize_entry(k, v)?;
        }
        out.end()
    }
}

impl<'de> Deserialize<'de> for Extra {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let m = Map::<String, Value>::deserialize(d)?;
        Ok(Extra(if m.is_empty() { None } else { Some(Box::new(m)) }))
    }
}

// ---------------------------------------------------------------- IP

/// IP 清單：無效的字串略過（不讓一筆壞資料毀掉整份檔案）
pub fn de_ips<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<IpAddr>, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::Array(a) => a.iter().filter_map(|x| x.as_str()).filter_map(parse_ip).collect(),
        _ => Vec::new(),
    })
}

pub fn de_opt_ips<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<IpAddr>>, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::Array(a) => Some(a.iter().filter_map(|x| x.as_str()).filter_map(parse_ip).collect()),
        _ => None,
    })
}

pub fn de_opt_ip<'de, D: Deserializer<'de>>(d: D) -> Result<Option<IpAddr>, D::Error> {
    Ok(Value::deserialize(d)?.as_str().and_then(parse_ip))
}

pub fn de_ip<'de, D: Deserializer<'de>>(d: D) -> Result<IpAddr, D::Error> {
    let v = Value::deserialize(d)?;
    v.as_str().and_then(parse_ip).ok_or_else(|| D::Error::custom("IP 格式錯誤"))
}

/// 解析 IP（容許 `[v6]` 與 IPv4-mapped 的 v6 寫法）
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim().trim_start_matches('[').trim_end_matches(']');
    s.parse().ok()
}

pub fn v4_u32(ip: Ipv4Addr) -> u32 {
    u32::from(ip)
}

/// IPv4 的 /24 前綴（整數，ip >> 8）
pub fn prefix24(ip: IpAddr) -> Option<u32> {
    match ip {
        IpAddr::V4(v) => Some(u32::from(v) >> 8),
        IpAddr::V6(_) => None,
    }
}

/// /24 前綴的文字（`151.101.76`，同 2.x 的 `prefix24`）
pub fn prefix24_str(p: u32) -> String {
    format!("{}.{}.{}", (p >> 16) & 0xff, (p >> 8) & 0xff, p & 0xff)
}

pub fn parse_prefix24(s: &str) -> Option<u32> {
    let mut it = s.trim().split('.');
    let mut v = 0u32;
    for _ in 0..3 {
        let o: u8 = it.next()?.parse().ok()?;
        v = (v << 8) | o as u32;
    }
    if it.next().is_some() {
        return None;
    }
    Some(v)
}

/// /24 前綴 + 最後一段 → IP
pub fn ip_of(prefix: u32, last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from((prefix << 8) | last as u32))
}

pub fn last_octet(ip: IpAddr) -> Option<u8> {
    match ip {
        IpAddr::V4(v) => Some(v.octets()[3]),
        IpAddr::V6(_) => None,
    }
}

/// 同 2.x 的 `subnetKey`：IPv4 → `a.b.c.0/24`、IPv6 → `xxxx:xxxx:xxxx::/48`
pub fn subnet_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v) => {
            let n = u128::from(v) >> 80 << 80;
            format!("{}/48", Ipv6Addr::from(n))
        }
    }
}

/// IPv6 的 /48（整數）
pub fn v6_48(ip: IpAddr) -> Option<u128> {
    match ip {
        IpAddr::V6(v) => Some(u128::from(v) >> 80),
        IpAddr::V4(_) => None,
    }
}

/// 檔案寫入：內容一樣就不寫；不一樣就先寫暫存檔、fsync、改名（規格 05 第 5.3 節）。回傳是否有寫
pub fn write_if_changed(path: &std::path::Path, data: &[u8]) -> std::io::Result<bool> {
    if let Ok(old) = std::fs::read(path) {
        if old == data {
            return Ok(false);
        }
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("{}.tmp", path.extension().and_then(|e| e.to_str()).unwrap_or("")));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(true)
}

/// 讀清單檔：去 BOM、去註解、去空行（同 2.x 的 `readList`）
pub fn read_list(text: &str) -> Vec<String> {
    text.trim_start_matches('\u{feff}')
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .map(|l| l.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_and_keys() {
        assert_eq!(iso(1793085962496), "2026-10-27T07:26:02.496Z");
        assert_eq!(iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(taipei_hour(1793085962496), 15);
        assert_eq!(subnet_key("104.16.161.36".parse().unwrap()), "104.16.161.0/24");
        assert_eq!(subnet_key("2606:4700:4406::6812:25b6".parse().unwrap()), "2606:4700:4406::/48");
        assert_eq!(prefix24_str(parse_prefix24("151.101.76").unwrap()), "151.101.76");
        assert_eq!(ip_of(parse_prefix24("151.101.76").unwrap(), 133).to_string(), "151.101.76.133");
        assert_eq!(round(1.23456, 2), 1.23);
    }

    #[test]
    fn json_fields() {
        #[derive(Serialize, Deserialize, Default, PartialEq, Debug)]
        struct T {
            #[serde(default, skip_serializing_if = "Num::is_absent")]
            a: Num,
            #[serde(default, skip_serializing_if = "Num::is_absent")]
            b: Num,
            #[serde(default, skip_serializing_if = "Num::is_absent")]
            c: Num,
            #[serde(flatten)]
            extra: Extra,
        }
        let src = r#"{"a":null,"b":4,"c":"∞","zz":{"k":[1,2]}}"#;
        let t: T = serde_json::from_str(src).unwrap();
        assert_eq!((t.a, t.b, t.c), (Num::Null, Num::V(4.0), Num::Inf));
        let back: Value = serde_json::to_value(&t).unwrap();
        assert_eq!(back, serde_json::from_str::<Value>(src).unwrap());
        assert_eq!(serde_json::to_string(&T::default()).unwrap(), "{}");
    }
}
