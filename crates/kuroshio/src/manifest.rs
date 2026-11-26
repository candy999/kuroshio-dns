//! data/ 的版本標記（`<data>/manifest.json`：`{"dataFormat": 1, "version": "x.y.z"}`）。
//!
//! 唯讀資料（種子、評測名單、CDN 範圍、網頁）跟執行檔要同一版。規則：
//! - 沒有 manifest.json：警告（可能是舊版的 data/）
//! - `dataFormat` 跟執行檔的 [`DATA_FORMAT`] 不同：警告，列出兩邊
//! - 只有 `version` 不同（格式相同）：只記一行資訊（Windows 小改版可能只換執行檔）
//!
//! - 舊版留下、這一版已經不讀的檔（[`RETIRED`]，3.5.1）：啟動時記一行資訊，提醒可以刪、升級時整個替換 data/。
//!   不在執行時刪（安裝目錄可能是唯讀的，也不該由服務去動）
//!
//! 一律照常執行，不拒絕啟動。結果放在 `/api/status.data` 與 `kuroshio status --json`。

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// 這個執行檔讀得懂的 data/ 格式
pub const DATA_FORMAT: u64 = 1;

pub const FILE: &str = "manifest.json";

/// 舊版附帶、這一版已經不讀的檔（相對 data/）：（路徑, 從哪一版起不用）。
/// 解壓覆蓋舊的 data/ 時會留下來（Windows、Linux 通用包）；OpenWrt 套件升級會自己移除
pub const RETIRED: &[(&str, &str)] = &[("seed/upstreams.json", "3.5.0")];

/// 檢查結果
#[derive(Debug, Clone, PartialEq)]
pub struct DataCheck {
    pub dir: PathBuf,
    /// manifest 裡的 `dataFormat`（沒有檔案或讀不懂是 None）
    pub format: Option<u64>,
    /// manifest 裡的 `version`
    pub version: Option<String>,
    /// 沒有警告
    pub ok: bool,
    /// 要使用者處理的問題（也放進 status 的 warnings）
    pub warning: Option<String>,
    /// 只是提醒（版本不同但格式相同）
    pub note: Option<String>,
    /// 舊版留下、已經不讀的檔（[`RETIRED`] 裡實際存在的）
    pub leftovers: Vec<String>,
}

/// 純函式：manifest 的內容（沒有檔案是 None）對照這個執行檔的格式與版本
pub fn evaluate(dir: &Path, content: Option<&str>, data_format: u64, bin_version: &str) -> DataCheck {
    let mut c = DataCheck {
        dir: dir.to_path_buf(),
        format: None,
        version: None,
        ok: false,
        warning: None,
        note: None,
        leftovers: Vec::new(),
    };
    let Some(text) = content else {
        c.warning = Some("data/ 沒有版本標記，可能是舊版的 data/（請用跟執行檔同一版的 data/）".into());
        return c;
    };
    let v: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            c.warning = Some(format!(
                "data/{FILE} 格式錯誤（{e}），可能是壞掉的 data/（請用跟執行檔同一版的 data/）"
            ));
            return c;
        }
    };
    c.format = v.get("dataFormat").and_then(Value::as_u64);
    c.version = v.get("version").and_then(Value::as_str).map(String::from);
    match c.format {
        Some(f) if f == data_format => {}
        f => {
            c.warning = Some(format!(
                "data/ 的格式是 {}，這個執行檔要的是 {data_format}（data/ 版本 {}、執行檔版本 {bin_version}）：請用跟執行檔同一版的 data/",
                f.map(|f| f.to_string()).unwrap_or_else(|| "（沒寫）".into()),
                c.version.as_deref().unwrap_or("（沒寫）"),
            ));
            return c;
        }
    }
    c.ok = true;
    if c.version.as_deref() != Some(bin_version) {
        c.note = Some(format!(
            "data/ 是 {} 版、執行檔是 {bin_version} 版（格式相同，可以照常使用）",
            c.version.as_deref().unwrap_or("（沒寫）")
        ));
    }
    c
}

/// 讀 `<dir>/manifest.json` 檢查，順便看有沒有舊版留下的檔
pub fn check(dir: &Path) -> DataCheck {
    let text = std::fs::read_to_string(dir.join(FILE)).ok();
    let mut c = evaluate(dir, text.as_deref(), DATA_FORMAT, env!("CARGO_PKG_VERSION"));
    c.leftovers = leftovers(dir);
    c
}

/// `dir` 裡實際存在的 [`RETIRED`] 檔（只看是不是檔案，不讀、不刪）
pub fn leftovers(dir: &Path) -> Vec<String> {
    RETIRED
        .iter()
        .filter(|(f, _)| dir.join(f).is_file())
        .map(|(f, _)| f.to_string())
        .collect()
}

/// 舊版留下的檔的提醒（沒有是 None）
pub fn leftovers_note(dir: &Path, files: &[String]) -> Option<String> {
    if files.is_empty() {
        return None;
    }
    let list: Vec<String> = files
        .iter()
        .map(|f| {
            let since = RETIRED.iter().find(|(r, _)| r == f).map_or("", |(_, v)| *v);
            format!("{f}（{since} 起不用）")
        })
        .collect();
    Some(format!(
        "data/ 裡有舊版留下、這一版已經不讀的檔：{}，略過不用，可以刪掉（{}）。升級時請整個替換 data/，不要只解壓覆蓋",
        list.join("、"),
        dir.display()
    ))
}

impl DataCheck {
    /// 啟動時記一行（警告或資訊；沒問題不記）
    pub fn log(&self) {
        if let Some(w) = &self.warning {
            warn!("{w}（{}）", self.dir.display());
        } else if let Some(n) = &self.note {
            info!("{n}");
        }
        if let Some(n) = leftovers_note(&self.dir, &self.leftovers) {
            info!("{n}");
        }
    }

    /// `/api/status.data`
    pub fn json(&self) -> Value {
        json!({
            "dir": self.dir,
            "format": self.format,
            "expectedFormat": DATA_FORMAT,
            "version": self.version,
            "ok": self.ok,
            "warning": self.warning,
            "note": self.note,
            "leftovers": self.leftovers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 發行版本號改了一定要跟著改 data/manifest.json（不然每個人都會看到版本不同的提醒）
    #[test]
    fn shipped_manifest_matches_binary() {
        let v: Value = serde_json::from_str(include_str!("../../../data/manifest.json")).unwrap();
        assert_eq!(v["dataFormat"].as_u64(), Some(DATA_FORMAT));
        assert_eq!(v["version"].as_str(), Some(env!("CARGO_PKG_VERSION")));
        let c = evaluate(
            Path::new("data"),
            Some(include_str!("../../../data/manifest.json")),
            DATA_FORMAT,
            env!("CARGO_PKG_VERSION"),
        );
        assert!(c.ok && c.warning.is_none() && c.note.is_none(), "{c:?}");
    }

    #[test]
    fn rules() {
        let d = Path::new("/usr/share/kuroshio");
        // 沒有檔案：警告
        let c = evaluate(d, None, 1, "3.1.0");
        assert!(!c.ok);
        assert!(c.warning.as_deref().unwrap().contains("沒有版本標記"));
        // 格式不同：警告，兩邊都寫出來
        let c = evaluate(d, Some(r#"{"dataFormat": 2, "version": "4.0.0"}"#), 1, "3.1.0");
        assert!(!c.ok);
        let w = c.warning.unwrap();
        assert!(
            w.contains('2') && w.contains('1') && w.contains("4.0.0") && w.contains("3.1.0"),
            "{w}"
        );
        assert_eq!(c.format, Some(2));
        // 沒寫格式：當成不同
        assert!(evaluate(d, Some(r#"{"version": "3.1.0"}"#), 1, "3.1.0").warning.is_some());
        // 壞掉的 JSON
        assert!(evaluate(d, Some("{"), 1, "3.1.0").warning.unwrap().contains("格式錯誤"));
        // 只有版本不同：只是提醒
        let c = evaluate(d, Some(r#"{"dataFormat": 1, "version": "3.0.9"}"#), 1, "3.1.0");
        assert!(c.ok && c.warning.is_none());
        assert!(c.note.unwrap().contains("3.0.9"));
        // 完全相同
        let c = evaluate(d, Some(r#"{"dataFormat": 1, "version": "3.1.0"}"#), 1, "3.1.0");
        assert!(c.ok && c.warning.is_none() && c.note.is_none());
        assert_eq!(c.json()["version"], "3.1.0");
        assert_eq!(c.json()["format"], 1);
        assert_eq!(c.json()["leftovers"], json!([]));
    }

    /// 3.5.1：解壓覆蓋留下的舊檔（3.4.x 的 `seed/upstreams.json`）列出來、提醒可以刪，但不刪
    #[test]
    fn leftovers_listed_not_deleted() {
        let d = std::env::temp_dir().join(format!("kuroshio-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("seed")).unwrap();
        std::fs::write(d.join(FILE), r#"{"dataFormat": 1, "version": "x"}"#).unwrap();
        assert!(check(&d).leftovers.is_empty());
        assert_eq!(leftovers_note(&d, &[]), None);
        std::fs::write(d.join("seed/upstreams.json"), "{}").unwrap();
        let c = check(&d);
        assert_eq!(c.leftovers, vec!["seed/upstreams.json"]);
        assert_eq!(c.json()["leftovers"], json!(["seed/upstreams.json"]));
        let n = leftovers_note(&d, &c.leftovers).unwrap();
        assert!(n.contains("seed/upstreams.json（3.5.0 起不用）") && n.contains("整個替換"), "{n}");
        c.log();
        assert!(d.join("seed/upstreams.json").exists(), "不在執行時刪安裝目錄的檔");
        // 同名的資料夾不算
        std::fs::remove_file(d.join("seed/upstreams.json")).unwrap();
        std::fs::create_dir_all(d.join("seed/upstreams.json")).unwrap();
        assert!(leftovers(&d).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }
}
