//! 狀態檔的讀取（規格 05 第 5.3 節）：快照可能是一般 JSON，也可能是 zstd 壓縮的 `.zst`。
//!
//! - 讀的一方（啟動載入、備份匯出 / 匯入、`kuroshio compare`）兩種都接受。
//! - 兩種同時存在時用比較新的那份：舊版或備份匯入寫的是一般 JSON，比壓縮檔新就代表它才是最新的內容；
//!   之後快照寫入器寫出壓縮檔時會把一般 JSON 刪掉（只遷移一次）。

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// 壓縮等級：3 在 MIPS 上也便宜（實測見規格 05），壓縮率跟更高等級差不多
pub const LEVEL: i32 = 3;
/// 壓縮視窗 2^19 = 512 KB：壓縮 / 解壓時暫用的記憶體跟著變小（tiny 路由器），JSON 的重複大多在附近，壓縮率幾乎不變
pub const WINDOW_LOG: u32 = 19;
/// 解壓後的上限（防止壞掉的檔案吃光記憶體）
pub const MAX_PLAIN: u64 = 512 << 20;

/// `a/b.json` → `a/b.json.zst`
pub fn zst_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".zst");
    PathBuf::from(s)
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// 讀到的狀態檔
pub struct Loaded {
    /// 解壓後的內容
    pub data: Vec<u8>,
    /// 實際讀的檔案
    pub path: PathBuf,
    /// 讀的是壓縮檔
    pub compressed: bool,
    pub mtime: Option<SystemTime>,
    /// 檔案在磁碟上的大小
    pub disk_size: u64,
}

/// 解壓（有上限）
pub fn decompress(b: &[u8]) -> std::io::Result<Vec<u8>> {
    let dec = zstd::stream::read::Decoder::new(b)?;
    let mut out = Vec::new();
    dec.take(MAX_PLAIN + 1).read_to_end(&mut out)?;
    if out.len() as u64 > MAX_PLAIN {
        return Err(std::io::Error::other("解壓後超過上限"));
    }
    Ok(out)
}

/// 壓縮整份內容（測試、量測用；正式寫檔用 `encoder` 邊寫邊壓）
pub fn compress(b: &[u8]) -> Vec<u8> {
    let mut e = encoder(Vec::new()).expect("zstd");
    e.write_all(b).expect("zstd");
    e.finish().expect("zstd")
}

/// 邊寫邊壓
pub fn encoder<W: Write>(w: W) -> std::io::Result<zstd::stream::write::Encoder<'static, W>> {
    let mut e = zstd::stream::write::Encoder::new(w, LEVEL)?;
    e.window_log(WINDOW_LOG)?;
    e.include_checksum(true)?;
    Ok(e)
}

/// 讀 `path`（一般 JSON）或 `path.zst`（壓縮），兩個都有就用比較新的；比較新的壞掉就退回另一份
pub fn load(path: &Path) -> Option<Loaded> {
    let z = zst_path(path);
    let (tp, tz) = (mtime(path), mtime(&z));
    let read_plain = || {
        std::fs::read(path).ok().map(|data| Loaded {
            disk_size: data.len() as u64,
            data,
            path: path.to_path_buf(),
            compressed: false,
            mtime: tp,
        })
    };
    let read_zst = || {
        let b = std::fs::read(&z).ok()?;
        match decompress(&b) {
            Ok(data) => Some(Loaded {
                data,
                path: z.clone(),
                compressed: true,
                mtime: tz,
                disk_size: b.len() as u64,
            }),
            Err(e) => {
                tracing::warn!("{} 解壓失敗：{e}", z.display());
                None
            }
        }
    };
    match (tp, tz) {
        (None, None) => None,
        (Some(_), None) => read_plain(),
        (None, Some(_)) => read_zst(),
        (Some(a), Some(b)) if a > b => read_plain().or_else(read_zst),
        _ => read_zst().or_else(read_plain),
    }
}

/// 只要內容
pub fn read(path: &Path) -> Option<Vec<u8>> {
    load(path).map(|l| l.data)
}

/// 兩種格式有沒有任何一份存在
pub fn exists(path: &Path) -> bool {
    path.exists() || zst_path(path).exists()
}

/// 兩種格式都刪掉（不存在不算錯）
pub fn remove(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(zst_path(path));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_formats_newer_wins() {
        let d = std::env::temp_dir().join(format!("kuroshio-statefile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("a.json");
        assert!(read(&p).is_none());
        std::fs::write(zst_path(&p), compress(b"{\"z\":1}")).unwrap();
        assert_eq!(read(&p).unwrap(), b"{\"z\":1}");
        // 之後才寫的一般 JSON（例如備份匯入）比較新：用它
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&p, b"{\"p\":1}").unwrap();
        let l = load(&p).unwrap();
        assert_eq!((l.data.as_slice(), l.compressed), (&b"{\"p\":1}"[..], false));
        // 壞掉的壓縮檔：退回一般 JSON
        std::fs::write(zst_path(&p), b"junk").unwrap();
        assert_eq!(read(&p).unwrap(), b"{\"p\":1}");
        remove(&p);
        assert!(!exists(&p));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
