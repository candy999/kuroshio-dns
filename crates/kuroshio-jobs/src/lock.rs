//! 工作鎖檔（同 2.x 的 `state/locks/<工作>.lock`）：同一個工作同時只跑一份，
//! 服務裡的排程器與指令列 `kuroshio job <name>` 互斥。鎖檔內容是 PID。
//! 規格 05：鎖放在 RAM（`/tmp/kuroshio/`），不寫 Flash。

use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct JobLock {
    path: PathBuf,
}

impl JobLock {
    /// 取得鎖；已經有別的程序拿著就回傳那個 PID
    pub fn acquire(dir: &Path, name: &str) -> Result<JobLock, u32> {
        let path = dir.join(format!("{name}.lock"));
        let me = std::process::id();
        if let Some(pid) = std::fs::read_to_string(&path).ok().and_then(|s| s.trim().parse::<u32>().ok()) {
            if pid != 0 && pid != me && pid_alive(pid) {
                return Err(pid);
            }
            // 舊程序已不存在：接手
        }
        let _ = std::fs::create_dir_all(dir);
        if let Err(e) = std::fs::write(&path, me.to_string()) {
            // 寫不了鎖（唯讀、權限）不擋工作，只是少了跨程序互斥
            tracing::debug!("無法寫入鎖檔 {}：{e}", path.display());
        }
        Ok(JobLock { path })
    }
}

impl Drop for JobLock {
    fn drop(&mut self) {
        let mine = std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .map(|p| p == std::process::id())
            .unwrap_or(false);
        if mine {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// 程序是否還在。Linux 看 /proc；其他平台沒辦法便宜地確認，當成已結束（只靠同一程序內的「一次一個」）
fn pid_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/proc").join(pid.to_string()).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_cycle() {
        let dir = std::env::temp_dir().join(format!("kuroshio-lock-{}", std::process::id()));
        let l = JobLock::acquire(&dir, "x").unwrap();
        assert!(dir.join("x.lock").exists());
        // 同一個程序再拿一次不會被自己擋住
        drop(JobLock::acquire(&dir, "x").unwrap());
        drop(l);
        assert!(!dir.join("x.lock").exists());
        #[cfg(target_os = "linux")]
        {
            // PID 1 一定在：被擋
            std::fs::write(dir.join("y.lock"), "1").unwrap();
            assert_eq!(JobLock::acquire(&dir, "y").unwrap_err(), 1);
            // 不存在的程序：接手
            std::fs::write(dir.join("z.lock"), "4000000000").unwrap();
            drop(JobLock::acquire(&dir, "z").unwrap());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
