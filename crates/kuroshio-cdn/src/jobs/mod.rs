//! CDN 背景工作（對齊 2.x `jobs/cdn-ranges.js`、`jobs/cdn-scan.js`、`jobs/cdn-pool.js`），由外層排程：
//!
//! | 工作 | 2.x 預設 | 輸出 |
//! |---|---|---|
//! | `ranges::run` | 每週日 03:10 | `state/cdn/ranges/<cdn>-ipv4.txt`、`-ipv6.txt`、`.done`（內容沒變不寫） |
//! | `scan::run` | 每週日 03:20（tiny 停用） | `state/cdn/scan/<cdn>-ipv4-TW/Global/Dead.txt`、`.done`（內容沒變不寫） |
//! | `pool::run` | 每天 05:30、節點不足時 | 直接換掉記憶體裡的節點池（快照由外層寫） |
//!
//! 範圍與分類檔每週才變一次，直接寫檔（先比對內容、暫存檔 + 改名）；寫完會通知 `Cdn` 重新讀取。

pub mod pool;
pub mod ranges;
pub mod scan;

use crate::cdn::Cdn;
use crate::config::JobsConfig;
use serde_json::Value;
use std::sync::Arc;

/// 工作的執行環境
pub struct JobCtx {
    /// 完整設定（`cdn`、`scan`、`pool` 區塊）
    pub cfg: Value,
    /// 共用的 CDN 狀態（路徑、網路、節點池、永久 IPv6 節點、候選 IP）
    pub cdn: Arc<Cdn>,
    /// 只跑某一家（2.x 的命令列參數）
    pub only: Option<String>,
}

impl JobCtx {
    pub fn new(cfg: Value, cdn: Arc<Cdn>) -> JobCtx {
        JobCtx { cfg, cdn, only: None }
    }

    pub fn jobs_cfg(&self) -> JobsConfig {
        JobsConfig::from_value(&self.cfg)
    }

    /// 這次要處理的 CDN（設定有啟用、而且符合 `only`）
    pub(crate) fn wants(&self, name: &str) -> bool {
        self.cdn.cfg.provider(name).map(|p| p.enabled).unwrap_or(false) && self.only.as_deref().map(|o| o == name).unwrap_or(true)
    }
}

/// 簡單的偽亂數（抽樣用，不需要密碼學等級）
pub(crate) struct Rng(u64);

impl Rng {
    pub fn new() -> Rng {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9e37_79b9_7f4a_7c15);
        Rng(t | 1)
    }
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    /// 0..n
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
    pub fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            v.swap(i, j);
        }
    }
}

/// 清單檔裡的 IPv4 CIDR（數字開頭的行）
pub(crate) fn v4_lines(text: Option<String>) -> Vec<String> {
    crate::util::read_list(&text.unwrap_or_default())
        .into_iter()
        .filter(|l| l.as_bytes().first().map(|c| c.is_ascii_digit()).unwrap_or(false))
        .collect()
}
