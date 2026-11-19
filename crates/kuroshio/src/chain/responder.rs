//! 上游回應器：回答 `chain.kuroshio` 底下的 CH TXT 查詢（規格 1.9、3.3、4.2）
//!
//! WP4 的最小可用版本：只有下游狀態機會呼叫的 [`Responder::set_upstream_path`]（自己串接中的上游的鏈）。
//! 回答查詢的部分由 WP3 實作，合併時以 WP3 的為準。

use crate::chain::ident::NodeKey;
use kuroshio_config::chain::ChainSettings;
use std::sync::{Arc, Mutex};

pub struct Responder {
    /// 自己串接中的上游的鏈（沒串接是 None）；auth 回應的 `path` = 這個 + 自己
    upstream_path: Mutex<Option<Vec<Vec<u8>>>>,
}

impl Responder {
    pub fn new(_settings: &ChainSettings, _key: Arc<NodeKey>) -> Arc<Responder> {
        Arc::new(Responder {
            upstream_path: Mutex::new(None),
        })
    }

    /// 下游狀態機（WP4）在綁定、解除時設定：自己串接中的上游的鏈
    pub fn set_upstream_path(&self, path: Option<Vec<Vec<u8>>>) {
        *self.upstream_path.lock().unwrap() = path;
    }

    pub fn upstream_path(&self) -> Option<Vec<Vec<u8>>> {
        self.upstream_path.lock().unwrap().clone()
    }
}
