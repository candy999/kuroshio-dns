//! 3.4.2：開機後還不知道會不會串接時，CDN 的定時檢查先等（`chain::deciding`）。
//! 用到行程層級的狀態（目前的下游狀態機、最近一次路徑檢查），所以獨立一個測試執行檔

use kuroshio::chain::client::{Client, Timing};
use kuroshio::chain::ident::NodeKey;
use kuroshio_config::chain::ChainSettings;
use kuroshio_net::path::Report;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

fn client(chain: bool, dir: &std::path::Path) -> Arc<Client> {
    let s = ChainSettings::from_cfg(&kuroshio_config::build(&json!({ "upstream": { "chain": chain } })));
    let timing = Timing {
        ask: Duration::from_millis(300),
        heartbeat: Duration::from_millis(400),
        early_min: Duration::from_millis(50),
        early_max: Duration::from_millis(100),
        retry_min: Duration::from_millis(200),
        retry_max: Duration::from_millis(800),
        fail_limit: 3,
        ..Timing::default()
    };
    Client::new(s, Arc::new(NodeKey::new(dir.join("community"))), timing)
}

#[test]
fn cdn_checks_wait_until_chain_is_decided() {
    let dir = std::env::temp_dir().join(format!("kuroshio-chain-deciding-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("community")).unwrap();
    kuroshio_net::path::clear();
    // 服務還沒啟動：不等
    assert!(!kuroshio::chain::deciding());
    // `chain` 開著、還沒做過路徑檢查：等
    kuroshio::chain::install(client(true, &dir));
    assert!(kuroshio::chain::deciding());
    // 路徑檢查做完、沒有上游黑潮（狀態 none）：不等，照單獨運作做 CDN 檢查
    kuroshio_net::path::apply(&Report::default(), false);
    assert!(!kuroshio::chain::deciding());
    // `chain` 關著：從一開始就不等
    kuroshio_net::path::clear();
    kuroshio::chain::install(client(false, &dir));
    assert!(!kuroshio::chain::deciding());
    let _ = std::fs::remove_dir_all(&dir);
}
