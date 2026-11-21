//! 小機器減量（`cdn.lite`，3.4.2）：只驗證問過 2 次以上的網域、驗證每分鐘上限、節點池測速節點數。
//! 不是關掉：問過 2 次以上的網域照樣驗證、換台灣節點

use super::selftest::setup;
use super::*;
use crate::Task;
use serde_json::json;

fn verifies(c: &Cdn) -> usize {
    c.take_tasks().iter().filter(|t| matches!(t, Task::Verify { .. })).count()
}

#[test]
fn lite_verifies_only_names_seen_twice() {
    let (c, _) = setup(json!({ "lite": true }));
    assert!(c.cfg.lite);
    let mut m = msg("once.test", 1, &["104.21.0.5"], vec![]);
    assert_eq!(c.apply(&mut m, "once.test", 1).provider, Some("cloudflare"));
    assert_eq!(verifies(&c), 0, "第一次：先不驗證（答案照樣是原始的）");
    let mut m = msg("once.test", 1, &["104.21.0.5"], vec![]);
    c.apply(&mut m, "once.test", 1);
    assert_eq!(verifies(&c), 1, "第二次：照樣驗證");
    assert_eq!(c.state().stats.lite_waited, 1);

    // 一般機器：第一次就驗證
    let (c, _) = setup(json!({}));
    assert!(!c.cfg.lite);
    let mut m = msg("once.test", 1, &["104.21.0.5"], vec![]);
    c.apply(&mut m, "once.test", 1);
    assert_eq!(verifies(&c), 1);
}

#[test]
fn lite_caps_verifies_per_minute() {
    let (c, _) = setup(json!({ "lite": true }));
    let n = crate::config::LITE_VERIFY_PER_MIN as usize + 5;
    let mut got = 0;
    for i in 0..n {
        let name = format!("cap{i}.test");
        for _ in 0..2 {
            let mut m = msg(&name, 1, &["104.21.0.5"], vec![]);
            c.apply(&mut m, &name, 1);
        }
        got += verifies(&c);
    }
    // 分鐘剛好換過時上限會重算一次：最多多一輪
    let cap = crate::config::LITE_VERIFY_PER_MIN as usize;
    assert!(got >= cap && got < n, "{got}");
    assert!(c.state().stats.lite_capped >= 1);
}

#[test]
fn lite_value_accepts_uci_strings() {
    use crate::config::lite_value;
    for (v, want) in [
        (json!(true), Some(true)),
        (json!(false), Some(false)),
        (json!("1"), Some(true)),
        (json!("0"), Some(false)),
        (json!("auto"), None),
        (json!(1), Some(true)),
    ] {
        assert_eq!(lite_value(Some(&v)), want, "{v}");
    }
    assert_eq!(lite_value(None), None);
    let (c, _) = setup(json!({ "lite": "1" }));
    assert!(c.cfg.lite, "UCI 的 option lite '1'");
}
