//! `kuroshio uci-migrate`：從舊版預設設定遷移的結果，要跟這一版的預設設定一樣（規則同 OpenWrt 的 uci-defaults）

use kuroshio_config::uci_migrate::migrate;

const V310: &str = include_str!("fixtures/kuroshio-3.1.0.config");
const V320: &str = include_str!("fixtures/kuroshio-3.2.0.config");
const NOW: &str = include_str!("../../../openwrt/kuroshio/files/kuroshio.config");

/// 依順序列出每個 filter_list 的（enabled, name, url, category）
fn lists(text: &str) -> Vec<(String, String, String, String)> {
    let mut out = Vec::new();
    let mut cur: Option<[String; 4]> = None;
    let unq = |v: &str| v.trim().trim_matches('\'').to_string();
    for l in text.lines() {
        let t = l.trim();
        if t.starts_with("config ") {
            if let Some(c) = cur.take() {
                out.push((c[0].clone(), c[1].clone(), c[2].clone(), c[3].clone()));
            }
            if t == "config filter_list" || t.starts_with("config filter_list ") {
                cur = Some(["1".into(), String::new(), String::new(), String::new()]);
            }
            continue;
        }
        if let Some(c) = cur.as_mut() {
            let mut it = t.splitn(3, char::is_whitespace);
            if it.next() == Some("option") {
                let (k, v) = (it.next().unwrap_or(""), unq(it.next().unwrap_or("")));
                match k {
                    "enabled" => c[0] = v,
                    "name" => c[1] = v,
                    "url" => c[2] = v,
                    "category" => c[3] = v,
                    _ => {}
                }
            }
        }
    }
    if let Some(c) = cur {
        out.push((c[0].clone(), c[1].clone(), c[2].clone(), c[3].clone()));
    }
    out
}

fn version(text: &str) -> Option<String> {
    text.lines()
        .find(|l| l.trim().starts_with("option lists_version"))
        .map(|l| l.trim().rsplit(' ').next().unwrap().trim_matches('\'').to_string())
}

#[test]
fn from_3_1_and_3_2_defaults_matches_current_default() {
    for (tag, old) in [("3.1.0", V310), ("3.2.0", V320)] {
        let m = migrate(old).unwrap();
        assert_eq!(lists(&m.text), lists(NOW), "從 {tag} 遷移：\n{}", m.log.join("\n"));
        assert_eq!(version(&m.text).as_deref(), Some("3.3"), "{tag}");
        assert!(!m.log.is_empty());
        // 其他區段原樣保留
        assert_eq!(
            old.lines()
                .filter(|l| l.trim().starts_with("config ") && !l.contains("filter_list"))
                .count(),
            m.text
                .lines()
                .filter(|l| l.trim().starts_with("config ") && !l.contains("filter_list"))
                .count()
        );
        // 再跑一次：不動
        let again = migrate(&m.text).unwrap();
        assert!(again.log.is_empty(), "{:?}", again.log);
        assert_eq!(again.text, m.text);
    }
    // 這一版的預設設定：不需要遷移
    let now = migrate(NOW).unwrap();
    assert!(now.log.is_empty(), "{:?}", now.log);
    assert_eq!(now.text, NOW);
}

#[test]
fn user_changes_are_kept() {
    // 3.2：刪掉 OISD small、自己加了 Pro++（啟用）→ 不加回 OISD、不重複加 Pro++，其他三份照加
    let mut t = V320.replace(
        "config filter_list\n\toption enabled '1'\n\toption name 'OISD small'\n\toption url 'https://small.oisd.nl/'\n\toption category 'ads'\n",
        "",
    );
    assert_ne!(t, V320, "測試資料要真的刪掉 OISD");
    t.push_str("\nconfig filter_list\n\toption enabled '1'\n\toption name 'Mine'\n\toption url 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt'\n\toption category 'ads'\n");
    let m = migrate(&t).unwrap();
    let l = lists(&m.text);
    assert!(!l.iter().any(|x| x.2 == "https://small.oisd.nl/"));
    let pro: Vec<_> = l.iter().filter(|x| x.2.ends_with("pro.plus.txt")).collect();
    assert_eq!(pro.len(), 1);
    assert_eq!(pro[0].1, "Mine");
    assert_eq!(pro[0].0, "1", "使用者的設定不動");
    assert_eq!(l.iter().filter(|x| x.0 == "0" && x.2.contains("tif.txt")).count(), 1);
    assert_eq!(m.log.iter().filter(|x| x.starts_with("新增")).count(), 3, "{:?}", m.log);

    // 3.1：改過的清單（多了 protect 選項）不動；順序調整過的不重新排序
    let t = V310.replace(
        "\toption name 'blocklistproject tracking'\n",
        "\toption name 'blocklistproject tracking'\n\toption protect '1'\n",
    );
    assert_ne!(t, V310);
    let m = migrate(&t).unwrap();
    assert!(lists(&m.text).iter().any(|x| x.1 == "blocklistproject tracking"), "改過的不刪");
}

#[test]
fn not_a_kuroshio_config() {
    assert!(migrate("config dnsmasq\n\toption x '1'\n").is_err());
}
