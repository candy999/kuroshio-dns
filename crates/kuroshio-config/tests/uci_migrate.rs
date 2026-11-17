//! `kuroshio uci-migrate`：從舊版預設設定遷移的結果，要跟這一版的預設設定一樣（規則同 OpenWrt 的 uci-defaults）

use kuroshio_config::uci_migrate::migrate;

// Windows 的 git 取出時可能換成 CRLF：一律比對 LF 版本
fn lf(s: &str) -> String {
    s.replace("\r\n", "\n")
}
fn v310() -> String {
    lf(include_str!("fixtures/kuroshio-3.1.0.config"))
}
fn v320() -> String {
    lf(include_str!("fixtures/kuroshio-3.2.0.config"))
}
fn now() -> String {
    lf(include_str!("../../../openwrt/kuroshio/files/kuroshio.config"))
}

/// 依順序列出每個 filter_list 的（enabled, name, url, category）
fn lists(text: &str) -> Vec<(String, String, String, String)> {
    let mut out = Vec::new();
    let mut cur: Option<[String; 4]> = None;
    let unq = |v: &str| v.trim().trim_matches('\'').to_string();
    for l in text.lines() {
        let t = l.trim();
        let mut words = t.split_whitespace();
        if words.next() == Some("config") {
            if let Some(c) = cur.take() {
                out.push((c[0].clone(), c[1].clone(), c[2].clone(), c[3].clone()));
            }
            if words.next() == Some("filter_list") {
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
    let (v310, v320, now) = (v310(), v320(), now());
    for (tag, old) in [("3.1.0", v310.as_str()), ("3.2.0", v320.as_str())] {
        let m = migrate(old).unwrap();
        assert_eq!(lists(&m.text), lists(&now), "從 {tag} 遷移：\n{}", m.log.join("\n"));
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
    let m = migrate(&now).unwrap();
    assert!(m.log.is_empty(), "{:?}", m.log);
    assert_eq!(m.text, now);
    // CRLF、BOM、`config` 後面接 Tab 的檔案也認得
    let crlf = format!(
        "\u{feff}{}",
        v320.replace('\n', "\r\n").replace("config filter_list", "config\tfilter_list")
    );
    let m = migrate(&crlf).unwrap();
    assert_eq!(lists(&m.text), lists(&now), "{:?}", m.log);
    assert!(!m.text.contains('\r'));
}

#[test]
fn user_changes_are_kept() {
    // 3.2：刪掉 OISD small、自己加了 Pro++（啟用）→ 不加回 OISD、不重複加 Pro++，其他三份照加
    let (v310, v320) = (v310(), v320());
    let mut t = v320.replace(
        "config filter_list\n\toption enabled '1'\n\toption name 'OISD small'\n\toption url 'https://small.oisd.nl/'\n\toption category 'ads'\n",
        "",
    );
    assert_ne!(t, v320, "測試資料要真的刪掉 OISD");
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
    let t = v310.replace(
        "\toption name 'blocklistproject tracking'\n",
        "\toption name 'blocklistproject tracking'\n\toption protect '1'\n",
    );
    assert_ne!(t, v310);
    let m = migrate(&t).unwrap();
    assert!(lists(&m.text).iter().any(|x| x.1 == "blocklistproject tracking"), "改過的不刪");
}

#[test]
fn not_a_kuroshio_config() {
    assert!(migrate("config dnsmasq\n\toption x '1'\n").is_err());
}

/// `config kuroshio 'main'` 寫了兩段：跟 uci / parse_text 一樣當成同一段，lists_version 取最後寫的那個
#[test]
fn duplicate_main_sections_are_merged() {
    let (v320, now) = (v320(), now());
    // 第二段 main 寫了 3.3：已經是最新的，不動
    let t = now.clone() + "\nconfig kuroshio 'main'\n\toption enabled '1'\n";
    let m = migrate(&t).unwrap();
    assert!(m.log.is_empty(), "第二段沒有 lists_version，沿用第一段的 3.3：{:?}", m.log);
    let t = v320.clone() + "\nconfig kuroshio 'main'\n\toption lists_version '3.3'\n";
    let m = migrate(&t).unwrap();
    assert!(m.log.is_empty(), "{:?}", m.log);
    assert_eq!(m.text, t);
    // 第二段 main 沒有 lists_version：看第一段的 3.2，做 3.3 遷移、改第一段那一行
    let t = v320.clone() + "\nconfig kuroshio 'main'\n\toption enabled '1'\n";
    let m = migrate(&t).unwrap();
    assert_eq!(lists(&m.text), lists(&now), "{:?}", m.log);
    assert_eq!(m.text.matches("option lists_version").count(), 1, "不另外加一行");
    assert_eq!(version(&m.text).as_deref(), Some("3.3"));
}

/// 同一個區段裡同一個選項寫了兩次：跟 uci 一樣取最後一個
#[test]
fn duplicate_option_last_wins() {
    let (v320, now) = (v320(), now());
    // 先 3.2 後 3.3 → 3.3：不動
    let t = v320.replace(
        "\toption lists_version '3.2'\n",
        "\toption lists_version '3.2'\n\toption lists_version '3.3'\n",
    );
    assert_ne!(t, v320);
    let m = migrate(&t).unwrap();
    assert!(m.log.is_empty(), "{:?}", m.log);
    // 先 3.3 後 3.2 → 3.2：做 3.3 遷移，兩行都改成 3.3
    let t = v320.replace(
        "\toption lists_version '3.2'\n",
        "\toption lists_version '3.3'\n\toption lists_version '3.2'\n",
    );
    let m = migrate(&t).unwrap();
    assert_eq!(lists(&m.text), lists(&now), "{:?}", m.log);
    assert_eq!(m.text.matches("option lists_version '3.3'").count(), 2);
    // 清單的選項重複：取最後一個（第一個是改過的名稱、最後一個是預設名稱 → 算沒改過，照樣遷移）
    let t = v310().replace(
        "\toption name 'Ruddernation（Adobe 驗證）'\n",
        "\toption name '我的'\n\toption name 'Ruddernation（Adobe 驗證）'\n",
    );
    let m = migrate(&t).unwrap();
    assert!(m.log.iter().any(|l| l.starts_with("Ruddernation 改成預設停用")), "{:?}", m.log);
}

/// `option enabled ''`：跟 uci-defaults 的 `${en:-1}` 一樣當成 1（啟用）
#[test]
fn empty_enabled_counts_as_enabled() {
    let v310 = v310();
    let t = v310.replace(
        "config filter_list\n\toption enabled '1'\n\toption name 'Ruddernation（Adobe 驗證）'",
        "config filter_list\n\toption enabled ''\n\toption name 'Ruddernation（Adobe 驗證）'",
    );
    assert_ne!(t, v310);
    let m = migrate(&t).unwrap();
    assert!(m.log.iter().any(|l| l.starts_with("Ruddernation 改成預設停用")), "{:?}", m.log);
    assert_eq!(lists(&m.text), lists(&now()));
}

/// lists_version 比版本號大小：降版或之後的版本號（3.10、4.0）不重做；看不懂的不動、只記 log；空白 = 很舊
#[test]
fn lists_version_compared_numerically() {
    let (v320, now) = (v320(), now());
    for v in ["3.10", "4.0", "4", "3.3.1"] {
        let t = now.replace("option lists_version '3.3'", &format!("option lists_version '{v}'"));
        assert_ne!(t, now);
        let m = migrate(&t).unwrap();
        assert!(m.log.is_empty(), "{v}：{:?}", m.log);
        assert_eq!(m.text, t, "{v}");
    }
    // 使用者刪掉 OISD small、lists_version 是之後的版本號：不加回來
    let t = now
        .replace(
            "config filter_list\n\toption enabled '1'\n\toption name 'OISD small'\n\toption url 'https://small.oisd.nl/'\n\toption category 'ads'\n",
            "",
        )
        .replace("option lists_version '3.3'", "option lists_version '3.10'");
    assert!(!t.contains("small.oisd.nl"), "測試資料要真的刪掉 OISD");
    assert!(migrate(&t).unwrap().log.is_empty());
    // 看不懂的版本號：什麼都不動，log 記一筆
    for v in ["abc", "3.x", " 3.2"] {
        let t = v320.replace("option lists_version '3.2'", &format!("option lists_version '{v}'"));
        let m = migrate(&t).unwrap();
        assert_eq!(m.text, t, "{v}");
        assert_eq!(
            m.log,
            vec![format!("main.lists_version 是「{v}」，看不懂這個版本號：過濾清單不做遷移")],
            "{v}"
        );
    }
    // 空白 = 很舊：從 3.1 開始遷移；3.2.x 只做 3.3
    let t = v310().replace("config kuroshio 'main'", "config kuroshio 'main'\n\toption lists_version ''");
    let m = migrate(&t).unwrap();
    assert_eq!(lists(&m.text), lists(&now), "{:?}", m.log);
    let t = v320.replace("option lists_version '3.2'", "option lists_version '3.2.1'");
    let m = migrate(&t).unwrap();
    assert_eq!(lists(&m.text), lists(&now), "{:?}", m.log);
    assert_eq!(version(&m.text).as_deref(), Some("3.3"));
}
