//! 共用結果（串接模式，3.4.0）：上游匯出、下游匯入節點池與永久 IPv6 節點

use super::*;
use crate::pools::PoolNode;

fn cdn(tag: &str) -> Arc<Cdn> {
    cdn_with(
        json!({ "providers": { "cloudflare": { "enabled": true }, "fastly": { "enabled": true } } }),
        paths_no_seed(tag),
        MockNet::new(),
    )
}

fn pool4(c: &Cdn, p: &str) -> Vec<String> {
    c.state().pools.p[p].pool4.iter().map(|x| x.ip.to_string()).collect()
}

fn pools_json(cf: &[&str], cf6: &[&str]) -> Vec<u8> {
    let node = |ip: &&str| json!({ "ip": ip, "ms": 5 });
    serde_json::to_vec(&json!({
        "providers": {
            "cloudflare": {
                "v4": cf.iter().map(node).collect::<Vec<_>>(),
                "v6": cf6.iter().map(node).collect::<Vec<_>>(),
                "updatedAt": "2026-11-18T05:30:00.000Z",
                "tw48": ["2606:4700:10::/48", "2001:db8:1::/48"]
            },
            "someOtherCdn": { "v4": [{ "ip": "198.51.100.1", "ms": 1 }] }
        }
    }))
    .unwrap()
}

#[test]
fn import_shared_drops_out_of_range_nodes() {
    let c = cdn("share-drop");
    let got = c
        .import_shared(
            Some(&pools_json(
                &["104.16.1.1", "192.0.2.1", "104.16.2.2"],
                &["2606:4700::1", "2001:db8::1"],
            )),
            None,
            48,
        )
        .unwrap();
    assert_eq!(got, vec![("cloudflare".to_string(), 3)]);
    assert_eq!(pool4(&c, "cloudflare"), vec!["104.16.1.1", "104.16.2.2"]);
    let st = c.state();
    let d = &st.pools.p["cloudflare"];
    assert_eq!(d.pool6.iter().map(|x| x.ip.to_string()).collect::<Vec<_>>(), vec!["2606:4700::1"]);
    // 不在範圍裡的分類網段也不收
    assert_eq!(d.rest["tw48"], json!(["2606:4700:10::/48"]));
    assert_eq!(d.rest["updatedAt"], json!("2026-11-18T05:30:00.000Z"));
    assert!(st.pools.dirty, "換掉之後要寫檔");
    drop(st);
    // 每家的上限
    let many: Vec<String> = (1..=10).map(|i| format!("104.16.3.{i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    c.import_shared(Some(&pools_json(&many, &[])), None, 4).unwrap();
    assert_eq!(pool4(&c, "cloudflare").len(), 4);
}

#[test]
fn import_shared_keeps_pool_when_all_rejected() {
    let c = cdn("share-keep");
    c.with_state(|st| {
        st.pools
            .replace("cloudflare", vec![PoolNode::new(ip("104.16.9.9"))], vec![], Default::default());
        st.pools.dirty = false;
    });
    let got = c
        .import_shared(Some(&pools_json(&["192.0.2.1", "198.51.100.7"], &[])), None, 48)
        .unwrap();
    assert!(got.is_empty(), "{got:?}");
    assert_eq!(pool4(&c, "cloudflare"), vec!["104.16.9.9"]);
    assert!(!c.state().pools.dirty);
    // 格式錯誤、空的節點池：錯誤，不動原本的
    assert!(c.import_shared(Some(b"{not json"), None, 48).is_err());
    assert!(c.import_shared(Some(br#"{"providers":{}}"#), None, 48).is_err());
    assert_eq!(pool4(&c, "cloudflare"), vec!["104.16.9.9"]);
    // IPv6 節點全部在範圍外：保留原本的紀錄
    c.with_state(|st| {
        st.v6.mark_ok("cloudflare", ip("2606:4700::9"), "TPE", Some(3.0));
    });
    let v6 = br#"{"providers":{"cloudflare":{"2001:db8::5":{"pop":"TPE","ms":2}}}}"#;
    assert!(c.import_shared(None, Some(v6), 48).unwrap().is_empty());
    assert!(c.state().v6.contains("cloudflare", ip("2606:4700::9")));
}

#[test]
fn export_then_import_roundtrip() {
    let up = cdn("share-up");
    // 還沒有節點池工作的結果（只有種子／空的）：不分享節點池
    assert_eq!(up.export_shared().pools, None);
    let mut rest = serde_json::Map::new();
    rest.insert("updatedAt".into(), json!("2026-11-18T05:30:00.000Z"));
    up.with_state(|st| {
        let mut n = PoolNode::new(ip("104.16.5.5"));
        n.ms = crate::util::Num::V(4.0);
        st.pools
            .replace("cloudflare", vec![n, PoolNode::new(ip("104.16.6.6"))], vec![], rest);
        st.v6.mark_ok("cloudflare", ip("2606:4700::7"), "TPE", Some(2.0));
    });
    std::fs::create_dir_all(up.paths.state_dir.join("cdn/ranges")).unwrap();
    std::fs::write(up.paths.state_dir.join("cdn/ranges/cloudflare-ipv4.txt"), "104.16.0.0/13\n").unwrap();
    let e = up.export_shared();
    // 內容只跟資料有關：再匯出一次位元組一樣（雜湊才會一樣）
    assert_eq!(e, up.export_shared());
    assert_eq!(e.ranges.keys().collect::<Vec<_>>(), vec!["cloudflare-ipv4.txt"]);
    let down = cdn("share-down");
    let got = down.import_shared(e.pools.as_deref(), e.v6.as_deref(), 48).unwrap();
    assert_eq!(got, vec![("cloudflare".to_string(), 3)]);
    assert_eq!(pool4(&down, "cloudflare"), vec!["104.16.5.5", "104.16.6.6"]);
    assert_eq!(down.state().pools.p["cloudflare"].pool4[0].ms, crate::util::Num::V(4.0));
    assert!(down.state().v6.contains("cloudflare", ip("2606:4700::7")));
    assert!(down.state().pools.p["cloudflare"].pool6.iter().any(|x| x.ip == ip("2606:4700::7")));
}

/// 3.4.3：串接拿到的節點池跟這台原本的合併（上游的在前），這台記的壞節點不清掉、也不放進來
#[test]
fn import_shared_merges_and_keeps_bad_marks() {
    let c = cdn("share-merge");
    c.with_state(|st| {
        st.pools
            .replace("cloudflare", vec![PoolNode::new(ip("104.16.9.9"))], vec![], Default::default());
        let d = st.pools.p.get_mut("cloudflare").unwrap();
        d.bad.insert(
            ip("104.16.1.1"),
            crate::pools::Bad {
                at: crate::util::now_ms(),
                reason: "連線失敗".into(),
                quality: false,
            },
        );
    });
    c.import_shared(Some(&pools_json(&["104.16.1.1", "104.16.2.2"], &[])), None, 48)
        .unwrap();
    assert_eq!(pool4(&c, "cloudflare"), vec!["104.16.2.2", "104.16.9.9"], "上游的在前、自己的留著、壞的不放進來");
    assert!(c.state().pools.p["cloudflare"].bad.contains_key(&ip("104.16.1.1")), "壞節點紀錄還在");
}

/// 3.4.3：上游給的官方範圍跟這台現有的重疊多少（串接匯入範圍前檢查）
#[test]
fn ranges_overlap_against_own_ranges() {
    let c = cdn("share-overlap");
    let f = c.ranges_overlap("cloudflare", &[ip("104.16.0.1"), ip("192.0.2.1")]).unwrap();
    assert!((f - 0.5).abs() < 1e-9, "{f}");
    assert_eq!(c.ranges_overlap("cloudflare", &[]), None);
    assert_eq!(c.ranges_overlap("no-such-cdn", &[ip("104.16.0.1")]), None);
}
