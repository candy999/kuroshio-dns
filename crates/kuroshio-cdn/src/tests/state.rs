//! 狀態檔：用 repo 附帶的種子資料（2.x 正式伺服器匯出）測讀寫相容、未知欄位保留、種子帶入

use super::*;
use crate::cdn::STATE_FILES;
use crate::util::now_ms;

fn strip_saved_at(v: &mut Value) {
    if let Some(o) = v.as_object_mut() {
        o.remove("savedAt");
    }
}

fn parse(b: &[u8]) -> Value {
    serde_json::from_slice(b).unwrap()
}

/// 種子資料加上一些不認識的欄位，放進狀態目錄
fn seed_state_with_unknowns(state: &std::path::Path) -> HashMap<&'static str, Value> {
    let seed = repo().join("data/seed");
    let mut pools: Value = parse(&std::fs::read(seed.join("cdn-pools.json")).unwrap());
    pools["futureTop"] = json!({ "a": 1 });
    pools["providers"]["cloudflare"]["futureProv"] = json!("x");
    pools["providers"]["cloudflare"]["v4"][0]["futureNode"] = json!([1, 2]);
    pools["providers"]["someNewCdn"] = json!({ "v4": [{ "ip": "1.2.3.4", "ms": 1 }], "note": "未啟用的 CDN 也保留" });
    let mut v6: Value = parse(&std::fs::read(seed.join("v6-nodes.json")).unwrap());
    v6["futureTop"] = json!(true);
    let first = v6["providers"]["cloudflare"].as_object().unwrap().keys().next().unwrap().clone();
    v6["providers"]["cloudflare"][&first]["futureNode"] = json!({ "k": "v" });
    let mut dom: Value = parse(&std::fs::read(seed.join("cdn-domains.json")).unwrap());
    dom["futureTop"] = json!(1);
    dom["domains"][0]["futureDomain"] = json!("y");
    let i = dom["domains"]
        .as_array()
        .unwrap()
        .iter()
        .position(|d| d.get("v4").is_some())
        .unwrap();
    dom["domains"][i]["v4"]["futureVerdict"] = json!(3);
    let j = dom["domains"]
        .as_array()
        .unwrap()
        .iter()
        .position(|d| d.get("cross4").is_some())
        .unwrap();
    dom["domains"][j]["cross4"]["tried"][0]["futureTried"] = json!(null);
    let harvest = json!({ "cloudflare": { "v4": { "104.16.1.1": 1793085962496u64, "104.16.0.9": 2 }, "v6": {}, "futureH": 1 } });
    let zone = json!({ "cloudflare|104.16.1.1": { "hit": 3, "miss": 1, "at": 1793085962496u64, "futureZ": "z" } });
    let out: HashMap<&'static str, Value> = [
        ("cdn/pools.json", pools),
        ("cdn/v6-nodes.json", v6),
        ("cdn-domains.json", dom),
        ("cdn/harvest.json", harvest),
        ("cdn/ip-zone.json", zone),
    ]
    .into_iter()
    .collect();
    for (k, v) in &out {
        let p = state.join(k);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, serde_json::to_vec(v).unwrap()).unwrap();
    }
    // 候選 IP 的順序有意義（依加入順序淘汰）：直接寫文字，不經過會排序的 json!
    std::fs::write(
        state.join("cdn/harvest.json"),
        r#"{"cloudflare":{"v4":{"104.16.1.1":1793085962496,"104.16.0.9":2},"v6":{},"futureH":1}}"#,
    )
    .unwrap();
    out
}

fn full_cfg() -> Value {
    kuroshio_config::defaults()
}

#[test]
fn round_trip_keeps_format_and_unknown_fields() {
    let paths = paths_no_seed("roundtrip");
    let orig = seed_state_with_unknowns(&paths.state_dir);
    let c = Cdn::load(&full_cfg(), paths.clone(), MockNet::new());
    // 沒有變動、沒有用種子：只有網域資料庫要寫（舊版單一檔案搬進分片）
    let first: Vec<String> = c.snapshots().into_iter().map(|x| x.0).collect();
    assert_eq!(first, vec!["cdn-domains.json".to_string()]);
    assert!(c.snapshots().is_empty(), "取出後不再重複");
    let snap: HashMap<String, Vec<u8>> = c.snapshots_all().into_iter().collect();
    assert_eq!(snap.len(), STATE_FILES.len());
    for (k, v) in &orig {
        let mut a = v.clone();
        let mut b = parse(&snap[*k]);
        strip_saved_at(&mut a);
        strip_saved_at(&mut b);
        if *k == "cdn-domains.json" {
            // 2.x 用 Map 的順序、3.0 依查詢次數排序：逐筆比對
            let key = |v: &Value| -> Vec<(String, Value)> {
                let mut l: Vec<(String, Value)> = v["domains"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|d| (d["name"].as_str().unwrap().to_string(), d.clone()))
                    .collect();
                l.sort_by(|x, y| x.0.cmp(&y.0));
                l
            };
            let (la, lb) = (key(&a), key(&b));
            assert_eq!(la.len(), lb.len());
            for (x, y) in la.iter().zip(&lb) {
                assert_eq!(x, y, "網域 {} 讀寫後不一樣", x.0);
            }
            a.as_object_mut().unwrap().remove("domains");
            b.as_object_mut().unwrap().remove("domains");
        }
        assert_eq!(a, b, "{k} 讀寫後不一樣");
    }
    // 再讀一次、再寫一次：完全一樣
    let paths2 = paths_no_seed("roundtrip2");
    for (k, v) in &snap {
        let p = paths2.state_dir.join(k);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, v).unwrap();
    }
    let c2 = Cdn::load(&full_cfg(), paths2, MockNet::new());
    let snap2: HashMap<String, Vec<u8>> = c2.snapshots_all().into_iter().collect();
    for (k, v) in &snap {
        let mut a = parse(v);
        let mut b = parse(&snap2[k]);
        strip_saved_at(&mut a);
        strip_saved_at(&mut b);
        assert_eq!(a, b, "{k} 第二次讀寫不一樣");
    }
    // 讀進來的內容可以用
    let st = c2.state();
    assert!(st.pools.serve_ips("cloudflare", 4).len() >= 2);
    assert!(st.db.domains.len() > 1000);
    assert!(st.v6.count("cloudflare") > 10);
    assert_eq!(
        st.db.harvest_of("cloudflare", false),
        ips(&["104.16.1.1", "104.16.0.9"]),
        "候選 IP 保持加入順序"
    );
    assert_eq!(st.pools.zone["cloudflare|104.16.1.1"].hit, 3);
}

#[test]
fn seed_used_when_state_empty() {
    let d = tmpdir("seed");
    let paths = Paths::new(d.join("state"), repo().join("data"));
    let before = now_ms();
    let c = Cdn::load(&full_cfg(), paths, MockNet::new());
    let snap: HashMap<String, Vec<u8>> = c.snapshots().into_iter().collect();
    for k in ["cdn/pools.json", "cdn/v6-nodes.json", "cdn-domains.json"] {
        assert!(snap.contains_key(k), "種子帶入後要寫入 {k}");
    }
    assert!(c.snapshots().is_empty(), "取出後不再重複");
    let st = c.state();
    assert!(
        st.db.domains.values().all(|e| e.last_seen >= before),
        "匯入時把最後出現時間設成現在"
    );
    // 種子裡「通過」的結果是別台機器驗證的：匯入後都不在有效期內，自己驗證過才換節點
    let now = now_ms() + 1;
    for e in st.db.domains.values() {
        for v in [&e.v4, &e.v6].into_iter().flatten() {
            assert!(!(v.is("ok") && v.valid(now)), "{} 的種子判定不能直接生效", e.name);
        }
        assert!(!e.ecs.as_ref().is_some_and(|x| x.is("ok") && x.until.unwrap_or(0) > now));
        assert!(!e.cross4.as_ref().is_some_and(|x| x.is("ok") && x.until.unwrap_or(0) > now));
    }
    assert!(!st.pools.serve_ips("cloudflare", 4).is_empty());
    // 種子的節點也會被分類成 Cloudflare 台灣節點（data/cdn 的範圍與分類）
    let first = st.pools.serve_ips("cloudflare", 4)[0];
    assert_eq!(st.pools.classify(first).map(|x| x.provider), Some("cloudflare"));
}

#[test]
fn state_files_are_used_over_seed() {
    let d = tmpdir("noseed-override");
    let paths = Paths::new(d.join("state"), repo().join("data"));
    let pools = json!({ "providers": { "cloudflare": { "v4": [{ "ip": "104.16.0.1", "ms": 1.5, "pop": "TPE" }], "v6": [] } } });
    std::fs::create_dir_all(paths.state_dir.join("cdn")).unwrap();
    std::fs::write(paths.state_dir.join("cdn/pools.json"), serde_json::to_vec(&pools).unwrap()).unwrap();
    let c = Cdn::load(&full_cfg(), paths, MockNet::new());
    assert_eq!(c.state().pools.serve_ips("cloudflare", 4), ips(&["104.16.0.1"]));
    // 沒有 v4 的節點池檔 → 算空的，用種子
    let d2 = tmpdir("empty-pools");
    let paths2 = Paths::new(d2.join("state"), repo().join("data"));
    std::fs::create_dir_all(paths2.state_dir.join("cdn")).unwrap();
    std::fs::write(
        paths2.state_dir.join("cdn/pools.json"),
        br#"{"providers":{"cloudflare":{"v4":[]}}}"#,
    )
    .unwrap();
    let c2 = Cdn::load(&full_cfg(), paths2, MockNet::new());
    assert!(c2.state().pools.serve_ips("cloudflare", 4).len() >= 4);
}

#[test]
fn load_with_custom_reader() {
    // 外層的快照寫入器提供讀取（例如壓縮過的快照）
    let paths = paths_no_seed("reader");
    let calls = Mutex::new(Vec::new());
    let read = |rel: &str| {
        calls.lock().unwrap().push(rel.to_string());
        (rel == "cdn/ip-zone.json").then(|| br#"{"fastly|151.101.1.1":{"hit":1,"miss":0}}"#.to_vec())
    };
    let c = Cdn::load_with(&full_cfg(), paths, MockNet::new(), &read);
    let mut got = calls.lock().unwrap().clone();
    got.sort();
    let mut want: Vec<String> = STATE_FILES.iter().map(|s| s.to_string()).collect();
    want.push(crate::db::MANIFEST.to_string());
    want.sort();
    assert_eq!(got, want);
    assert!(c.state().pools.zone_hit("fastly", ip("151.101.1.1")));
}

#[test]
fn chunked_domains_snapshot_matches_single_pass() {
    // snapshots() 分批寫的網域資料庫，內容要跟一次寫完（snapshots_all()，關機時用）完全一樣
    let d = tmpdir("chunked");
    let paths = Paths::new(d.join("state"), repo().join("data"));
    let c = Cdn::load(&full_cfg(), paths, MockNet::new());
    c.with_state(|st| {
        assert!(st.db.domains.len() > 1000, "種子要夠多筆才會分好幾批");
        st.db.dirty = true;
        st.db.harvest_dirty = true;
        st.pools.dirty = true;
        st.pools.zone_dirty = true;
        st.v6.dirty = true;
    });
    let part = c.snapshots();
    let order: Vec<&str> = part.iter().map(|x| x.0.as_str()).collect();
    assert_eq!(order, crate::cdn::STATE_FILES, "檔案順序不變");
    let part: HashMap<String, Vec<u8>> = part.into_iter().collect();
    let all: HashMap<String, Vec<u8>> = c.snapshots_all().into_iter().collect();
    let strip = |b: &[u8]| -> String {
        // savedAt 是寫入時間，兩次不會一樣：拿掉再逐字比對
        let s = String::from_utf8(b.to_vec()).unwrap();
        let i = s.find("\"domains\":[").unwrap();
        assert!(s.starts_with("{\"savedAt\":\""));
        s[i..].to_string()
    };
    assert_eq!(strip(&part["cdn-domains.json"]), strip(&all["cdn-domains.json"]));
    // 不認識的最上層欄位也要原樣留著（外框跟一次寫完時相同）
    c.with_state(|st| {
        st.db
            .load_domains(
                br#"{"savedAt":"x","domains":[{"name":"a.test","hits":2},{"name":"b.test","hits":5}],"future":{"k":[1,2]}}"#,
                false,
            )
            .unwrap();
        st.db.dirty = true;
    });
    let part: HashMap<String, Vec<u8>> = c.snapshots().into_iter().collect();
    let v: Value = serde_json::from_slice(&part["cdn-domains.json"]).unwrap();
    assert_eq!(v["future"], json!({"k": [1, 2]}));
    assert_eq!(v["domains"][0]["name"], "b.test");
    assert_eq!(v["domains"].as_array().unwrap().len(), 2);
    let all: HashMap<String, Vec<u8>> = c.snapshots_all().into_iter().collect();
    assert_eq!(strip(&part["cdn-domains.json"]), strip(&all["cdn-domains.json"]));
}

#[test]
fn streamed_domains_snapshot_matches_single_pass() {
    // 網域資料庫邊序列化邊寫（write_domains）：內容要跟一次寫完的完全一樣，讀得回來
    let d = tmpdir("streamed");
    let paths = Paths::new(d.join("state"), repo().join("data"));
    let c = Cdn::load(&full_cfg(), paths, MockNet::new());
    c.with_state(|st| {
        st.db.dirty = true;
        st.pools.dirty = true;
    });
    let (small, ch) = c.snapshots_sharded(false);
    assert_eq!(ch.changed.len(), ch.shards, "整個資料庫有變動：每片都要寫");
    assert!(ch.changed.iter().all(|x| x.1));
    assert!(ch.manifest.is_some(), "種子帶入：還沒有分片清單");
    assert!(small.iter().any(|x| x.0 == "cdn/pools.json"));
    assert!(small.iter().all(|x| x.0 != "cdn-domains.json"), "網域資料庫不整份序列化");
    assert!(!c.state().db.changed(), "登記之後不再重複");
    let (_, ch2) = c.snapshots_sharded(false);
    assert!(ch2.changed.is_empty() && ch2.manifest.is_none());

    /// 每次只收一小段（模擬檔案寫入），記下最大的一段
    struct Sink(Vec<u8>, usize);
    impl std::io::Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.1 = self.1.max(b.len());
            self.0.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut w = Sink(Vec::new(), 0);
    c.write_domains(&mut w).unwrap();
    let all: HashMap<String, Vec<u8>> = c.snapshots_all().into_iter().collect();
    let strip = |b: &[u8]| -> String {
        let s = String::from_utf8(b.to_vec()).unwrap();
        s[s.find("\"domains\":[").unwrap()..].to_string()
    };
    assert_eq!(strip(&w.0), strip(&all["cdn-domains.json"]));
    let n = c.state().db.domains.len();
    assert!(w.1 < w.0.len() / 4, "分批寫出（最大一段 {} / 全部 {}）", w.1, w.0.len());
    let mut db = crate::db::Db::new(1_000_000);
    assert_eq!(db.load_domains(&w.0, false).unwrap(), n);
    // 關機：全部都算有變動
    let (_, ch3) = c.snapshots_sharded(true);
    assert_eq!(ch3.changed.len(), ch3.shards);
}

/// 把變動的分片（與清單）寫進狀態目錄（模擬快照寫入器：分片壓縮、清單一般 JSON）
fn write_changes(c: &Cdn, dir: &std::path::Path, ch: &crate::cdn::DomainChanges) -> Vec<(usize, usize)> {
    let mut sizes = Vec::new();
    for (i, _) in &ch.changed {
        let mut raw = Vec::new();
        c.write_shard(ch.shards, *i, &mut raw).unwrap();
        let z = crate::statefile::compress(&raw);
        let p = crate::statefile::zst_path(&dir.join(crate::db::shard_file(ch.shards, *i)));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, &z).unwrap();
        sizes.push((raw.len(), z.len()));
    }
    if let Some((m, retire)) = &ch.manifest {
        std::fs::write(dir.join(crate::db::MANIFEST), m).unwrap();
        for r in retire {
            crate::statefile::remove(&dir.join(r));
        }
    }
    sizes
}

#[test]
fn shards_migrate_and_track_changes() {
    // (iv) 舊版單一檔案 → 分片：讀得進來、全部重寫、清單寫好後刪掉舊檔；再啟動時內容一樣
    let paths = paths_no_seed("shards");
    let dir = paths.state_dir.clone();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(repo().join("data/seed/cdn-domains.json"), dir.join(crate::db::FILE)).unwrap();
    let c = Cdn::load(&full_cfg(), paths.clone(), MockNet::new());
    let n = c.state().db.domains.len();
    assert!(n > 1000);
    let (_, ch) = c.snapshots_sharded(false);
    assert_eq!(ch.changed.len(), ch.shards, "搬家：每片都寫");
    let (_, retire) = ch.manifest.clone().expect("要寫分片清單");
    assert_eq!(retire, vec![crate::db::FILE.to_string()]);
    write_changes(&c, &dir, &ch);
    assert!(!dir.join(crate::db::FILE).exists(), "搬完刪掉舊檔");
    let c2 = Cdn::load(&full_cfg(), paths.clone(), MockNet::new());
    assert_eq!(c2.state().db.domains.len(), n);
    let (_, ch) = c2.snapshots_sharded(false);
    assert!(ch.changed.is_empty() && ch.manifest.is_none(), "內容沒變：什麼都不用寫");

    // (ii) 一個驗證結果的變動只重寫一片
    // 固定挑同一個（HashMap 的順序每次執行不同）：有供應商、而且原本就有 IPv4 驗證結果的網域中名稱最小的
    drop(c);
    let name = c2
        .state()
        .db
        .domains
        .values()
        .filter(|d| d.provider().is_some() && d.v4.is_some())
        .map(|d| d.name.to_string())
        .min()
        .unwrap();
    c2.with_state(|st| st.db.set_verdict(&name, 4, |v| v.verdict = Some(crate::util::intern("fail"))));
    let (_, ch) = c2.snapshots_sharded(false);
    assert_eq!(ch.changed, vec![(crate::db::shard_of(&name, ch.shards), true)]);

    // (iii) 只有計數（查詢次數、最後出現時間）：標成「只有計數」，不算重要變動
    let (prov, ips4) = {
        let st = c2.state();
        let e = st.db.get(&name).unwrap();
        (e.provider().unwrap_or("cloudflare").to_string(), e.ips4.to_vec())
    };
    c2.with_state(|st| {
        let cname = st.db.get(&name).unwrap().cname.val().cloned();
        let via = st.db.get(&name).unwrap().via.val().map(|v| v.to_string()).unwrap_or_default();
        st.db.touch(&name, &prov, &via, &ips4, &[], cname.as_deref());
    });
    let (_, ch) = c2.snapshots_sharded(false);
    assert_eq!(ch.changed, vec![(crate::db::shard_of(&name, ch.shards), false)], "只有計數");
    // 計數跟著分片一起寫出去
    let hits = c2.state().db.get(&name).unwrap().hits;
    write_changes(&c2, &dir, &ch);
    let before = serde_json::to_string(c2.state().db.get(&name).unwrap()).unwrap();
    drop(c2);
    let c3 = Cdn::load(&full_cfg(), paths.clone(), MockNet::new());
    let after = c3.state().db.get(&name).map(|d| serde_json::to_string(d).unwrap());
    assert_eq!(
        c3.state().db.get(&name).map(|d| d.hits),
        Some(hits),
        "{name}\n寫出前 {before}\n讀回 {after:?}"
    );
    assert!(
        c3.state().db.get(&name).and_then(|d| d.v4.as_ref()).is_some_and(|v| v.is("fail")),
        "{name}\n寫出前 {before}\n讀回 {after:?}"
    );

    // (v) 壞掉 / 不見的分片：其他照常載入、不會不能啟動，壞掉的那片之後重寫
    let shards = ch.shards;
    let bad = crate::db::shard_of(&name, shards);
    let bad_path = crate::statefile::zst_path(&dir.join(crate::db::shard_file(shards, bad)));
    std::fs::write(&bad_path, b"not zstd at all").unwrap();
    let other = (bad + 1) % shards;
    std::fs::remove_file(crate::statefile::zst_path(&dir.join(crate::db::shard_file(shards, other)))).unwrap();
    let c4 = Cdn::load(&full_cfg(), paths.clone(), MockNet::new());
    let left = c4.state().db.domains.len();
    assert!(left > n / 2 && left < n, "其他分片照常載入：{left} / {n}");
    assert!(c4.state().db.get(&name).is_none());
    let (_, ch) = c4.snapshots_sharded(false);
    let mut want = vec![(bad, true), (other, true)];
    want.sort();
    assert_eq!(ch.changed, want, "只重寫壞掉的分片");
    assert!(ch.manifest.is_none());

    // 分片清單壞掉：用目錄裡的分片救回來，並重寫清單
    std::fs::write(dir.join(crate::db::MANIFEST), b"{oops").unwrap();
    let c5 = Cdn::load(&full_cfg(), paths, MockNet::new());
    assert_eq!(c5.state().db.domains.len(), left);
    assert!(c5.snapshots_sharded(false).1.manifest.is_some());
}

#[test]
fn shard_count_change_rewrites_all() {
    // 分片數改變（例如換了等級）：新的一組全部寫好、清單更新後才刪掉舊的一組
    let paths = paths_no_seed("reshard");
    let dir = paths.state_dir.clone();
    let mut cfg = full_cfg();
    cfg["cdn"]["maxEntries"] = json!(20000);
    let c = Cdn::load(&cfg, paths.clone(), MockNet::new());
    c.with_state(|st| {
        for i in 0..300 {
            st.db.touch(&format!("s{i}.example.com"), "cloudflare", "ip", &[], &[], None);
        }
    });
    let (_, ch) = c.snapshots_sharded(false);
    let old_n = ch.shards;
    write_changes(&c, &dir, &ch);
    cfg["cdn"]["maxEntries"] = json!(200000);
    let c2 = Cdn::load(&cfg, paths.clone(), MockNet::new());
    assert_eq!(c2.state().db.domains.len(), 300);
    let (_, ch) = c2.snapshots_sharded(false);
    assert!(ch.shards > old_n);
    assert_eq!(ch.changed.len(), ch.shards);
    let (_, retire) = ch.manifest.clone().unwrap();
    assert!(retire.contains(&crate::db::shard_file(old_n, 0)));
    write_changes(&c2, &dir, &ch);
    assert!(!crate::statefile::exists(&dir.join(crate::db::shard_file(old_n, 0))));
    let c3 = Cdn::load(&cfg, paths, MockNet::new());
    assert_eq!(c3.state().db.domains.len(), 300);
}

#[test]
fn cold_entries_evicted_after_persist_and_lazily_reloaded() {
    // 記憶體控制（規格 09）：冷資料只移出記憶體，磁碟上保留；查到時讀回來的內容（含驗證結果）跟原本完全一樣；
    // 這片之後有變動要重寫時，移出的冷資料從舊檔接回去，磁碟上不會少
    let paths = paths_no_seed("cold");
    let dir = paths.state_dir.clone();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(repo().join("data/seed/cdn-domains.json"), dir.join(crate::db::FILE)).unwrap();
    let c = Cdn::load(&full_cfg(), paths.clone(), MockNet::new());
    let n = c.state().db.domains.len();
    let mut names: Vec<String> = c.state().db.domains.keys().map(|k| k.to_string()).collect();
    names.sort();
    // 只有一個是「熱的」（剛查過），其他都一週沒出現
    let hot = names[0].clone();
    let now = now_ms();
    c.with_state(|st| {
        for d in st.db.domains.values_mut() {
            d.last_seen = if *d.name == *hot { now } else { now - 7 * 24 * 3600 * 1000 };
        }
    });
    let original = {
        let st = c.state();
        st.db.domains.values().find(|d| d.v4.is_some() && *d.name != *hot).unwrap().clone()
    };
    let cold = original.name.to_string();
    // 搬家還沒寫進磁碟：一筆都不能移出
    assert_eq!(c.evict_cold(3_600_000, &|_| true).entries, 0, "整個資料庫還要重寫時不動");
    let (_, ch) = c.snapshots_sharded(false);
    let shards = ch.shards;
    assert_eq!(c.evict_cold(3_600_000, &|_| false).entries, 0, "快照寫入器還有待寫內容的分片不動");
    write_changes(&c, &dir, &ch);
    let shard_bytes = |i: usize| crate::statefile::read(&dir.join(crate::db::shard_file(shards, i))).unwrap();
    let before: Vec<Vec<u8>> = (0..shards).map(shard_bytes).collect();
    // 有一個分片之後又有變動（還沒寫）：那片不動
    let cold_shard = crate::db::shard_of(&cold, shards);
    let touched = names
        .iter()
        .find(|x| crate::db::shard_of(x, shards) != cold_shard && **x != hot)
        .unwrap()
        .clone();
    c.with_state(|st| st.db.set_verdict(&touched, 4, |v| v.verdict = Some(crate::util::intern("fail"))));
    let r = c.evict_cold(3_600_000, &|_| true);
    assert!(r.entries > n / 2, "冷資料移出記憶體：{} / {n}", r.entries);
    assert!(r.bytes > r.entries * 100, "估計釋出的記憶體：{}", r.bytes);
    assert_eq!(c.evicted_count(), r.entries);
    {
        let st = c.state();
        assert!(st.db.get(&hot).is_some(), "熱的網域不動");
        assert!(st.db.get(&touched).is_some(), "剛改過（還沒寫）的分片不動");
        assert!(st.db.get(&cold).is_none());
    }
    // 磁碟上的分片完全沒變
    for (i, b) in before.iter().enumerate() {
        assert_eq!(&shard_bytes(i), b, "分片 {i}");
    }
    // 查到移出的網域：從磁碟讀回來，內容一樣（驗證結果不變）
    assert!(c.ensure_loaded(&cold));
    assert_eq!(c.state().db.get(&cold).unwrap(), &original);
    assert_eq!(c.evicted_count(), r.entries - 1);
    assert!(!c.ensure_loaded(&cold), "已經在記憶體裡");
    assert!(!c.ensure_loaded("never-seen.example.com"), "不在資料庫的名稱不讀磁碟");
    // 有冷資料的分片沒有變動、重寫：一模一樣（冷資料一筆不少）
    let touched_shard = crate::db::shard_of(&touched, shards);
    let s = (0..shards)
        .find(|i| *i != touched_shard && *i != cold_shard && c.state().db.evicted_hashes(shards, *i).len() > 2)
        .unwrap();
    let mut raw = Vec::new();
    c.write_shard(shards, s, &mut raw).unwrap();
    assert_eq!(raw, before[s], "重寫出來跟磁碟上一樣");
    // 新增一筆：冷資料都在，多一筆
    let fresh = (0..)
        .map(|k| format!("fresh{k}.example.com"))
        .find(|x| crate::db::shard_of(x, shards) == s)
        .unwrap();
    c.with_state(|st| {
        st.db.touch(&fresh, "cloudflare", "ip", &[], &[], None);
    });
    let mut raw = Vec::new();
    c.write_shard(shards, s, &mut raw).unwrap();
    let count = |b: &[u8]| {
        let mut k = 0;
        crate::db::scan_shard(b, &mut |_| k += 1).unwrap();
        k
    };
    assert_eq!(count(&raw), count(&before[s]) + 1, "新增一筆、冷資料都在");
    // 記憶體恢復：全部讀回來
    let back = c.restore_cold();
    assert_eq!(back.entries, r.entries - 1);
    assert_eq!(c.evicted_count(), 0);
    assert_eq!(c.state().db.domains.len(), n + 1);
}

// ---- 磁碟預算（3.5.0 C5，規格 05 第 5.7 節）----

/// 種子資料（約 3,960 筆）不帶預算寫成分片，回傳（路徑，分片數，筆數）
fn seeded_shards(tag: &str) -> (Paths, usize, usize) {
    let paths = paths_no_seed(tag);
    let dir = paths.state_dir.clone();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(repo().join("data/seed/cdn-domains.json"), dir.join(crate::db::FILE)).unwrap();
    let c = Cdn::load(&full_cfg(), paths.clone(), MockNet::new());
    assert_eq!(c.budget_limit(), None, "預設（auto 還沒換算、或大磁碟）沒有預算");
    let (_, ch) = c.snapshots_sharded(false);
    write_changes(&c, &dir, &ch);
    let n = c.state().db.domains.len();
    assert!(n > 3900, "{n}");
    (paths, ch.shards, n)
}

fn budget_cfg(kb: u64) -> Value {
    let mut cfg = full_cfg();
    cfg["cdn"]["dbDiskBudgetKB"] = json!(kb);
    cfg
}

fn shard_dir_size(dir: &std::path::Path) -> u64 {
    std::fs::read_dir(dir.join(crate::db::SHARD_DIR))
        .unwrap()
        .flatten()
        .map(|e| e.metadata().unwrap().len())
        .sum()
}

#[test]
fn budget_zero_disables() {
    // 沒有預算（`cdn.dbDiskBudgetKB` 是 0、或 "auto" 在大磁碟上換算成 0）：一筆都不淘汰、不標任何變動，只量大小
    let (paths, _, n0) = seeded_shards("budget-off");
    for cfg in [budget_cfg(0), full_cfg()] {
        let c = Cdn::load(&cfg, paths.clone(), MockNet::new());
        let n = c.state().db.domains.len();
        assert_eq!(n, n0);
        assert_eq!(c.budget_round(), crate::cdn::BudgetRound::default());
        assert_eq!(c.state().db.domains.len(), n);
        assert!(!c.state().db.changed());
        let st = c.status_lite();
        assert!(st["dbBudgetKB"].is_null() && st["dbBudgetEntries"].is_null(), "{st}");
        assert_eq!(st["dbEntries"], json!(n));
        assert!(st["dbDiskKB"].as_u64().unwrap() > 300, "實際大小照樣量：{st}");
        assert_eq!(st["prunedForBudget"], json!(0));
    }
}

#[test]
fn budget_round_sweeps_in_rounds_and_survives_restart() {
    // 升級後第一次套用預算、要淘汰快一半：一輪一輪來（每輪主動重寫最多 16 片），每個分片只重寫一次；
    // 寫出去之後磁碟上真的變小，重新啟動讀回來的就是淘汰後的內容，不會再淘汰一次
    let (paths, shards, n0) = seeded_shards("budget-sweep");
    let dir = paths.state_dir.clone();
    assert_eq!(shards, 256);
    let before_disk = shard_dir_size(&dir);
    assert!(before_disk > 512 * 1024, "{before_disk}");
    let c = Cdn::load(&budget_cfg(512), paths.clone(), MockNet::new());
    // 載入時就量了磁碟，筆數上限依實測校正：不低於模型、不超過模型的 1.5 倍
    let model = crate::db::BUDGET_MIN_ENTRIES;
    let limit = c.budget_limit().unwrap();
    assert!((model..=model * 3 / 2).contains(&limit), "{limit}");
    assert!(!c.state().db.changed(), "載入時不淘汰");
    let mut rewritten = vec![0u32; shards];
    let mut rounds = 0;
    let mut dropped = 0;
    loop {
        let r = c.budget_round();
        if r.shards == 0 {
            break;
        }
        rounds += 1;
        assert!(r.forced <= 16 && r.shards <= 32, "每輪上限：{r:?}");
        dropped += r.dropped;
        let (_, ch) = c.snapshots_sharded(false);
        assert!(ch.manifest.is_none(), "不動分片清單");
        assert!(ch.changed.len() <= 32, "一輪最多重寫 32 片：{}", ch.changed.len());
        for (i, _) in &ch.changed {
            rewritten[*i] += 1;
        }
        write_changes(&c, &dir, &ch);
        assert!(rounds <= 64, "要會結束");
    }
    assert!(rounds >= 8, "不是一次做完：{rounds} 輪");
    assert!(rewritten.iter().all(|n| *n <= 1), "每個分片最多重寫一次");
    let left = c.state().db.domains.len();
    assert_eq!(left, n0 - dropped);
    let after_disk = shard_dir_size(&dir);
    // 每輪重新量磁碟、重新校正：最後的上限也在模型～1.5 倍之間，留下的在上限以內、不會刪過頭
    let limit = c.budget_limit().unwrap();
    assert!((model..=model * 3 / 2).contains(&limit), "{limit}");
    assert!(left <= limit && left >= limit * 8 / 10, "{left} / {limit}");
    assert!(after_disk < before_disk * 9 / 10, "磁碟上變小：{before_disk} → {after_disk}");
    assert!(after_disk <= 512 * 1024 * 21 / 20, "淘汰完在預算附近：{after_disk}");
    let st = c.status_lite();
    assert_eq!(st["dbBudgetKB"], json!(512));
    assert_eq!(st["dbBudgetEntries"], json!(limit));
    assert_eq!(st["prunedForBudget"], json!(dropped));
    assert_eq!(st["dbEntries"], json!(left));
    // 重新啟動：內容一樣，在預算以內，不再淘汰
    let c2 = Cdn::load(&budget_cfg(512), paths, MockNet::new());
    assert_eq!(c2.state().db.domains.len(), left);
    assert_eq!(c2.budget_round(), crate::cdn::BudgetRound::default());
    assert!(!c2.state().db.changed());
}

#[test]
fn prune_counts_evicted_cold_entries() {
    // 記憶體控制把冷資料移出記憶體之後，它們還在磁碟上：預算要算它們，淘汰時先讀回來比新舊，
    // 重寫分片時被淘汰的冷資料不會又從舊檔接回去
    let (paths, shards, n0) = seeded_shards("budget-cold");
    let dir = paths.state_dir.clone();
    let c = Cdn::load(&budget_cfg(512), paths.clone(), MockNet::new());
    let limit = c.budget_limit().unwrap();
    let r = c.evict_cold(3_600_000, &|_| true);
    assert!(r.entries > 3000, "{}", r.entries);
    assert!(c.state().db.domains.len() < limit, "記憶體裡的不到預算");
    assert_eq!(c.state().db.total_entries(), n0, "總筆數要算移出去的");
    let mut rounds = 0;
    loop {
        let r = c.budget_round();
        if r.shards == 0 {
            break;
        }
        rounds += 1;
        let (_, ch) = c.snapshots_sharded(false);
        write_changes(&c, &dir, &ch);
        assert!(rounds <= 64);
    }
    assert!(rounds >= 8);
    let total = c.state().db.total_entries();
    // 每輪重新量磁碟校正上限：跟最後的上限比，而且不低於模型（筆數下限 2,000）的 80%
    let last = c.budget_limit().unwrap();
    assert!(last <= limit && last >= crate::db::BUDGET_MIN_ENTRIES, "{last} / {limit}");
    assert!(total <= last && total >= last * 8 / 10, "{total} / {last}");
    // 磁碟上的筆數跟算的一樣（沒有被接回去）
    let mut on_disk = 0;
    for i in 0..shards {
        let b = crate::statefile::read(&dir.join(crate::db::shard_file(shards, i))).unwrap();
        crate::db::scan_shard(&b, &mut |_| on_disk += 1).unwrap();
    }
    assert_eq!(on_disk, total);
    let c2 = Cdn::load(&budget_cfg(512), paths, MockNet::new());
    assert_eq!(c2.state().db.domains.len(), total);
}

#[test]
fn budget_keeps_what_is_in_use() {
    // 淘汰的是最久沒人查的：今天查過的網域、手動設定策略的網域一筆都不會少
    let (paths, _, _) = seeded_shards("budget-keep");
    let dir = paths.state_dir.clone();
    let c = Cdn::load(&budget_cfg(512), paths, MockNet::new());
    let mut names: Vec<String> = c.state().db.domains.keys().map(|k| k.to_string()).collect();
    names.sort();
    let now = now_ms();
    // 每片的額度只有 7 筆（測試用的最小預算）：正在用的取少一點，不會有哪一片光是正在用的就超過額度
    let in_use: Vec<String> = names.iter().step_by(13).take(300).cloned().collect();
    let manual = names[1].clone();
    c.with_state(|st| {
        for d in st.db.domains.values_mut() {
            d.last_seen = now - 20 * 24 * 3600 * 1000;
        }
        for n in &in_use {
            st.db.get_mut(n).unwrap().last_seen = now - 3_600_000;
        }
        st.db.set_policy(&manual, crate::db::Policy::Always);
        st.db.take_marks(false);
    });
    for _ in 0..64 {
        if c.budget_round().shards == 0 {
            break;
        }
        let (_, ch) = c.snapshots_sharded(false);
        write_changes(&c, &dir, &ch);
    }
    let limit = c.budget_limit().unwrap();
    let st = c.state();
    assert!(st.db.domains.len() <= limit);
    assert!(st.db.get(&manual).is_some());
    let kept = in_use.iter().filter(|n| st.db.get(n).is_some()).count();
    assert_eq!(kept, in_use.len(), "今天查過的都在");
}

#[test]
fn budget_calibrates_from_disk() {
    use crate::cdn::calibrated_limit;
    // 3.5.0 D3 實測：預算 2303 KB、256 片，模型換算約 16,613 筆；實際 23,158 筆在磁碟上只佔 2,218 KB
    let budget = 2303 * 1024;
    let model = crate::db::budget_entries(Some(budget), 256).unwrap();
    assert_eq!(model, 16_613);
    let n = calibrated_limit(model, 256, 23_158, 2218 * 1024, budget);
    assert!((23_158..=25_000).contains(&n), "放得下的不淘汰：{n}");
    // 只往上調：實測每筆比模型大時照模型
    assert_eq!(calibrated_limit(model, 256, 10_000, 2400 * 1024, budget), model);
    // 最多到模型的 1.5 倍（升級後第一次：56,222 筆、3,465 KB，壓縮比較好）
    assert_eq!(calibrated_limit(model, 256, 56_222, 3465 * 1024, budget), model * 3 / 2);
    // 實測太少、沒有實測：照模型
    assert_eq!(calibrated_limit(model, 256, 1_500, 2218 * 1024, budget), model);
    assert_eq!(calibrated_limit(model, 256, 23_158, 0, budget), model);
    assert_eq!(calibrated_limit(model, 256, 23_158, 200 * 1024, budget), model);
}

#[test]
fn budget_disk_measured_at_load() {
    // 3.5.0 D3：重新啟動後到第一輪預算之前 dbDiskKB 是 null。有預算時載入就量
    let (paths, _, _) = seeded_shards("budget-load-disk");
    let disk = shard_dir_size(&paths.state_dir);
    let c = Cdn::load(&budget_cfg(4096), paths, MockNet::new());
    let st = c.status_lite();
    assert_eq!(st["dbDiskKB"], json!(disk.div_ceil(1024)), "{st}");
}
