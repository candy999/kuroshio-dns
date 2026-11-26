//! 3.5.1：長期資料檢查（規格 11 的 A10）。一台正式環境 14 天的每日評測資料找到的問題：
//! 可疑判斷太容易定罪、舊規則的可疑紀錄、永久黑名單只會變長、judge.log 截斷、選出的上游天天換……
//!
//! 本機假 DNS 伺服器：每個 DoH 候選轉到自己的本機 UDP 伺服器；答案預設是「多數業者」（93.1.網域編號.候選編號），
//! 測試可以替某一台、某一天、某一個網域換答案。日期用注入的時鐘，一天跑一次評測。

use kuroshio_jobs::benchmark::learn::{day_of, Learn};
use kuroshio_jobs::benchmark::probe::{AsnSource, NetProber, Prober, SiteCheck, StaticAsn};
use kuroshio_jobs::benchmark::rules::AsnInfo;
use kuroshio_jobs::scheduler::BoxFuture;
use kuroshio_jobs::time::{days_from_civil, ManualClock, DAY_MS, HOUR_MS, TPE_OFFSET_MS};
use kuroshio_jobs::{BenchPaths, Benchmark, Clock, JobCtx};
use kuroshio_net::upstream::{Kind, Upstream};
use kuroshio_proto::message::Record;
use kuroshio_proto::Message;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;

/// 評測網域（多數業者 93.1.x 的憑證有效）
pub const WEB: [&str; 3] = ["www.example.com", "cdn.example.net", "img.example.com"];

/// 替某一台換答案：（候選編號, 網域）→ 位址
type Overrides = Arc<Mutex<HashMap<(u8, String), Ipv4Addr>>>;

async fn mock(n: u8, ov: Overrides) -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((len, peer)) = sock.recv_from(&mut buf).await else { break };
            let Ok(q) = Message::parse(&buf[..len]) else { continue };
            let name = q.question().map(|x| x.name.clone()).unwrap_or_default();
            let mut r = Message::response_to(&q, 0);
            if name == "one.one.one.one" {
                r.answers.push(Record::a(&name, 60, Ipv4Addr::new(1, 1, 1, 1)));
                r.answers.push(Record::a(&name, 60, Ipv4Addr::new(1, 0, 0, 1)));
            } else if let Some(d) = WEB.iter().position(|w| *w == name) {
                let ip = ov
                    .lock()
                    .unwrap()
                    .get(&(n, name.clone()))
                    .copied()
                    .unwrap_or(Ipv4Addr::new(93, 1, d as u8, n));
                r.answers.push(Record::a(&name, 60, ip));
            } else {
                r.rcode = 3;
            }
            let _ = sock.send_to(&r.encode(), peer).await;
        }
    });
    addr
}

/// DoH 依主機名稱轉到本機假伺服器。`limited` 的主機回 HTTP 429；網站驗證：93.1.x 有效、96.4.x 憑證不符、其他連不上
pub struct Mapped {
    pub map: HashMap<String, SocketAddr>,
    pub limited: Mutex<HashSet<String>>,
    pub asked: Mutex<HashMap<String, usize>>,
}

impl Prober for Mapped {
    fn supports(&self, up: &Upstream) -> bool {
        matches!(up.kind, Kind::Doh | Kind::Doh3 | Kind::Dot) && self.map.contains_key(&up.host)
    }
    fn exchange(&self, up: Upstream, q: Vec<u8>, t: Duration) -> BoxFuture<anyhow::Result<Vec<u8>>> {
        *self.asked.lock().unwrap().entry(up.id.clone()).or_default() += 1;
        if self.limited.lock().unwrap().contains(&up.host) {
            let k = if up.kind == Kind::Doh3 { "DoH3" } else { "DoH" };
            return Box::pin(async move { Err(anyhow::anyhow!("{k} HTTP 429 Too Many Requests")) });
        }
        let to = Upstream::parse(&format!("udp://{}", self.map[&up.host])).unwrap();
        Box::pin(async move { NetProber.exchange(to, q, t).await })
    }
    fn resolve_v4(&self, _host: String) -> BoxFuture<Option<Ipv4Addr>> {
        Box::pin(async { None })
    }
    fn verify_site(&self, ip: std::net::IpAddr, _d: String, _t: Duration) -> BoxFuture<(SiteCheck, String)> {
        let s = ip.to_string();
        Box::pin(async move {
            if s.starts_with("93.1.") {
                (SiteCheck::Valid, "OK".to_string())
            } else if s.starts_with("96.4.") {
                (SiteCheck::Invalid, "ERR_TLS_CERT_ALTNAME_INVALID".to_string())
            } else {
                (SiteCheck::Unverified, "TIMEOUT".to_string())
            }
        })
    }
}

fn asn() -> Arc<dyn AsnSource> {
    let mut m = HashMap::new();
    let mut add = |k: &str, isp: &str, as_: &str| {
        m.insert(k.to_string(), AsnInfo::from_ip_api(isp, isp, as_, "JP"));
    };
    add("93.1", "Alpha Web", "AS64496 Alpha Web");
    add("96.4", "Evil Corp", "AS64497 Evil Corp");
    add("98.6", "Quiet Hosting", "AS64498 Quiet Hosting");
    Arc::new(StaticAsn(m))
}

pub struct Env {
    pub root: PathBuf,
    pub p: BenchPaths,
    pub prober: Arc<Mapped>,
    pub ov: Overrides,
    pub clock: Arc<ManualClock>,
    /// 名單裡第 n 台的 id
    pub ids: Vec<String>,
}

/// `n` 台 DoH（`https://h<編號>.example.com/dns-query`，經營者 `Op<編號>`，A 級）。`extra`：名單後面再加的行
pub async fn setup(name: &str, n: u8, extra: &str) -> Env {
    let ov: Overrides = Arc::new(Mutex::new(HashMap::new()));
    let mut map = HashMap::new();
    let mut ids = Vec::new();
    let mut lines = Vec::new();
    for i in 1..=n {
        let host = format!("h{i}.example.com");
        map.insert(host.clone(), mock(i, ov.clone()).await);
        let id = format!("https://{host}/dns-query");
        lines.push(format!("{id}  # tier=A op=Op{i}"));
        ids.push(id);
    }
    let root = std::env::temp_dir().join(format!("kuroshio-bench-long-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("benchmark")).unwrap();
    std::fs::create_dir_all(root.join("state")).unwrap();
    let p = BenchPaths {
        list_dir: root.join("benchmark"),
        out_root: Some(root.join("state/benchmark")),
        upstreams_file: root.join("state/upstreams.json"),
        community_candidates: Some(root.join("state/community/upstream-candidates.json")),
        blacklist_file: Some(root.join("state/blacklist.txt")),
        default_list_dir: None,
        learn_file: Some(root.join("state/benchmark-learn.json")),
    };
    std::fs::write(p.list_dir.join("dohlist.txt"), format!("{}\n{extra}", lines.join("\n"))).unwrap();
    std::fs::write(p.list_dir.join("web.txt"), WEB.join("\n")).unwrap();
    let prober = Arc::new(Mapped {
        map,
        limited: Mutex::new(HashSet::new()),
        asked: Mutex::new(HashMap::new()),
    });
    let clock = Arc::new(ManualClock::new(
        days_from_civil(2026, 11, 20) as u64 * DAY_MS + 12 * HOUR_MS - TPE_OFFSET_MS,
    ));
    Env {
        root,
        p,
        prober,
        ov,
        clock,
        ids,
    }
}

pub fn cfg() -> Value {
    kuroshio_config::with_overrides(&json!({
        "upstream": { "autoTypes": ["doh"], "autoMax": 3 },
        "benchmark": { "timeoutMs": 300, "concurrency": 8, "paceMs": 0, "maxTimeouts": 1, "minAuto": 1, "tiers": "ab" }
    }))
}

impl Env {
    /// 替第 n 台（1 起算）的某個網域換答案
    pub fn answer(&self, n: u8, domain: &str, ip: &str) {
        self.ov.lock().unwrap().insert((n, domain.to_string()), ip.parse().unwrap());
    }
    pub fn reset_answers(&self) {
        self.ov.lock().unwrap().clear();
    }
    pub fn id(&self, n: u8) -> &str {
        &self.ids[n as usize - 1]
    }
    /// 跑一天的評測：回傳（upstreams.json, judge.log）
    pub async fn run(&self, c: &Value) -> (Value, String) {
        let ctx = JobCtx::new("dns-benchmark", "測試", Arc::new(c.clone())).with_clock(self.clock.clone());
        let b = Benchmark::with(self.p.clone(), self.prober.clone(), asn());
        let state = b.run(&ctx).await.unwrap();
        let day = state["date"].as_str().unwrap().to_string();
        let log = std::fs::read_to_string(self.p.out_root.clone().unwrap().join(day).join("judge.log")).unwrap();
        (state, log)
    }
    pub fn next_day(&self) {
        self.clock.advance(DAY_MS);
    }
    pub fn today(&self) -> u32 {
        day_of(self.clock.now_ms())
    }
    pub fn blacklist(&self) -> String {
        std::fs::read_to_string(self.root.join("state/blacklist.txt")).unwrap_or_default()
    }
    pub fn suspects(&self) -> Value {
        std::fs::read(self.root.join("state/blacklist-suspects.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(json!({}))
    }
    pub fn learn(&self) -> Learn {
        Learn::load(self.p.learn_file.as_ref().unwrap())
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn eliminated(state: &Value) -> u64 {
    state["counts"]["eliminated"].as_u64().unwrap()
}

/// A10.2：同一題天天「網站無法驗證」不累積（不定罪、不算評測歷史的可疑天數）；兩個以上網域、3 天才定罪；
/// 別的經營者的加密 DNS 也回了同一個位址時，今天不用但不記可疑
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unverified_needs_two_domains_and_unshared_answer() {
    // 多數業者 12 台（第 13～16 台各有安排）：規則外的群組才不會因為分數超過第一名的 20% 被當成有效
    let e = setup("unverified", 16, "").await;
    let (same, multi, sh1, sh2) = (13u8, 14u8, 15u8, 16u8);
    for day in 0..3 {
        e.reset_answers();
        // same：天天只有同一題連不上
        e.answer(same, WEB[0], "98.6.0.13");
        // multi：每天換一題連不上（第 3 天回到第一題）
        e.answer(multi, WEB[[0, 1, 0][day]], "98.6.0.14");
        // sh1、sh2：兩家不同經營者回同一個連不上的位址
        e.answer(sh1, WEB[2], "98.6.0.99");
        e.answer(sh2, WEB[2], "98.6.0.99");
        let (state, log) = e.run(&cfg()).await;
        assert_eq!(eliminated(&state), 8, "四台（https 與 h3）今天都不用：{log}");
        assert!(
            log.contains(&format!(
                "{} -> Quiet_Hosting__AS64498_Quiet_Hosting：{} 網站無法驗證（TIMEOUT），但別的經營者的 DNS 也回了同樣的位址，不記可疑",
                e.id(sh1),
                WEB[2]
            )),
            "{log}"
        );
        e.next_day();
    }
    let bl = e.blacklist();
    assert!(bl.contains(&format!("{}  # ", e.id(multi))), "3 天、2 個網域：定罪 {bl}");
    assert!(bl.contains("（30 天內 3 天、2 個網域網站無法驗證）"), "{bl}");
    assert!(!bl.contains(e.id(same)), "同一題天天連不上不定罪：{bl}");
    assert!(!bl.contains(e.id(sh1)) && !bl.contains(e.id(sh2)), "{bl}");
    let s = e.suspects();
    assert_eq!(s[e.id(same)].as_array().unwrap().len(), 3, "照樣記下來：{s}");
    assert!(s.get(e.id(sh1)).is_none(), "別的經營者也回了同樣的位址：不記 {s}");
    // 評測歷史：同一題的不算可疑天數（不會因此降級）；兩個網域以上的從第 2 個網域那天起算
    let l = e.learn();
    assert_eq!(l.hist[e.id(same)].suspect(), 0, "{:?}", l.hist[e.id(same)]);
    assert_eq!(l.hist[e.id(sh1)].suspect(), 0);
    assert_eq!(l.hist[e.id(multi)].suspect(), 2, "{:?}", l.hist[e.id(multi)]);
}

/// A10.4：永久黑名單裡「網站無法驗證」的 30～60 天後重測一次：通過就移除；沒通過照列入的標準判斷
/// （3.5.1 第二版之後：可疑紀錄夠格才留著、從今天重新算，不夠格就移出、照一般規則累積；重測時憑證不符的改成永久；
/// 資格賽或連線失敗算今天沒測到，留著、30～60 天後再試）；
/// 憑證不符的永久（不重測）；名單裡已經沒有的移除；檔頭換成新的說明
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unverified_blacklist_entries_are_retested() {
    // 多數業者要夠多：規則外的群組才不會因為分數超過第一名的 20% 被當成有效
    let e = setup("retest", 20, "").await;
    let q = "Quiet_Hosting__AS64498_Quiet_Hosting";
    let lines = [
        "# 永久黑名單：每日評測判定「汙染」（解析到錯誤業者）的 DNS，之後不再測試".to_string(),
        "# 要恢復某台就刪掉那一行".to_string(),
        format!("{}  # 2026-11-15 汙染：{} → {q}（連續 3 天網站無法驗證）", e.id(13), WEB[0]),
        format!(
            "{}  # 2026-09-15 汙染：{} → {q}（30 天內 3 天、2 個網域網站無法驗證）",
            e.id(14),
            WEB[0]
        ),
        format!(
            "{}  # 2026-09-15 汙染：{} → Evil（憑證不符 ERR_TLS_CERT_ALTNAME_INVALID）",
            e.id(15),
            WEB[1]
        ),
        format!(
            "{}  # 2026-11-19 汙染：{} → {q}（30 天內 3 天、2 個網域網站無法驗證）",
            e.id(12),
            WEB[0]
        ),
        format!("{}  # 2026-11-15 汙染：{} → {q}（連續 3 天網站無法驗證）", e.id(11), WEB[0]),
        format!("{}  # 2026-11-15 汙染：{} → {q}（連續 3 天網站無法驗證）", e.id(10), WEB[0]),
        format!("{}  # 2026-11-15 汙染：{} → {q}（連續 3 天網站無法驗證）", e.id(9), WEB[0]),
        format!(
            "https://gone.example.net/dns-query  # 2026-09-15 汙染：{} → X（30 天內 3 天、2 個網域網站無法驗證）",
            WEB[0]
        ),
    ];
    std::fs::write(e.root.join("state/blacklist.txt"), lines.join("\n") + "\n").unwrap();
    // 第 11 台：前兩天另一個網域已經有可疑紀錄（今天再一筆就是 30 天內 3 天、2 個網域）
    std::fs::write(
        e.root.join("state/blacklist-suspects.json"),
        json!({ e.id(11): [format!("2026-11-18|r2|{}", WEB[1]), format!("2026-11-19|r2|{}", WEB[1])] }).to_string(),
    )
    .unwrap();
    // 第 14 台重測時還是連不上（一天、一個網域）；第 11 台也連不上；第 10 台這次憑證不符
    e.answer(14, WEB[0], "98.6.0.14");
    e.answer(11, WEB[0], "98.6.0.11");
    e.answer(10, WEB[0], "96.4.0.10");
    // 第 9 台連資格賽都沒過（什麼都沒看到）：算今天沒測到，留著、30～60 天後再試
    e.prober.limited.lock().unwrap().insert("h9.example.com".into());
    let (state, log) = e.run(&cfg()).await;
    let out = e.blacklist();
    assert!(
        log.contains(
            "[永久黑名單] 重測「網站無法驗證」5 台：通過移除 1；沒通過的照列入的標準判斷：不夠格移出 1（今天的失敗照一般規則記進可疑紀錄）、夠格留著 1（從今天重新算 30～60 天）、憑證不符改成永久 1；今天沒測到 1（其中資格賽或連線失敗 1：留著，30～60 天後再試）；名單裡已經沒有的移除 1"
        ),
        "{log}"
    );
    assert!(out.starts_with("# 永久黑名單：每日評測判定竄改的 DNS"), "{out}");
    assert!(
        !out.contains(&format!("{}  #", e.id(13))),
        "3.5.0 以前的規則列入的：重測通過就移除 {out}"
    );
    // 第 14 台：一天、一個網域，不到列入的標準（30 天內 3 天、2 個網域）→ 移出，今天這筆照一般規則記下
    assert!(!out.contains(&format!("{}  #", e.id(14))), "不夠格：移出 {out}");
    assert_eq!(
        e.suspects()[e.id(14)],
        json!([format!("2026-11-20|r2|{}", WEB[0])]),
        "今天的失敗照一般規則記進可疑紀錄"
    );
    assert!(
        log.contains(&format!(
            "{} -> {q}：{} 網站無法驗證（TIMEOUT；可疑 1 天、1 個網域）：重測沒通過，但不到列入的標準（30 天內 3 天、2 個網域），移出永久黑名單、照一般規則累積",
            e.id(14),
            WEB[0]
        )),
        "{log}"
    );
    // 第 11 台：夠格 → 留著、從今天重新算
    assert!(
        out.contains(&format!("{}  # 2026-11-20 重測：網站無法驗證（可疑 {}", e.id(11), WEB[0])),
        "夠格：從今天重新算 {out}"
    );
    assert!(out.contains("第一次列入 2026-11-15）"), "{out}");
    assert!(
        log.contains(&format!(
            "{} -> {q}：{} 網站無法驗證（TIMEOUT；30 天內 3 天、2 個網域）：重測沒通過，留在永久黑名單",
            e.id(11),
            WEB[0]
        )),
        "{log}"
    );
    // 第 10 台：重測時憑證不符 → 留著、改成永久；文字照實際狀態寫（不是「再發生一天就列入」）
    assert!(out.contains(&format!("{}  # 2026-11-20 重測：憑證不符（", e.id(10))), "{out}");
    assert!(
        log.contains(&format!(
            "[淘汰] {} -> 汙染 Evil_Corp__AS64497_Evil_Corp：憑證不符 ERR_TLS_CERT_ALTNAME_INVALID（重測：已經在永久黑名單裡，留著、改成永久的那一種）",
            e.id(10)
        )),
        "{log}"
    );
    assert!(
        !log.contains(&format!(
            "{} -> 汙染 Evil_Corp__AS64497_Evil_Corp：憑證不符 ERR_TLS_CERT_ALTNAME_INVALID（再發生一天",
            e.id(10)
        )),
        "{log}"
    );
    // 第 9 台：留著，日期改成今天（30～60 天後再試）
    assert!(
        out.contains(&format!("{}  # 2026-11-20 重測：連不上（資格賽失敗 (", e.id(9))),
        "{out}"
    );
    assert!(out.contains("網站無法驗證的判斷下次再試（第一次列入 2026-11-15）"), "{out}");
    // 重測的不再附加一行（整理時改寫）：每台只有一行
    for n in [9u8, 10, 11] {
        assert_eq!(out.matches(&format!("{}  #", e.id(n))).count(), 1, "{out}");
    }
    assert!(out.contains(&format!("{}  # 2026-09-15", e.id(15))), "憑證不符的永久：{out}");
    assert!(out.contains(&format!("{}  # 2026-11-19", e.id(12))), "還沒到重測的不動：{out}");
    assert!(!out.contains("gone.example.net"), "名單裡已經沒有的移除：{out}");
    assert!(log.contains("永久黑名單略過 2 台：學到的 2）"), "{log}");
    let asked = e.prober.asked.lock().unwrap().clone();
    assert!(asked.contains_key(e.id(13)) && asked.contains_key(e.id(14)));
    assert!(
        !asked.contains_key(e.id(15)) && !asked.contains_key(e.id(12)),
        "還在黑名單的不測：{asked:?}"
    );
    assert_eq!(state["counts"]["eliminated"], 8, "第 9、10、11、14 台的 https 與 h3：{state}");
    // 隔天：剛重測過、留著的不會再測；移除的第 13 台、移出的第 14 台照常每天測
    e.next_day();
    e.reset_answers();
    e.prober.limited.lock().unwrap().clear();
    e.prober.asked.lock().unwrap().clear();
    let (_, log) = e.run(&cfg()).await;
    assert!(!log.contains("[永久黑名單] 重測"), "連不上的也不會天天排：{log}");
    let asked = e.prober.asked.lock().unwrap().clone();
    assert!(
        !asked.contains_key(e.id(11)) && !asked.contains_key(e.id(10)) && !asked.contains_key(e.id(9)),
        "{asked:?}"
    );
    assert!(asked.contains_key(e.id(13)) && asked.contains_key(e.id(14)), "{asked:?}");
}

/// A10.5：報表目錄裡的 judge.log 有選出結果（以前在「今日選出的上游」之前就寫檔了）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn judge_log_has_selection() {
    let e = setup("journal", 4, "").await;
    let (_, log) = e.run(&cfg()).await;
    assert!(log.contains("=== 今日選出的上游 ==="), "{log}");
    // 3.5.1：以前是「總涵蓋率 4.2%（981/23161）」，看起來像「只查得到 4%」。改成寫明在算什麼，另外一行寫網域查不查得到
    assert!(!log.contains("總涵蓋率"), "{log}");
    assert!(
        log.contains("  位址覆蓋 ") && log.contains("個不同的（網域, 位址），倖存的 8 台合起來是 "),
        "{log}"
    );
    assert!(log.contains("這個比例本來就低，只用來挑新增位址多的上游"), "{log}");
    // 選出幾台看本機的延遲（這個測試不比），網域數一定寫出來
    assert!(log.contains("  網域覆蓋：計分的 3 個網域，選出的上游答得出 "), "{log}");
    assert!(log.lines().last().unwrap().starts_with("[dns-benchmark] 結束 "), "{log}");
    // 3.5.1 第二版之後：各大階段結束時寫花了多久，最後一行合計（測試者比不出「收集」變慢在哪裡）
    for stage in ["資格賽 ", "收集 ", "ASN 合併查 ", "逐網域判斷 ", "選出 "] {
        assert!(log.contains(&format!("[花費時間] {stage}")), "{stage}：{log}");
    }
    assert!(
        log.contains("個網域 × 8 個候選、同時測 8 個；照查詢間隔 0 ms 算至少約 0.0 秒；最慢的候選："),
        "{log}"
    );
    assert!(log.contains("（3 個網域；其中查業者 "), "{log}");
    let total = log.lines().rev().nth(1).unwrap();
    assert!(
        total.starts_with("[花費時間] 資格賽 ") && total.contains("、收集 ") && total.contains("；整次評測 "),
        "{log}"
    );
}

/// 3.5.1 第二版之後：「永久黑名單略過」寫台數（同一台的不同寫法算一台）與來源（學到的、程式附帶的），
/// 才對得上 `state/blacklist.txt` 的筆數（以前寫候選數：Windows 第二階段 9 筆的名單寫「略過 10」）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blacklist_skip_counts_servers_not_spellings() {
    let e = setup("blskip", 6, "").await;
    std::fs::write(e.p.list_dir.join("dotlist.txt"), "tls://h3.example.com\ntls://h3.example.com:853\n").unwrap();
    std::fs::write(
        e.root.join("state/blacklist.txt"),
        format!(
            "tls://h3.example.com:853  # 2026-10-01 汙染：{} → Evil（憑證不符 X）\n{}  # 2026-10-01 汙染：{} → Evil（憑證不符 X）\n",
            WEB[0],
            e.id(4),
            WEB[0]
        ),
    )
    .unwrap();
    // 程式附帶的唯讀名單
    std::fs::write(
        e.p.list_dir.join("blacklist.txt"),
        format!("{}  # 2026-10-01 汙染：{} → Evil（憑證不符 X）\n", e.id(2), WEB[0]),
    )
    .unwrap();
    let (_, log) = e.run(&cfg()).await;
    assert!(
        log.contains("永久黑名單略過 3 台：學到的 2、程式附帶的 1，同一台的不同寫法共 4 個候選）"),
        "{log}"
    );
    let asked = e.prober.asked.lock().unwrap().clone();
    assert!(!asked.keys().any(|k| k.starts_with("tls://h3.")), "{asked:?}");
}

/// 3.5.1：ASN 在逐網域判斷之前合併查：全部網域裡快取沒有的 /24 一起查、每個 /24 只問一次
/// （以前每個網域各查一批，新的 /24 只有幾個也要等 ip-api 的 4.2 秒間隔：D3 換成 /24 鍵那天逐網域判斷多 7.4 分鐘）。
/// 快取裡有的隔天不再問
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn asn_lookups_merged_before_judging() {
    struct Counting {
        inner: Arc<dyn AsnSource>,
        calls: Mutex<Vec<Vec<Ipv4Addr>>>,
    }
    impl AsnSource for Counting {
        fn lookup(&self, ips: Vec<Ipv4Addr>) -> BoxFuture<Vec<(Ipv4Addr, AsnInfo)>> {
            self.calls.lock().unwrap().push(ips.clone());
            self.inner.lookup(ips)
        }
    }
    let e = setup("asn-merge", 6, "").await;
    // 第 6 台在第 2 個網域回另一個 /24（同一家業者）：一樣在同一批裡
    e.answer(6, WEB[1], "93.1.9.6");
    let src = Arc::new(Counting {
        inner: asn(),
        calls: Mutex::new(Vec::new()),
    });
    let run = || async {
        let ctx = JobCtx::new("dns-benchmark", "測試", Arc::new(cfg())).with_clock(e.clock.clone());
        let b = Benchmark::with(e.p.clone(), e.prober.clone(), src.clone());
        let state = b.run(&ctx).await.unwrap();
        let day = state["date"].as_str().unwrap().to_string();
        std::fs::read_to_string(e.p.out_root.clone().unwrap().join(day).join("judge.log")).unwrap()
    };
    let log = run().await;
    let calls = src.calls.lock().unwrap().clone();
    // 3 個網域、6 台候選：93.1.0／93.1.1／93.1.2／93.1.9 四個 /24，一次問完（每個 /24 一個代表）
    assert_eq!(calls.len(), 1, "{calls:?}");
    let mut keys: Vec<[u8; 3]> = calls[0].iter().map(|ip| [ip.octets()[0], ip.octets()[1], ip.octets()[2]]).collect();
    keys.sort();
    assert_eq!(keys, [[93, 1, 0], [93, 1, 1], [93, 1, 2], [93, 1, 9]]);
    assert!(
        log.contains("[ASN] 逐網域判斷之前先合併查：4 個 /24（快取沒有或到期），每批 100 個、共 1 批"),
        "{log}"
    );
    assert!(log.contains("[ASN] 合併查完：查到 4、查不到 0"), "{log}");
    // 隔天：都在快取裡，不再問、不寫合併查那一行
    e.next_day();
    let log = run().await;
    assert_eq!(src.calls.lock().unwrap().len(), 1);
    assert!(!log.contains("[ASN] 逐網域判斷之前先合併查"), "{log}");
}

/// A10.9：每天回 HTTP 429 的（https 與 h3 都算）連續 3 天之後跳過 7～30 天；到期再測沒有 429 就恢復
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_429_is_skipped_like_h3skip() {
    let e = setup("rl429", 4, "").await;
    e.prober.limited.lock().unwrap().insert("h4.example.com".into());
    let h3 = "h3://h4.example.com/dns-query";
    for day in 1..=3u32 {
        let (_, log) = e.run(&cfg()).await;
        let l = e.learn();
        assert_eq!(l.rl429[e.id(4)].f, day, "{log}");
        assert_eq!(l.rl429[h3].f, day);
        if day == 3 {
            assert!(l.rl429[e.id(4)].until > e.today(), "第 3 天開始跳過");
            assert!(log.contains("限流（HTTP 429）：多記一天 0、開始跳過 2"), "{log}");
        }
        e.next_day();
    }
    // 跳過期間：不測（一筆查詢都沒有）
    e.prober.asked.lock().unwrap().clear();
    let (_, log) = e.run(&cfg()).await;
    assert!(log.contains("限流（HTTP 429）先不測 2 個"), "{log}");
    assert!(!e.prober.asked.lock().unwrap().contains_key(e.id(4)));
    // 到期：再測，沒有 429 就恢復（整筆刪掉）
    // https 與 h3 的跳過天數各自加了亂數：等兩個都到期
    let until = e.learn().rl429.values().map(|x| x.until).max().unwrap();
    assert!(until - e.today() <= 30);
    e.prober.limited.lock().unwrap().clear();
    e.clock.advance((until - e.today()) as u64 * DAY_MS);
    let (state, log) = e.run(&cfg()).await;
    assert!(e.prober.asked.lock().unwrap().contains_key(e.id(4)));
    assert!(e.learn().rl429.is_empty(), "{log}");
    assert_eq!(state["counts"]["eliminated"], 0);
}

/// A10.10：評測失敗也清舊報表（以前只有成功才清）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_run_still_cleans_old_reports() {
    let e = setup("cleanup", 2, "").await;
    let out = e.p.out_root.clone().unwrap();
    std::fs::create_dir_all(out.join("2026-11-06")).unwrap();
    std::fs::create_dir_all(out.join("2026-11-07")).unwrap();
    // 全部回 429：沒有任何 DNS 通過資格賽，評測失敗
    for i in 1..=2 {
        e.prober.limited.lock().unwrap().insert(format!("h{i}.example.com"));
    }
    let ctx = JobCtx::new("dns-benchmark", "測試", Arc::new(cfg())).with_clock(e.clock.clone());
    let b = Benchmark::with(e.p.clone(), e.prober.clone(), asn());
    assert!(b.run(&ctx).await.is_err());
    // 今天是 11-20：留 11-07～11-20 這 14 個日期
    assert!(!out.join("2026-11-06").exists());
    assert!(out.join("2026-11-07").exists());
}
