//! 好友邀請碼（規格 03 第 6.1 節）：兩個本機節點
//! 有效邀請碼 → 雙方成為好友並馬上同步；密鑰錯誤 / 重新產生後的舊碼 → 不自動同意；指紋不符 → 送出前中止；
//! 封鎖 / 墓碑照舊；我這邊沒就緒 → 列出缺什麼；打錯字 → 檢查碼擋下；密鑰不出現在日誌與其他 API

mod common;

use common::*;
use kuroshio_community::invite::{Invite, PREFIX};
use kuroshio_community::peers::Rel;
use kuroshio_community::{Community, Config, Options, Scheme};
use serde_json::{json, Value};
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

/// 整個測試程式的日誌都收進這裡（TRACE 等級），檢查密鑰有沒有被寫進日誌
fn logs() -> Arc<Mutex<Vec<u8>>> {
    static BUF: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    BUF.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        struct W(Arc<Mutex<Vec<u8>>>);
        impl Write for W {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let b = buf.clone();
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || W(b.clone()))
            .try_init();
        buf
    })
    .clone()
}

/// 三種管道都開（DoQ、DoT、HTTPS）：同一個測試程式裡每個測試各有一個 runtime，
/// QUIC 用戶端端點跟著 runtime 走，前一個測試結束後別的測試照樣能用 DoQ
fn spec() -> Spec {
    Spec::default()
}

fn code_of(n: &Node) -> String {
    let v = n.c.invite_json();
    assert_eq!(v["ok"], true, "{v}");
    v["code"].as_str().unwrap().to_string()
}

fn has_event(n: &Node, domain: &str, kind: &str, detail: &str) -> bool {
    n.c.events()
        .iter()
        .any(|e| e.domain == domain && e.kind == kind && e.detail.contains(detail))
}

/// 密鑰（base64 / 十六進位 / 邀請碼本身）都不能出現在這段文字裡
fn assert_no_secret(what: &str, text: &str, code: &str) {
    let inv = Invite::parse(code).unwrap();
    let hex = kuroshio_community::util::hex(&inv.secret);
    let b64 = kuroshio_community::util::b64(&inv.secret);
    assert!(!text.contains(code), "{what} 含邀請碼");
    assert!(!text.contains(&hex), "{what} 含密鑰（hex）");
    assert!(!text.contains(&b64), "{what} 含密鑰（base64）");
    assert!(!text.contains(&code[PREFIX.len()..PREFIX.len() + 40]), "{what} 含邀請碼片段");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_with_valid_code() {
    let log = logs();
    let r = resolver(&[]);
    // A 的自動規則是「全部拒絕」：邀請碼不受自動規則影響
    let a = node(
        "ia.test",
        &r,
        Spec {
            rules: vec![json!({ "action": "reject" })],
            ..spec()
        },
    )
    .await;
    let b = node("ib.test", &r, spec()).await;
    a.data.set(vec![node_rec("104.16.1.1")]);
    b.data.set(vec![node_rec("104.16.3.3")]);

    let code = code_of(&a);
    assert!(code.starts_with(PREFIX));
    let inv = Invite::parse(&code).unwrap();
    assert_eq!(inv.domain, "ia.test");
    assert_eq!(kuroshio_community::identity::fingerprint_text(&inv.fingerprint), a.c.fingerprint());
    // 測試的端點都不在預設埠：邀請碼帶第一個端點（DoQ）
    assert_eq!(inv.endpoint.as_ref().map(|e| (e.scheme, e.port)), Some((Scheme::Doq, a.doq)));
    // 固定：再查一次一樣
    assert_eq!(code_of(&a), code);

    let res = b.c.use_invite(&code).await;
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(res["stage"], "accepted", "{res}");
    let stages: Vec<&str> = res["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["step"].as_str().unwrap())
        .collect();
    assert_eq!(stages, ["format", "ready", "identity", "fingerprint", "request", "accepted"]);
    assert_eq!(a.peer("ib.test").rel, Rel::Friend);
    assert_eq!(b.peer("ia.test").rel, Rel::Friend);
    assert_eq!(a.peer("ib.test").pair_id, b.peer("ia.test").pair_id);
    assert!(a.peer("ib.test").invited_at > 0);
    assert!(has_event(&a, "ib.test", "成為好友", "透過邀請碼加入"));
    let peers = a.c.admin("/api/community/peers", &Default::default()).await.unwrap();
    assert!(peers[0]["invitedAt"].as_u64().is_some(), "{peers}");

    // 成為好友後馬上開始第一次同步（雙方）
    wait_for("B 收到 A 的資料", || {
        b.data.received.lock().unwrap().iter().any(|x| x.from == "ia.test" && x.full)
    })
    .await;
    wait_for("A 收到 B 的資料", || {
        a.data.received.lock().unwrap().iter().any(|x| x.from == "ib.test" && x.full)
    })
    .await;

    // 可以重複使用：第三台也能用同一個邀請碼
    let c = node("ic.test", &r, spec()).await;
    let res = c.c.use_invite(&code).await;
    assert_eq!(res["stage"], "accepted", "{res}");
    // 已經是好友：再貼一次也沒問題
    let res = b.c.use_invite(&code).await;
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(res["status"], "accepted");

    // 重新啟動後不變（金鑰目錄的 invite.json）
    let again = Community::open(
        Config {
            enabled: true,
            domain: "ia.test".into(),
            endpoints: a.c.config().endpoints,
            ..Default::default()
        },
        Options::new(&a.key_dir, tmpdir("ia-restart")),
    )
    .unwrap();
    assert_eq!(again.invite_json()["code"], Value::String(code.clone()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(a.key_dir.join("invite.json")).unwrap().permissions().mode();
        assert_eq!(m & 0o777, 0o600, "邀請密鑰只有擁有者能讀");
    }

    // 密鑰只在擁有者自己的 invite API：狀態、好友、事件、要寫回 state 的檔案、對方的 API、日誌都沒有
    for n in [&a, &b, &c] {
        let dom = &n.domain;
        for p in ["status", "peers", "events", "scores"] {
            let v = n.c.admin(&format!("/api/community/{p}"), &Default::default()).await.unwrap();
            assert_no_secret(&format!("{dom} {p}"), &v.to_string(), &code);
        }
        for (path, bytes) in n.c.snapshots() {
            assert_no_secret(&format!("{dom} {path}"), &String::from_utf8_lossy(&bytes), &code);
        }
    }
    assert_eq!(a.c.status()["invite"]["createdAt"].as_u64(), Some(inv_created(&a)));
    assert_no_secret("use 的回應", &res.to_string(), &code);
    let text = String::from_utf8_lossy(&log.lock().unwrap()).to_string();
    assert!(text.contains("透過邀請碼加入"), "日誌有收到");
    assert_no_secret("日誌", &text, &code);
}

fn inv_created(n: &Node) -> u64 {
    n.c.invite_json()["createdAt"].as_u64().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_or_refreshed_code_is_not_accepted() {
    let r = resolver(&[]);
    let a = node("wa.test", &r, spec()).await;
    let b = node("wb.test", &r, spec()).await;
    let code = code_of(&a);

    // 密鑰錯誤（其他都對，檢查碼也對）：當成一般請求 → 沒有規則 → 等人工審核，不是好友
    let mut fake = Invite::parse(&code).unwrap();
    fake.secret = [0x55; 16];
    let res = b.c.use_invite(&fake.encode()).await;
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(res["stage"], "sent", "{res}");
    assert_eq!(res["status"], "pending");
    assert_eq!(a.peer("wb.test").rel, Rel::In);
    assert_eq!(b.peer("wa.test").rel, Rel::Out);
    assert!(has_event(&a, "wb.test", "邀請碼不符或已重新產生", ""));

    // 重新產生：舊的立刻失效、新的可以用（對方原本在等審核也直接同意）
    let res = a.c.refresh_invite();
    let fresh = res["code"].as_str().unwrap().to_string();
    assert_ne!(fresh, code);
    let res = b.c.use_invite(&code).await;
    assert_eq!(res["stage"], "sent", "舊的邀請碼：{res}");
    assert_eq!(a.peer("wb.test").rel, Rel::In);
    let res = b.c.use_invite(&fresh).await;
    assert_eq!(res["stage"], "accepted", "{res}");
    assert_eq!(a.peer("wb.test").rel, Rel::Friend);
    assert_eq!(b.peer("wa.test").rel, Rel::Friend);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fingerprint_mismatch_aborts_before_sending() {
    let r = resolver(&[]);
    let a = node("fa.test", &r, spec()).await;
    let b = node("fb.test", &r, spec()).await;
    // 有人把 fa.test 指到自己的機器（另一把金鑰）：邀請碼的指紋跟對方身分文件不符
    let mut inv = Invite::parse(&code_of(&a)).unwrap();
    inv.fingerprint = [0xab; 16];
    let res = b.c.use_invite(&inv.encode()).await;
    assert_eq!(res["ok"], false, "{res}");
    assert_eq!(res["stage"], "fingerprint", "{res}");
    assert!(res["reason"].as_str().unwrap().contains("冒充"), "{res}");
    assert!(a.c.peer("fb.test").is_none(), "A 沒有收到任何請求");
    assert!(b.c.peer("fa.test").map(|p| p.rel == Rel::None).unwrap_or(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn block_and_tombstone_are_respected() {
    let r = resolver(&[]);
    let a = node("ba.test", &r, spec()).await;
    let b = node("bb.test", &r, spec()).await;
    let c = node("bc.test", &r, spec()).await;
    let code = code_of(&a);
    // A 封鎖了 B：邀請碼也不會自動同意
    a.c.with_peer("bb.test", |p| p.my_block = true);
    let res = b.c.use_invite(&code).await;
    assert_eq!(res["ok"], false, "{res}");
    assert_eq!(res["status"], "blocked", "{res}");
    assert!(a.peer("bb.test").my_block);
    assert_ne!(a.peer("bb.test").rel, Rel::Friend);
    // A 刪除過 C（墓碑）：一律人工審核
    a.c.with_peer("bc.test", |p| p.deleted_at = now());
    let res = c.c.use_invite(&code).await;
    assert_eq!(res["stage"], "sent", "{res}");
    assert_eq!(a.peer("bc.test").rel, Rel::In);
    assert!(has_event(&a, "bc.test", "邀請碼有效", "曾被你刪除"));
    // A 拒絕過的：照樣回「已拒絕」
    let d = node("bd.test", &r, spec()).await;
    a.c.with_peer("bd.test", |p| p.rejected_until = now() + 86_400_000);
    let res = d.c.use_invite(&code).await;
    assert_eq!(res["status"], "rejected", "{res}");
    assert_ne!(a.peer("bd.test").rel, Rel::Friend);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joiner_not_ready_and_typos() {
    let r = resolver(&[]);
    let a = node("na.test", &r, spec()).await;
    let b = node("nb.test", &r, spec()).await;
    let code = code_of(&a);

    // 打錯一個字：檢查碼擋下，什麼都不送
    let mut t = code.clone().into_bytes();
    let i = t.len() / 2;
    t[i] = if t[i] == b'Q' { b'R' } else { b'Q' };
    let res = b.c.use_invite(&String::from_utf8(t).unwrap()).await;
    assert_eq!(res["stage"], "format", "{res}");
    assert!(res["reason"].as_str().unwrap().contains("檢查碼"), "{res}");
    assert!(a.c.peer("nb.test").is_none());

    // 自己的邀請碼
    let res = a.c.use_invite(&code).await;
    assert_eq!(res["stage"], "self", "{res}");

    // B 關掉社群模式：列出缺什麼，不送任何東西（雙向，不做單向訂閱）
    let mut cfg = b.c.config();
    cfg.enabled = false;
    b.c.set_config(cfg.clone());
    let res = b.c.use_invite(&code).await;
    assert_eq!(res["ok"], false, "{res}");
    assert_eq!(res["stage"], "ready", "{res}");
    let problems: Vec<&str> = res["problems"].as_array().unwrap().iter().map(|p| p.as_str().unwrap()).collect();
    assert!(problems.contains(&"社群模式沒有啟用"), "{problems:?}");
    // 網域解析不到也一樣列出來
    cfg.enabled = true;
    b.c.set_config(cfg);
    r.set("nb.test", &[]);
    let res = b.c.use_invite(&code).await;
    assert_eq!(res["stage"], "ready", "{res}");
    assert!(res["problems"].to_string().contains("解析不到 nb.test"), "{res}");
    assert!(a.c.peer("nb.test").is_none(), "A 沒有收到任何請求");

    // 沒設網域的節點沒有邀請碼
    let dir = tmpdir("no-domain");
    let x = Community::open(Config::default(), Options::new(dir.join("k"), dir.join("s"))).unwrap();
    let v = x.invite_json();
    assert_eq!(v["ok"], false, "{v}");
    assert!(!dir.join("k/invite.json").exists());
}
