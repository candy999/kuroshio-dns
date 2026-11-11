//! 用戶端：加好友、通知、同步、poke、金鑰輪替、定時工作；收到資料後的檢查與品質分數（規格 03 第 6–8 節）

use crate::envelope::*;
use crate::identity::KeyInfo;
use crate::node::{Community, Job, OldVersion, State};
use crate::peers::{Rel, View};
use crate::provider::{CrossHint, NodeCandidate, RangeCheck, Received, SiteHint, UpstreamCandidate};
use crate::score::{self, Kind, Outcome};
use crate::share::{limit_of, validate, Check};
use crate::transport::{Endpoint, Reply};
use crate::util::{hex, now_ms, random_bytes, site_hash, valid_domain, DAY, HOUR};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

/// 回應的問題
#[derive(Debug)]
pub(crate) enum ReplyErr {
    /// 對方回錯誤（狀態碼、代碼、要求的 PoW 位元）
    Status(u16, String, Option<u8>),
    /// 已知金鑰、簽名卻不符
    Forged,
    /// 格式錯誤、超過上限
    Malformed(String),
    /// 不認得的金鑰（可能輪替了、還沒拿到）
    UnknownKey,
}

impl std::fmt::Display for ReplyErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplyErr::Status(s, c, _) => write!(f, "對方回應 {s} {c}"),
            ReplyErr::Forged => f.write_str("回應簽名不符"),
            ReplyErr::Malformed(e) => write!(f, "回應格式錯誤：{e}"),
            ReplyErr::UnknownKey => f.write_str("回應的金鑰不認得"),
        }
    }
}

fn fail(reason: impl std::fmt::Display) -> Value {
    json!({ "ok": false, "reason": reason.to_string() })
}

/// 收到的上游候選（所有好友合併）
pub(crate) fn upstream_ids(st: &State) -> Vec<String> {
    let mut v: Vec<String> = st
        .remote
        .iter()
        .filter(|(d, _)| {
            st.store
                .get(d)
                .map(|p| p.rel == Rel::Friend && !score::is_paused(&p.score, Kind::Upstream))
                .unwrap_or(false)
        })
        .flat_map(|(_, r)| r.recs.values().filter(|x| x.kind == "upstream").filter_map(|x| x.url.clone()))
        .collect();
    v.sort();
    v.dedup();
    v
}

/// 好友提示的一個 IP，與提到它的好友
#[derive(Debug, Clone, PartialEq)]
pub struct Hint {
    pub ip: IpAddr,
    pub from: Vec<String>,
}

impl Community {
    // ---------------- 送出與驗證 ----------------

    /// 送一個簽好名的信封給對方：依管道順序試，成功的管道記下來
    pub(crate) async fn post_env(&self, domain: &str, action: &str, env: &Envelope, max_wire: usize) -> Result<Reply> {
        self.post_each(domain, action, max_wire, || env.clone()).await
    }

    /// 依序試每個端點；`make` 每試一個端點就叫一次。
    /// 前一個端點可能已經收下訊息、只是回應沒傳回來，同一個 nonce 再送會被對方當成重放，
    /// 所以能重做的訊息（sync、relation、poke）每個端點都用新的 nonce 重新簽。
    async fn post_each(&self, domain: &str, action: &str, max_wire: usize, make: impl Fn() -> Envelope) -> Result<Reply> {
        let eps = self.peer_endpoints(domain);
        let mut last = anyhow!("沒有可用的端點");
        for ep in eps {
            let env = make();
            match crate::transport::call(&*self.resolver, &ep, action, Some(&env), self.timeouts(max_wire)).await {
                Ok(r) => {
                    let mut st = self.lock();
                    if let Some(p) = st.store.get_mut(domain) {
                        p.channel = Some(ep.scheme.as_str().to_string());
                    }
                    return Ok(r);
                }
                Err(e) => {
                    tracing::debug!("社群 {domain} {action} 經 {ep} 失敗：{e}");
                    last = e;
                }
            }
        }
        Err(last)
    }

    pub(crate) async fn post(&self, domain: &str, action: &str, body: Vec<u8>, max_wire: usize) -> Result<Reply> {
        let env = self.seal_envelope(action, body, None);
        self.post_env(domain, action, &env, max_wire).await
    }

    /// 同 `post`，但每個端點各自產生內容（新的 nonce）
    pub(crate) async fn post_fresh(&self, domain: &str, action: &str, max_wire: usize, body: impl Fn() -> Vec<u8>) -> Result<Reply> {
        self.post_each(domain, action, max_wire, || self.seal_envelope(action, body(), None))
            .await
    }

    /// 驗證回應：簽名（對方的金鑰）、寄件者、收件者；回傳明文 body
    pub(crate) async fn open_reply(
        &self,
        domain: &str,
        r: &Reply,
        action: &str,
        max_plain: usize,
    ) -> std::result::Result<Vec<u8>, ReplyErr> {
        if r.status != 200 {
            let e = Envelope::decode(&r.body).ok();
            return Err(ReplyErr::Status(
                r.status,
                e.as_ref().and_then(|e| e.error.clone()).unwrap_or_default(),
                e.and_then(|e| e.pow_bits),
            ));
        }
        let env = Envelope::decode(&r.body).map_err(|e| ReplyErr::Malformed(e.to_string()))?;
        let kid = env.kid().ok_or_else(|| ReplyErr::Malformed("沒有 kid".into()))?;
        let key = self.peer_key(domain, &kid, true).await.ok_or(ReplyErr::UnknownKey)?;
        if !env.verify_with(action, &key) {
            return Err(ReplyErr::Forged);
        }
        let plain = env.plain_body(max_plain).map_err(|e| ReplyErr::Malformed(e.to_string()))?;
        let head: Head = from_cbor(&plain).map_err(|e| ReplyErr::Malformed(e.to_string()))?;
        if head.t != action || head.from != domain || head.to.as_deref() != Some(self.domain().as_str()) {
            return Err(ReplyErr::Malformed("回應的動作或收件者不符".into()));
        }
        Ok(plain)
    }

    /// 連線失敗：對方回 404 而且 v1 路徑在 → 標記「對方版本較舊」，每 6 小時重試，不算連不上
    async fn note_error(&self, domain: &str, err: &str, maybe_v1: bool) {
        let now = now_ms();
        if maybe_v1 {
            let ep = self
                .peer_endpoints(domain)
                .into_iter()
                .find(|e| e.scheme == crate::transport::Scheme::Https);
            if let Some(ep) = ep {
                if crate::transport::is_v1(&*self.resolver, &ep, self.timeouts(MAX_REQUEST)).await {
                    self.mark_old_version(domain, now);
                    return;
                }
            }
        }
        self.lock().store.note_failure(domain, err, now);
    }

    fn mark_old_version(&self, domain: &str, now: u64) {
        let mut st = self.lock();
        let first = st.store.get(domain).map(|p| p.old_version_since == 0).unwrap_or(false);
        if let Some(p) = st.store.get_mut(domain) {
            if p.old_version_since == 0 {
                p.old_version_since = now;
            }
            p.last_error = Some("對方版本較舊（v1）".into());
            p.next_try = now + 6 * HOUR;
        }
        if first {
            st.store.event(domain, "對方版本較舊（v1）", "每 6 小時重試，最多等 30 天");
        }
    }

    /// 24 小時內 3 次格式完全錯誤 / 超過上限的回應 → 封鎖（只對好友）
    fn note_malformed(&self, domain: &str, why: &str) {
        let now = now_ms();
        let mut st = self.lock();
        let Some(p) = st.store.get_mut(domain) else { return };
        p.malformed.retain(|t| now.saturating_sub(*t) < DAY);
        p.malformed.push(now);
        let n = p.malformed.len();
        let friend = p.rel == Rel::Friend;
        st.store.note_failure(domain, why, now);
        if friend && n >= 3 {
            p_block(&mut st, domain, "24 小時內 3 次格式錯誤或超過上限的回應");
        }
    }

    // ---------------- 好友請求 ----------------

    /// 送出（或重送）好友請求；`input` = 網域或「網域:埠」。回傳 v1 的 `{ok, status, reason}`
    pub async fn send_request(&self, input: &str, manual: bool) -> Value {
        if !self.is_ready() {
            let p = self.lock().check.problems.join("；");
            return fail(format!("社群模式未就緒：{p}"));
        }
        let s = input.trim().to_ascii_lowercase();
        let s = s.strip_prefix("https://").unwrap_or(&s);
        let s = s.split('/').next().unwrap_or("");
        let (domain, port) = match s.rsplit_once(':') {
            Some((d, p)) => (d.to_string(), p.parse::<u16>().ok()),
            None => (s.to_string(), None),
        };
        if !valid_domain(&domain) || domain == self.domain() || (s.contains(':') && port.is_none()) {
            return fail("網域格式錯誤");
        }
        let now = now_ms();
        let st = self.lock().store.start_request(&domain, manual, now);
        if !st.ok {
            return fail(st.reason);
        }
        if st.accept_incoming {
            return self.decide(&domain, "accept").await;
        }
        if !self.lock().busy.insert(format!("req:{domain}")) {
            return json!({ "ok": true, "status": "pending" });
        }
        let r = self.request_inner(&domain, port).await;
        self.lock().busy.remove(&format!("req:{domain}"));
        r
    }

    async fn request_inner(&self, domain: &str, port: Option<u16>) -> Value {
        let now = now_ms();
        let mut cands = match port {
            Some(p) => Endpoint::defaults(domain, Some(p)),
            None => self.peer_endpoints(domain),
        };
        for e in Endpoint::defaults(domain, port) {
            if !cands.contains(&e) {
                cands.push(e);
            }
        }
        let idn = match self.fetch_identity(domain, cands, false, true).await {
            Ok(x) => x,
            Err(e) if e.downcast_ref::<OldVersion>().is_some() => {
                self.mark_old_version(domain, now);
                return fail("對方版本較舊（v1），每 6 小時重試");
            }
            Err(e) => {
                self.lock().store.note_failure(domain, &e.to_string(), now);
                return fail(e);
            }
        };
        if let Err(e) = self.reconcile_keys(domain, &idn, now) {
            self.lock().store.note_failure(domain, &e, now);
            return fail(e);
        }
        {
            let mut st = self.lock();
            if let Some(p) = st.store.get_mut(domain) {
                p.endpoints = idn.endpoints.clone();
                p.info.colo = idn.net.colo.clone();
                p.info.proto = idn.proto.clone();
                p.info.caps = idn.caps.clone();
                p.info.has_txt = Some(idn.has_txt);
                p.old_version_since = 0;
            }
        }
        let mut bits = {
            let st = self.lock();
            self.cfg.read().unwrap().pow_bits.max(st.pow_need.get(domain).copied().unwrap_or(0))
        };
        for attempt in 0..2 {
            let req_id = self.lock().store.get(domain).and_then(|p| p.out_req_id.clone()).unwrap_or_default();
            let body = RequestBody {
                t: "request".into(),
                from: self.domain(),
                to: domain.to_string(),
                ts: now_ms(),
                nonce: random_bytes::<12>().to_vec(),
                kid: self.kid().to_vec(),
                endpoints: self.my_endpoints(),
                req_id,
                pow: vec![0; 8],
            };
            let raw = to_cbor(&body);
            let solved = tokio::task::spawn_blocking(move || solve_pow(raw, bits)).await.unwrap_or_default();
            let reply = match self.post(domain, "request", solved, MAX_REQUEST).await {
                Ok(r) => r,
                Err(e) => {
                    self.note_error(domain, &e.to_string(), false).await;
                    return fail(e);
                }
            };
            let plain = match self.open_reply(domain, &reply, "relation", MAX_REQUEST).await {
                Ok(p) => p,
                Err(ReplyErr::Status(400, code, Some(need))) if code == "pow" && need > bits && attempt == 0 => {
                    // 對方請求太多、提高了難度：照對方要求的位元重算一次
                    self.lock().pow_need.insert(domain.to_string(), need);
                    bits = need;
                    continue;
                }
                Err(e) => {
                    self.note_error(domain, &e.to_string(), matches!(e, ReplyErr::Status(404, ..)))
                        .await;
                    return fail(e);
                }
            };
            let Ok(rb) = from_cbor::<RelationBody>(&plain) else {
                return fail("回應格式錯誤");
            };
            let now = now_ms();
            let accepted = rb.status == "accepted";
            {
                let mut st = self.lock();
                match rb.status.as_str() {
                    "accepted" | "pending" | "rejected" | "blocked" => {
                        let v = View {
                            status: rb.status.clone(),
                            pair_id: rb.pair_id.clone(),
                            until: rb.until,
                            req_id: rb.req_id.clone(),
                        };
                        st.store.apply_response(domain, &v, now);
                        if let Some(p) = st.store.get_mut(domain) {
                            p.last_error = None;
                            p.fail_count = 0;
                        }
                    }
                    "unverified" => st.store.note_failure(
                        domain,
                        &format!("對方無法驗證我的身分：{}", rb.error.clone().unwrap_or_default()),
                        now,
                    ),
                    "key-mismatch" => st.store.note_failure(domain, "對方記得的金鑰跟我現在的不一樣，請對方人工確認", now),
                    other => st.store.note_failure(domain, &format!("對方回應 {other}"), now),
                }
            }
            if accepted {
                self.later(self.tuning.follow_up_ms, Job::Sync(domain.to_string()));
            }
            return json!({ "ok": true, "status": rb.status, "error": rb.error });
        }
        fail("工作量證明失敗")
    }

    /// 送 relation（通知同意 / 拒絕 / 封鎖 / 刪除）；回傳對方的看法
    pub(crate) async fn send_relation(&self, domain: &str, v: &View) -> Option<View> {
        let body = RelationBody {
            t: "relation".into(),
            from: self.domain(),
            to: domain.to_string(),
            ts: now_ms(),
            nonce: random_bytes::<12>().to_vec(),
            pair_id: v.pair_id.clone(),
            status: v.status.clone(),
            req_id: v.req_id.clone(),
            until: v.until,
            error: None,
        };
        let r = self
            .post_fresh(domain, "relation", MAX_REQUEST, || {
                let mut b = body.clone();
                b.nonce = random_bytes::<12>().to_vec();
                to_cbor(&b)
            })
            .await
            .ok()?;
        let plain = self.open_reply(domain, &r, "relation", MAX_REQUEST).await.ok()?;
        let rb: RelationBody = from_cbor(&plain).ok()?;
        Some(View {
            status: rb.status,
            pair_id: rb.pair_id,
            until: rb.until,
            req_id: rb.req_id,
        })
    }

    /// 我處理對方的請求：accept / reject / block
    pub async fn decide(&self, domain: &str, action: &str) -> Value {
        let now = now_ms();
        let (req_id, v) = {
            let mut st = self.lock();
            let Some(p) = st.store.get(domain) else {
                return fail("沒有這個對象");
            };
            let req_id = p.in_req_id.clone();
            let v = match action {
                "accept" => st.store.accept(domain, "手動同意", now),
                "reject" => st.store.reject(domain, "手動拒絕", now),
                "block" => st.store.block(domain, "手動封鎖"),
                _ => return fail("未知動作"),
            };
            (req_id, v)
        };
        if v.status == "error" {
            return fail("沒有待處理的請求");
        }
        let n = View { req_id, ..v.clone() };
        self.send_relation(domain, &n).await;
        if v.status == "accepted" {
            self.later(self.tuning.follow_up_ms, Job::Sync(domain.to_string()));
        }
        json!({ "ok": true, "status": v.status })
    }

    /// 刪除好友（block = 同時封鎖）；也用來取消送出的請求
    pub async fn remove_friend(&self, domain: &str, block: bool) -> Value {
        let now = now_ms();
        let old = {
            let mut st = self.lock();
            let Some(old) = st.store.remove(domain, true, if block { "刪除並封鎖" } else { "手動刪除" }, now) else {
                return fail("沒有這個對象");
            };
            if block {
                st.store.block(domain, "刪除並封鎖");
            }
            st.remote.remove(domain);
            old
        };
        let v = View {
            status: if block { "blocked" } else { "deleted" }.into(),
            pair_id: old,
            ..Default::default()
        };
        self.send_relation(domain, &v).await;
        json!({ "ok": true })
    }

    pub fn unblock(&self, domain: &str) -> Value {
        let ok = self.lock().store.unblock(domain);
        json!({ "ok": ok })
    }

    /// 人工接受未經舊金鑰簽名的金鑰變更（保留原本的好友狀態）
    pub fn accept_key(&self, domain: &str) -> Value {
        let mut st = self.lock();
        let Some(p) = st.store.get_mut(domain) else {
            return fail("沒有這個對象");
        };
        let Some(k) = p.pending_key.take() else {
            return fail("沒有待確認的金鑰");
        };
        let kid = k.kid.clone();
        p.keys = vec![k];
        let friend = p.rel == Rel::Friend;
        st.id_cache.remove(domain);
        st.store.event(domain, "人工接受新金鑰", &kid);
        drop(st);
        if friend {
            self.later(0, Job::Sync(domain.to_string()));
        }
        json!({ "ok": true, "kid": kid })
    }

    /// 指定管道（doq / dot / https；auto = 自動）
    pub fn set_channel(&self, domain: &str, ch: &str) -> Value {
        let mut st = self.lock();
        let Some(p) = st.store.get_mut(domain) else {
            return fail("沒有這個對象");
        };
        if ch.is_empty() || ch == "auto" {
            p.prefer_channel = None;
        } else if let Some(s) = crate::transport::Scheme::parse(ch) {
            p.prefer_channel = Some(s.as_str().to_string());
        } else {
            return fail("管道只能是 doq / dot / https / auto");
        }
        json!({ "ok": true, "channel": p.channel, "prefer": p.prefer_channel })
    }

    // ---------------- 同步 ----------------

    /// 向好友拉資料（增量）；狀態不是 ok 時用 relation 對一次狀態，再同步一次
    pub async fn sync_peer(&self, domain: &str) -> Value {
        let key = format!("sync:{domain}");
        if !self.lock().busy.insert(key.clone()) {
            return json!({ "ok": true, "status": "busy" });
        }
        let r = self.sync_inner(domain).await;
        self.lock().busy.remove(&key);
        r
    }

    async fn sync_inner(&self, domain: &str) -> Value {
        let max_plain = self.config().max_plain_bytes();
        for attempt in 0..2 {
            let (pair_id, epoch, since) = {
                let st = self.lock();
                let Some(p) = st.store.get(domain).filter(|p| p.rel == Rel::Friend) else {
                    return fail("不是好友");
                };
                let r = st.remote.get(domain).filter(|r| !r.epoch.is_empty());
                (p.pair_id.clone(), r.map(|r| r.epoch.clone()), r.map(|r| r.seq))
            };
            let body = SyncRequest {
                t: "sync".into(),
                from: self.domain(),
                to: domain.to_string(),
                ts: now_ms(),
                nonce: random_bytes::<12>().to_vec(),
                pair_id: pair_id.clone(),
                epoch: epoch.map(serde_bytes::ByteBuf::from),
                since,
            };
            let reply = match self
                .post_fresh(domain, "sync", MAX_RESPONSE_WIRE, || {
                    let mut b = body.clone();
                    b.nonce = random_bytes::<12>().to_vec();
                    to_cbor(&b)
                })
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    let msg = e.to_string();
                    if e.downcast_ref::<crate::transport::TooLarge>().is_some() {
                        self.note_malformed(domain, &msg);
                    } else {
                        self.note_error(domain, &msg, false).await;
                    }
                    return fail(msg);
                }
            };
            let plain = match self.open_reply(domain, &reply, "sync", max_plain).await {
                Ok(p) => p,
                Err(ReplyErr::Forged) => {
                    // 已驗證的好友管道上收到簽名錯誤的訊息：不可能是正常系統
                    let mut st = self.lock();
                    p_block(&mut st, domain, "回應簽名不符（可能被冒用）");
                    return fail("回應簽名不符，已封鎖");
                }
                Err(ReplyErr::Malformed(e)) => {
                    self.note_malformed(domain, &e);
                    return fail(e);
                }
                Err(e) => {
                    self.note_error(domain, &e.to_string(), matches!(e, ReplyErr::Status(404, ..)))
                        .await;
                    return fail(e);
                }
            };
            let resp: SyncResponse = match from_cbor(&plain) {
                Ok(r) => r,
                Err(e) => {
                    self.note_malformed(domain, &e.to_string());
                    return fail(e);
                }
            };
            let now = now_ms();
            match resp.status.as_str() {
                "ok" => {
                    let out = self.ingest(domain, resp, now);
                    return out;
                }
                "unchanged" => {
                    self.lock().store.note_success(domain, now);
                    return json!({ "ok": true, "status": "unchanged" });
                }
                other => {
                    // 互相檢查狀態（2.1.5）：我說是好友，問對方怎麼看；問不到就照 sync 的狀態處理
                    let mine = View {
                        status: "accepted".into(),
                        pair_id: pair_id.clone(),
                        ..Default::default()
                    };
                    let theirs = if attempt == 0 {
                        self.send_relation(domain, &mine).await
                    } else {
                        None
                    };
                    let v = theirs.unwrap_or(View {
                        status: other.to_string(),
                        pair_id: resp.pair_id.clone(),
                        until: resp.until,
                        req_id: None,
                    });
                    let (follow, still) = {
                        let mut st = self.lock();
                        let f = st.store.apply_response(domain, &v, now);
                        let still = st.store.get(domain).map(|p| p.rel == Rel::Friend).unwrap_or(false);
                        if !still {
                            st.remote.remove(domain);
                        }
                        (f, still)
                    };
                    if follow.re_request {
                        self.later(self.tuning.rerequest_ms, Job::Request(domain.to_string()));
                    }
                    if still && attempt == 0 && v.status == "accepted" {
                        continue;
                    }
                    return json!({ "ok": false, "status": other, "reason": format!("對方回應 {other}") });
                }
            }
        }
        fail("同步失敗")
    }

    /// 套用好友的同步回應：檢查每筆、存起來、把候選交給 DataProvider、更新分數
    fn ingest(&self, domain: &str, resp: SyncResponse, now: u64) -> Value {
        let r = {
            let mut g = self.lock();
            self.ingest_locked(&mut g, domain, resp, now)
        };
        match r {
            Ok((summary, batch)) => {
                // DataProvider 在鎖外面呼叫
                self.provider.on_received(&batch);
                summary
            }
            Err(v) => v,
        }
    }

    fn ingest_locked(&self, st: &mut State, domain: &str, resp: SyncResponse, now: u64) -> std::result::Result<(Value, Received), Value> {
        let full = resp.full.unwrap_or(true);
        let remote = st.remote.entry(domain.to_string()).or_default();
        let epoch = resp.epoch.as_ref().map(|e| e.to_vec()).unwrap_or_default();
        if !full && remote.epoch != epoch {
            // 增量的基準不符：清掉，下次拿完整集合
            remote.epoch.clear();
            return Err(fail("增量同步的 epoch 不符，下次改拿完整集合"));
        }
        if full {
            remote.recs.clear();
        }
        let mut invalid: BTreeMap<Kind, u32> = BTreeMap::new();
        let mut invalid_total = 0u32;
        let mut fresh = vec![];
        let mut counts: HashMap<Kind, usize> = Kind::ALL.iter().map(|k| (*k, remote.count(*k))).collect();
        let mut out_of_range = 0usize;
        let mut nodes = vec![];
        for x in resp.upserts {
            let Some(r) = x.0 else {
                invalid_total += 1;
                continue;
            };
            match validate(&r, now) {
                Check::Valid(k, rec) => {
                    let rec = *rec;
                    let exists = remote.get(&rec.kind, &rec.key).is_some();
                    let c = counts.get_mut(&k).unwrap();
                    if !exists && *c >= limit_of(k) {
                        continue;
                    }
                    if k == Kind::Node {
                        // 不在我的官方範圍內、或我不認識的 CDN：每次同步最多收 100 筆當「待驗證」候選
                        let ip: IpAddr = rec.ip.as_deref().unwrap_or("").parse().unwrap();
                        let in_range = self.provider.in_range(rec.p.as_deref().unwrap_or(""), ip) == RangeCheck::InRange;
                        if !in_range {
                            out_of_range += 1;
                            if out_of_range > 100 {
                                continue;
                            }
                        }
                        nodes.push((in_range, rec.clone()));
                    }
                    if !exists {
                        *c += 1;
                    }
                    remote.upsert(rec.clone());
                    fresh.push((k, rec));
                }
                Check::Expired => {
                    remote.delete(&r.kind, &r.key);
                }
                Check::Invalid(k) => {
                    invalid_total += 1;
                    if let Some(k) = k {
                        *invalid.entry(k).or_default() += 1;
                    }
                }
            }
        }
        let mut deleted = vec![];
        for (kind, key) in resp.deletes {
            if remote.delete(&kind, &key) {
                deleted.push((kind, key));
            }
        }
        remote.epoch = epoch;
        remote.seq = resp.seq.unwrap_or(0);
        remote.ctx = resp.ctx.clone().unwrap_or_default();
        remote.updated = now;
        let valid = fresh.len() as u32;

        // 品質分數：格式錯誤算 invalid；被暫停的 kind 只放一小批
        let p = st.store.get_mut(domain).unwrap();
        for (k, n) in &invalid {
            score::entry(&mut p.score, *k).add(Outcome::Invalid, *n, now);
        }
        let mut allow: HashMap<Kind, Option<usize>> = HashMap::new();
        for k in Kind::ALL {
            allow.insert(
                k,
                if score::is_paused(&p.score, k) {
                    score::entry(&mut p.score, k).allowance(now)
                } else {
                    None
                },
            );
        }
        p.stats.offered = valid;
        p.stats.invalid = invalid_total;
        let mut take = |k: Kind| match allow.get_mut(&k).unwrap() {
            None => true,
            Some(0) => false,
            Some(n) => {
                *n -= 1;
                true
            }
        };
        let mut batch = Received {
            from: domain.to_string(),
            ctx: resp.ctx.unwrap_or_default(),
            full,
            deleted: deleted.clone(),
            ..Default::default()
        };
        for (in_range, r) in nodes {
            if take(Kind::Node) {
                batch.nodes.push(NodeCandidate {
                    p: r.p.unwrap_or_default(),
                    ip: r.ip.as_deref().unwrap_or("").parse().unwrap(),
                    pop: r.pop.unwrap_or_default(),
                    ms: r.ms,
                    in_range,
                    obs: r.obs,
                    exp: r.exp,
                });
            }
        }
        let ips = |v: &Option<Vec<String>>| v.iter().flatten().filter_map(|s| s.parse().ok()).collect::<Vec<IpAddr>>();
        for (k, r) in &fresh {
            match k {
                Kind::Site if take(Kind::Site) => batch.sites.push(SiteHint {
                    h: r.h.as_ref().map(|h| h.as_slice().try_into().unwrap()).unwrap(),
                    p: r.p.clone().unwrap_or_default(),
                    fam: r.fam.unwrap_or(4),
                    ips: ips(&r.ips),
                    pop: r.pop.clone().unwrap_or_default(),
                    obs: r.obs,
                }),
                Kind::Cross if take(Kind::Cross) => batch.cross.push(CrossHint {
                    h: r.h.as_ref().map(|h| h.as_slice().try_into().unwrap()).unwrap(),
                    from: r.from.clone().unwrap_or_default(),
                    to: r.to.clone().unwrap_or_default(),
                    ips: ips(&r.ips),
                    obs: r.obs,
                }),
                Kind::Upstream if take(Kind::Upstream) => batch.upstreams.push(UpstreamCandidate {
                    url: r.url.clone().unwrap_or_default(),
                    proto: r.proto.clone().unwrap_or_default(),
                    ms: r.ms,
                    ok: r.ok.unwrap_or(0.0),
                }),
                _ => {}
            }
        }
        st.store.note_success(domain, now);
        if invalid_total > 0 {
            st.store
                .event(domain, "資料有問題", &format!("{invalid_total} 筆格式錯誤或私有位址"));
        }
        // 同一次同步裡 invalid ≥ 20 筆、而且超過有效筆數 → 封鎖（同 2.1.4）
        if invalid_total >= 20 && invalid_total > valid {
            p_block(st, domain, &format!("同一次同步有 {invalid_total} 筆格式錯誤"));
            return Err(json!({ "ok": false, "status": "blocked", "reason": "資料格式錯誤太多，已封鎖" }));
        }
        let seq = remote_seq(st, domain);
        let summary = json!({
            "ok": true, "status": "ok", "full": full, "upserts": valid, "deletes": batch.deleted.len(),
            "invalid": invalid_total, "seq": seq,
        });
        Ok((summary, batch))
    }

    // ---------------- 通知與輪替 ----------------

    /// poke 好友（只通知「有變化」，不帶資料）；資料類每個好友最多每 10 分鐘一次
    pub async fn poke(&self, domain: &str, what: &str) -> bool {
        let now = now_ms();
        let pair_id = {
            let mut st = self.lock();
            let Some(pid) = st
                .store
                .get(domain)
                .filter(|p| p.rel == Rel::Friend)
                .and_then(|p| p.pair_id.clone())
            else {
                return false;
            };
            if what == "data" {
                let last = st.poke_last.get(domain).copied().unwrap_or(0);
                if last != 0 && now.saturating_sub(last) < self.tuning.poke_interval_ms {
                    return false;
                }
                st.poke_last.insert(domain.to_string(), now);
            }
            pid
        };
        let seq = self.lock().share.seq;
        let body = PokeBody {
            t: "poke".into(),
            from: self.domain(),
            to: domain.to_string(),
            ts: now,
            nonce: random_bytes::<12>().to_vec(),
            pair_id: Some(pair_id),
            what: what.to_string(),
            seq: (what == "data").then_some(seq),
        };
        self.post_fresh(domain, "poke", MAX_REQUEST, || {
            let mut b = body.clone();
            b.nonce = random_bytes::<12>().to_vec();
            to_cbor(&b)
        })
        .await
        .is_ok()
    }

    /// 產生新金鑰、用舊金鑰簽輪替聲明，通知所有好友
    pub fn rotate(&self) -> Value {
        let now = now_ms();
        let me = self.domain();
        let r = self.ident.write().unwrap().rotate(now, |old, new, now| {
            to_cbor(&RotateBody {
                t: "rotate".into(),
                from: me.clone(),
                ts: now,
                nonce: random_bytes::<12>().to_vec(),
                old: old.kid.to_vec(),
                new: KeyInfo {
                    kid: new.kid.to_vec(),
                    public: new.public.to_vec(),
                    since: now,
                },
            })
        });
        if let Err(e) = r {
            return fail(format!("更換金鑰失敗：{e}"));
        }
        let friends: Vec<String> = {
            let mut st = self.lock();
            st.doc = None;
            st.store.event(&me, "更換金鑰", &format!("新金鑰 {}", hex(&self.kid())));
            st.store.friends().map(|p| p.domain.clone()).collect()
        };
        for d in friends {
            self.later(0, Job::Rotate(d));
        }
        json!({ "ok": true, "kid": hex(&self.kid()), "fingerprint": self.fingerprint() })
    }

    /// 把輪替聲明送給一個好友（舊金鑰簽的原始 body）
    pub(crate) async fn send_rotate(&self, domain: &str) {
        let env = {
            let id = self.ident.read().unwrap();
            let Some(r) = id.rotation.as_ref() else { return };
            let (Some(kid), Some(body), Some(sig)) = (
                crate::util::unhex(&r.old_kid),
                crate::util::unb64(&r.body),
                crate::util::unb64(&r.sig),
            ) else {
                return;
            };
            Envelope {
                v: PROTO,
                kid: Some(serde_bytes::ByteBuf::from(kid)),
                body: Some(serde_bytes::ByteBuf::from(body)),
                sig: Some(serde_bytes::ByteBuf::from(sig)),
                ..Default::default()
            }
        };
        match self.post_env(domain, "rotate", &env, MAX_REQUEST).await {
            Ok(r) if r.status == 204 || r.status == 200 => {}
            Ok(r) => {
                // 聲明太舊（超過時間誤差）或對方沒收到：改 poke，請對方讀身分文件（裡面有聲明）
                tracing::debug!("社群：{domain} 沒收下輪替通知（{}），改用 poke", r.status);
                self.poke(domain, "rotate").await;
            }
            Err(_) => {}
        }
    }

    // ---------------- 收到的資料：查詢與回饋 ----------------

    /// 這個網站好友驗證過的 IP（越多好友提到、分數越高的排越前面）
    pub fn site_hints(&self, name: &str, provider: &str, fam: u8) -> Vec<Hint> {
        let key = format!("{}/{fam}", hex(&site_hash(name)));
        self.collect_hints("site", &key, Kind::Site, |r| r.p.as_deref() == Some(provider))
    }

    /// 跨 CDN 提示：（換到哪一家, IP）
    pub fn cross_hint(&self, name: &str) -> Option<(String, Vec<Hint>)> {
        let key = hex(&site_hash(name));
        let to = {
            let st = self.lock();
            let mut to = None;
            for (d, r) in &st.remote {
                if !usable(&st, d, Kind::Cross) {
                    continue;
                }
                if let Some(x) = r.get("cross", &key) {
                    to = x.to.clone();
                    break;
                }
            }
            to?
        };
        let v = self.collect_hints("cross", &key, Kind::Cross, |r| r.to.as_deref() == Some(to.as_str()));
        (!v.is_empty()).then_some((to, v))
    }

    fn collect_hints(&self, kind: &str, key: &str, k: Kind, filter: impl Fn(&WireRecord) -> bool) -> Vec<Hint> {
        let now = now_ms();
        let st = self.lock();
        let mut m: HashMap<IpAddr, (Vec<String>, f64)> = HashMap::new();
        for (d, r) in &st.remote {
            if !usable(&st, d, k) {
                continue;
            }
            let Some(rec) = r.get(kind, key).filter(|x| x.exp > now && filter(x)) else {
                continue;
            };
            let s = st.store.get(d).map(|p| score::score_of(&p.score, k, now)).unwrap_or(0.5);
            for ip in rec.ips.iter().flatten().filter_map(|s| s.parse::<IpAddr>().ok()) {
                let e = m.entry(ip).or_insert((vec![], 0.0));
                e.0.push(d.clone());
                e.1 = e.1.max(s);
            }
        }
        let mut v: Vec<(IpAddr, Vec<String>, f64)> = m.into_iter().map(|(ip, (f, s))| (ip, f, s)).collect();
        v.sort_by(|a, b| {
            b.1.len()
                .cmp(&a.1.len())
                .then(b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal))
                .then(a.0.cmp(&b.0))
        });
        v.into_iter()
            .map(|(ip, mut from, _)| {
                from.sort();
                Hint { ip, from }
            })
            .collect()
    }

    /// 好友提供的上游（每日評測的候選）
    pub fn upstream_candidates(&self) -> Vec<String> {
        upstream_ids(&self.lock())
    }

    /// 本機驗證結果回饋到好友的資料品質分數（例如網站提示的 IP 實際可用 / 不可用）
    pub fn report(&self, froms: &[String], kind: Kind, outcome: Outcome) {
        let now = now_ms();
        let min = self.config().min_hit_rate;
        let mut st = self.lock();
        let mut evs = vec![];
        for d in froms {
            let Some(p) = st.store.get_mut(d) else { continue };
            let e = score::entry(&mut p.score, kind);
            e.add(outcome, 1, now);
            if e.evaluate(min, now) {
                evs.push((d.clone(), e.paused));
            }
        }
        for (d, paused) in evs {
            st.store
                .event(&d, if paused { "暫停採用資料" } else { "恢復採用資料" }, kind.as_str());
        }
    }

    // ---------------- 定時工作 ----------------

    /// 每分鐘呼叫一次：重建分享集合（有變動就 poke 好友）、到期的同步與請求、每小時的維護
    pub async fn tick(&self) {
        let cfg = self.config();
        if !cfg.enabled {
            return;
        }
        if !self.lock().check.ready {
            self.check().await;
            if !self.lock().check.ready {
                return;
            }
        }
        let now = now_ms();
        if self.refresh_share(now, false) {
            let friends: Vec<String> = self.lock().store.friends().map(|p| p.domain.clone()).collect();
            for d in friends {
                self.later(0, Job::Poke(d, "data"));
            }
        }
        let due: Vec<(String, Rel)> = {
            let st = self.lock();
            st.store
                .peers
                .values()
                .filter(|p| p.next_try == 0 || now >= p.next_try)
                .filter(|p| {
                    (p.rel == Rel::Friend && now.saturating_sub(p.last_sync_ok) >= cfg.sync_interval_min as u64 * 60_000)
                        || p.rel == Rel::Out
                })
                .map(|p| (p.domain.clone(), p.rel))
                .collect()
        };
        for (d, rel) in due {
            if rel == Rel::Friend {
                self.sync_peer(&d).await;
            } else {
                self.send_request(&d, false).await;
            }
        }
        let hourly = {
            let mut st = self.lock();
            let due = now.saturating_sub(st.last_hourly) >= HOUR;
            if due {
                st.last_hourly = now;
            }
            due
        };
        if hourly {
            self.maintain(now);
        }
    }

    /// 每小時：長期連不上的好友、品質分數、過期資料、nonce、輪替後的舊金鑰
    pub fn maintain(&self, now: u64) {
        let cfg = self.config();
        let mut st = self.lock();
        for d in st.store.expire_stale(cfg.stale_days, now) {
            st.remote.remove(&d);
        }
        st.store.expire_auto_blocks(now);
        let mut evs = vec![];
        let mut drop_peers = vec![];
        for p in st.store.peers.values_mut() {
            p.keys.retain(|k| k.until.map(|u| now < u).unwrap_or(true));
            p.malformed.retain(|t| now.saturating_sub(*t) < DAY);
            if p.rel != Rel::Friend {
                continue;
            }
            for k in Kind::ALL {
                let e = score::entry(&mut p.score, k);
                e.prune(now);
                if e.evaluate(cfg.min_hit_rate, now) {
                    evs.push((p.domain.clone(), if e.paused { "暫停採用資料" } else { "恢復採用資料" }, k));
                }
                if e.paused && cfg.auto_delete_low_hit_rate {
                    drop_peers.push((p.domain.clone(), k, e.score(now)));
                }
            }
        }
        for (d, t, k) in evs {
            st.store.event(&d, t, k.as_str());
        }
        drop_peers.dedup_by(|a, b| a.0 == b.0);
        for (d, k, s) in drop_peers {
            st.store
                .remove(&d, false, &format!("{} 資料品質 {:.0}% 太低", k.as_str(), s * 100.0), now);
            st.remote.remove(&d);
        }
        for r in st.remote.values_mut() {
            r.expire(now);
        }
        st.share.prune(now);
        st.nonces.prune(now);
        st.id_cache
            .retain(|_, (_, at)| now.saturating_sub(*at) < crate::node::IDENTITY_CACHE_MS);
        st.poke_last.retain(|_, t| now.saturating_sub(*t) < HOUR);
    }
}

fn usable(st: &State, domain: &str, k: Kind) -> bool {
    st.store
        .get(domain)
        .map(|p| p.rel == Rel::Friend && !score::is_paused(&p.score, k))
        .unwrap_or(false)
}

fn remote_seq(st: &State, domain: &str) -> u64 {
    st.remote.get(domain).map(|r| r.seq).unwrap_or(0)
}

/// 封鎖並丟掉對方的資料
pub(crate) fn p_block(st: &mut State, domain: &str, why: &str) {
    st.store.block(domain, why);
    st.remote.remove(domain);
}
