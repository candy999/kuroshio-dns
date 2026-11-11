//! 好友狀態（規格 03 第 5 節；語意跟 v1 `peers.js` 一樣，純邏輯、不碰網路，方便測試）
//!
//! 關係 rel：none（無）/ out（我送出請求，等對方）/ in（對方送來請求，等我決定）/ friend（好友）
//! 另外記錄：
//!   myBlock          我封鎖對方：對方請求一律回「已封鎖」
//!   theirBlock       對方封鎖我：不再自動請求
//!   rejectedUntil    我拒絕對方：這之前對方的請求一律回「已拒絕」；提早重送 3 次就自動封鎖
//!   theirRejectUntil 對方拒絕我：這之前不再自動請求
//!   deletedAt        我手動刪除對方（墓碑）：之後對方再請求，不套用自動同意，一律人工審核
//!   pairId           這一次好友配對的編號：刪除後清空，舊配對的訊息一律忽略
//!   autoReqPair      被對方刪除後自動重新請求過的配對編號：每次被刪只自動重送一次

use crate::score::Reputation;
use crate::util::{fmt_date, hex, now_ms, random_bytes, sha256, DAY, HOUR};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rel {
    #[default]
    None,
    Out,
    In,
    Friend,
}

impl Rel {
    pub fn as_str(self) -> &'static str {
        match self {
            Rel::None => "none",
            Rel::Out => "out",
            Rel::In => "in",
            Rel::Friend => "friend",
        }
    }
}

/// 數字欄位寬鬆讀取（v1 的 JSON 可能是浮點數或 null）
fn lenient_u32<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u32>, D::Error> {
    let v = Option::<Value>::deserialize(d)?;
    Ok(v.and_then(|v| v.as_f64())
        .filter(|x| x.is_finite() && *x >= 0.0)
        .map(|x| x.round().min(u32::MAX as f64) as u32))
}

fn lenient_u64<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let v = Option::<Value>::deserialize(d)?;
    Ok(v.and_then(|v| v.as_f64())
        .filter(|x| x.is_finite() && *x >= 0.0)
        .map(|x| x as u64)
        .unwrap_or(0))
}

/// 加好友時量到、查到的資訊（自動規則用）
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerInfo {
    #[serde(default, deserialize_with = "lenient_u32", skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
    #[serde(default, deserialize_with = "lenient_u32", skip_serializing_if = "Option::is_none")]
    pub jitter_ms: Option<u32>,
    #[serde(default, deserialize_with = "lenient_u32", skip_serializing_if = "Option::is_none")]
    pub loss_pct: Option<u32>,
    #[serde(default, deserialize_with = "lenient_u32", skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default)]
    pub colo: String,
    #[serde(default, deserialize_with = "lenient_u32", skip_serializing_if = "Option::is_none")]
    pub age_days: Option<u32>,
    #[serde(default, deserialize_with = "lenient_u32", skip_serializing_if = "Option::is_none")]
    pub mutual: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// 來源 IP 是否在對方網域的解析結果裡（v2：軟性條件）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_match: Option<bool>,
    /// 對方有沒有設定 `_kuroshio` TXT
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_txt: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proto: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// 對方的公鑰（輪替期間可能兩把；舊的到 `until` 為止）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerKey {
    pub kid: String,
    #[serde(rename = "pub")]
    pub public: String,
    #[serde(default)]
    pub since: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerStats {
    /// 最近一次同步收下的筆數
    #[serde(default)]
    pub offered: u32,
    /// 最近一次同步的格式錯誤筆數
    #[serde(default)]
    pub invalid: u32,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Peer {
    pub domain: String,
    #[serde(default)]
    pub keys: Vec<PeerKey>,
    /// 金鑰變更但沒有舊金鑰的簽名：等人工確認
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_key: Option<PeerKey>,
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// 上次成功的管道（doq / dot / https）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// 管理介面指定的管道（沒指定 = 自動）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefer_channel: Option<String>,
    #[serde(default)]
    pub rel: Rel,
    #[serde(default)]
    pub my_block: bool,
    /// 自動封鎖（拒絕期間一直重送請求、自動規則）的時間；0 = 不是自動封鎖。
    /// 自動封鎖有數量上限、30 天後解除（見 `MAX_AUTO_BLOCKS`）；使用者自己封鎖的永遠不會被清掉。
    /// 舊版的檔案沒有這個欄位：既有的封鎖一律當成使用者封鎖
    #[serde(default, skip_serializing_if = "is_zero", deserialize_with = "lenient_u64")]
    pub auto_block_at: u64,
    #[serde(default)]
    pub their_block: bool,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub rejected_until: u64,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub their_reject_until: u64,
    #[serde(default)]
    pub early_retries: u32,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub deleted_at: u64,
    #[serde(default)]
    pub pair_id: Option<String>,
    #[serde(default)]
    pub out_req_id: Option<String>,
    #[serde(default)]
    pub in_req_id: Option<String>,
    #[serde(default)]
    pub auto_req_pair: Option<String>,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub created_at: u64,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub friend_since: u64,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub last_contact: u64,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub last_sync_ok: u64,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub fail_count: u32,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub next_try: u64,
    #[serde(default)]
    pub info: PeerInfo,
    #[serde(default)]
    pub stats: PeerStats,
    /// 每種 kind 的資料品質分數
    #[serde(default)]
    pub score: Reputation,
    /// 對方還在 v1（第一次發現的時間）：不算連不上，最多等 30 天
    #[serde(default, skip_serializing_if = "is_zero")]
    pub old_version_since: u64,
    /// 最近 24 小時格式完全錯誤 / 超過上限的回應時間
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub malformed: Vec<u64>,
    #[serde(default)]
    pub note: String,
    /// 不認識的欄位原樣保留（新舊版本來回切換不遺失資料）
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn is_zero(x: &u64) -> bool {
    *x == 0
}

impl Peer {
    pub fn blank(domain: &str, now: u64) -> Peer {
        Peer {
            domain: domain.to_string(),
            keys: vec![],
            pending_key: None,
            endpoints: vec![],
            channel: None,
            prefer_channel: None,
            rel: Rel::None,
            my_block: false,
            auto_block_at: 0,
            their_block: false,
            rejected_until: 0,
            their_reject_until: 0,
            early_retries: 0,
            deleted_at: 0,
            pair_id: None,
            out_req_id: None,
            in_req_id: None,
            auto_req_pair: None,
            created_at: now,
            friend_since: 0,
            last_contact: 0,
            last_sync_ok: 0,
            last_error: None,
            fail_count: 0,
            next_try: 0,
            info: PeerInfo::default(),
            stats: PeerStats::default(),
            score: Reputation::new(),
            old_version_since: 0,
            malformed: vec![],
            note: String::new(),
            extra: Map::new(),
        }
    }

    /// 成為好友時清掉封鎖 / 拒絕旗標（同 2.1.5）
    fn become_friend(&mut self, pair_id: String, now: u64) {
        self.rel = Rel::Friend;
        self.pair_id = Some(pair_id);
        self.friend_since = now;
        self.out_req_id = None;
        self.in_req_id = None;
        self.my_block = false;
        self.auto_block_at = 0;
        self.their_block = false;
        self.rejected_until = 0;
        self.their_reject_until = 0;
        self.early_retries = 0;
        self.deleted_at = 0;
        self.fail_count = 0;
        self.next_try = 0;
    }

    /// 目前有效的公鑰（輪替期間包含舊的）
    pub fn active_keys(&self, now: u64) -> impl Iterator<Item = &PeerKey> {
        self.keys.iter().filter(move |k| k.until.map(|u| now < u).unwrap_or(true))
    }
}

/// 對方的關係狀態（relation 訊息、請求回應、sync 的非 ok 狀態都用這個）
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct View {
    pub status: String,
    pub pair_id: Option<String>,
    pub until: Option<u64>,
    pub req_id: Option<String>,
}

impl View {
    pub fn of(status: &str) -> View {
        View {
            status: status.to_string(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Follow {
    /// 被對方刪除：自動重新請求一次
    pub re_request: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Start {
    pub ok: bool,
    pub reason: String,
    pub req_id: Option<String>,
    /// 對方也在等我 → 直接同意
    pub accept_incoming: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub at: u64,
    pub domain: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub detail: String,
}

pub fn new_id() -> String {
    hex(&random_bytes::<12>())
}

/// 雙方同時請求：配對編號由兩個請求編號決定（排序後用 | 串起來），兩邊算出來一樣（同 v1）
pub fn joint_pair_id(a: &str, b: &str) -> String {
    let mut v = [a, b];
    v.sort();
    hex(&sha256(&[v.join("|").as_bytes()]))[..24].to_string()
}

/// 不是好友、也不是我主動加的網域（待確認、已拒絕、已刪除）最多留幾筆
pub const MAX_STRANGERS: usize = 300;

/// 自動封鎖（陌生人在拒絕期間一直重送請求、自動規則封鎖）最多留幾筆：滿了先清最舊的自動封鎖。
/// 任何人只要有網域就能觸發（一小時十幾筆），不設上限的話紀錄會一直長
pub const MAX_AUTO_BLOCKS: usize = 300;
/// 自動封鎖幾天後解除（紀錄整筆刪掉；對方再送請求就重新照規則處理）
pub const AUTO_BLOCK_DAYS: u64 = 30;

pub struct PeerStore {
    pub peers: BTreeMap<String, Peer>,
    pub events: Vec<Event>,
    pub reject_days: u64,
}

impl PeerStore {
    pub fn new(reject_days: u32) -> PeerStore {
        PeerStore {
            peers: BTreeMap::new(),
            events: vec![],
            reject_days: reject_days.max(1) as u64,
        }
    }

    pub fn event(&mut self, domain: &str, kind: &str, detail: &str) {
        self.events.push(Event {
            at: now_ms(),
            domain: domain.to_string(),
            kind: kind.to_string(),
            detail: detail.to_string(),
        });
        if self.events.len() > 600 {
            let cut = self.events.len() - 500;
            self.events.drain(..cut);
        }
        if detail.is_empty() {
            info!("社群 {domain}：{kind}");
        } else {
            info!("社群 {domain}：{kind}（{detail}）");
        }
    }

    pub fn get(&self, domain: &str) -> Option<&Peer> {
        self.peers.get(&domain.to_ascii_lowercase())
    }

    pub fn get_mut(&mut self, domain: &str) -> Option<&mut Peer> {
        self.peers.get_mut(&domain.to_ascii_lowercase())
    }

    pub fn ensure(&mut self, domain: &str, now: u64) -> &mut Peer {
        let d = domain.to_ascii_lowercase();
        self.peers.entry(d.clone()).or_insert_with(|| Peer::blank(&d, now))
    }

    /// 陌生人的請求會留下紀錄（待確認、已拒絕…）：有上限，滿了先丟最不重要的。
    /// 好友、我送出的請求、我封鎖的不會被丟。任何人只要有網域就能送請求，沒有上限的話
    /// 紀錄會一直長（記憶體、peers.json、每次寫 Flash 的量）
    fn make_room(&mut self, incoming: &str) {
        let keep = incoming.to_ascii_lowercase();
        let droppable = |p: &Peer| matches!(p.rel, Rel::None | Rel::In) && !p.my_block;
        // 這個網域的紀錄可能已經在了（驗證金鑰時先建立）：算進去，但不會被丟
        let n = self.peers.values().filter(|p| droppable(p)).count() + usize::from(!self.peers.contains_key(&keep));
        if n <= MAX_STRANGERS {
            return;
        }
        // 先丟沒有關係的舊紀錄，再丟最久以前的待確認請求
        let mut list: Vec<(bool, u64, String)> = self
            .peers
            .values()
            .filter(|p| droppable(p) && p.domain != keep)
            .map(|p| (p.rel == Rel::In, p.last_contact.max(p.created_at), p.domain.clone()))
            .collect();
        list.sort();
        for (_, _, d) in list.into_iter().take(n - MAX_STRANGERS) {
            self.peers.remove(&d);
        }
    }

    pub fn friends(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values().filter(|p| p.rel == Rel::Friend)
    }

    pub fn friend_count(&self) -> usize {
        self.friends().count()
    }

    // ---------------- 我這邊發起 ----------------

    /// 我要加對方好友
    pub fn start_request(&mut self, domain: &str, manual: bool, now: u64) -> Start {
        let mut evs = vec![];
        let p = self.ensure(domain, now);
        // 被封鎖後不再自動請求；手動按「加好友」可以再試一次（對方解除封鎖後才會成功）
        if p.their_block && !manual {
            return Start {
                reason: "對方已封鎖你".into(),
                ..Default::default()
            };
        }
        p.their_block = false;
        if p.their_reject_until > now && !manual {
            return Start {
                reason: format!("對方拒絕過，{} 之後才能再請求", fmt_date(p.their_reject_until)),
                ..Default::default()
            };
        }
        if p.rel == Rel::Friend {
            return Start {
                reason: "已經是好友".into(),
                ..Default::default()
            };
        }
        if manual && p.my_block {
            p.my_block = false;
            p.auto_block_at = 0;
            evs.push(("解除封鎖", ""));
        }
        if manual {
            p.deleted_at = 0; // 自己主動加回來，墓碑就不用了
        }
        let out = if p.rel == Rel::In {
            Start {
                ok: true,
                accept_incoming: true,
                ..Default::default()
            }
        } else {
            let was_out = p.rel == Rel::Out;
            p.rel = Rel::Out;
            if p.out_req_id.is_none() {
                p.out_req_id = Some(new_id());
            }
            if manual {
                p.next_try = 0;
            }
            if !was_out {
                evs.push((if manual { "送出好友請求" } else { "自動重新請求" }, ""));
            }
            Start {
                ok: true,
                req_id: p.out_req_id.clone(),
                ..Default::default()
            }
        };
        let d = p.domain.clone();
        for (k, det) in evs {
            self.event(&d, k, det);
        }
        out
    }

    /// 對方回應我的請求（或之後的通知 / 狀態確認）
    pub fn apply_response(&mut self, domain: &str, r: &View, now: u64) -> Follow {
        let reject_days = self.reject_days;
        let Some(p) = self.get_mut(domain) else { return Follow::default() };
        p.last_contact = now;
        let d = p.domain.clone();
        match r.status.as_str() {
            "accepted" => {
                let new_pair = r.pair_id.as_ref().filter(|x| p.pair_id.as_ref() != Some(*x)).is_some();
                if p.rel == Rel::Out || p.rel == Rel::In || (p.rel == Rel::Friend && new_pair) {
                    let pid = r.pair_id.clone().unwrap_or_else(new_id);
                    p.become_friend(pid, now);
                    self.event(&d, "成為好友", "");
                }
            }
            "pending" => {
                // 等對方決定；6 小時後再確認一次（通知可能沒送到）
                p.next_try = now + 6 * HOUR;
            }
            "rejected" => {
                // 本來是好友、對方卻回「已拒絕」：雙方狀態不一致，當成對方不認得我，自動重新請求一次
                if p.rel == Rel::Friend {
                    let v = View {
                        status: "not-friend".into(),
                        pair_id: p.pair_id.clone(),
                        ..Default::default()
                    };
                    return self.apply_response(domain, &v, now);
                }
                p.rel = Rel::None;
                p.out_req_id = None;
                p.pair_id = None;
                p.their_reject_until = (now + HOUR).max(r.until.unwrap_or(now + reject_days * DAY));
                let until = p.their_reject_until;
                self.event(&d, "對方拒絕", &format!("{} 前不再請求", fmt_date(until)));
            }
            "blocked" => {
                p.rel = Rel::None;
                p.out_req_id = None;
                p.pair_id = None;
                p.their_block = true;
                self.event(&d, "對方封鎖了你", "不再請求");
            }
            "deleted" | "not-friend" if p.rel == Rel::Friend && (r.pair_id.is_none() || r.pair_id == p.pair_id) => {
                p.rel = Rel::None;
                let old = p.pair_id.take();
                // 每次被刪只自動重新請求一次；對方刪除後不會自動同意（墓碑），不會循環
                let again = p.auto_req_pair != old;
                if again {
                    p.auto_req_pair = old;
                }
                self.event(&d, "對方已刪除好友", "");
                return Follow { re_request: again };
            }
            _ => {}
        }
        Follow::default()
    }

    // ---------------- 對方發起 ----------------

    /// 收到好友請求（簽名、工作量證明都已驗證過；金鑰比對在呼叫端做）
    /// decide(p) → 自動規則的動作
    pub fn on_request(
        &mut self,
        domain: &str,
        req_id: &str,
        endpoints: Vec<String>,
        info: PeerInfo,
        now: u64,
        decide: impl FnOnce(&Peer, usize) -> crate::rules::Action,
    ) -> View {
        let friend_count = self.friend_count();
        self.make_room(domain);
        let p = self.ensure(domain, now);
        let d = p.domain.clone();
        if p.my_block {
            return View::of("blocked");
        }
        if p.rejected_until > now {
            p.early_retries += 1;
            if p.early_retries >= 3 {
                return self.auto_block(&d, "拒絕期間重複請求", now);
            }
            return View {
                status: "rejected".into(),
                until: Some(p.rejected_until),
                ..Default::default()
            };
        }
        if !endpoints.is_empty() {
            p.endpoints = endpoints;
        }
        p.last_contact = now;
        p.info = info;
        if p.rel == Rel::Friend {
            // 對方遺失狀態時重送：冪等
            return View {
                status: "accepted".into(),
                pair_id: p.pair_id.clone(),
                ..Default::default()
            };
        }
        if p.rel == Rel::Out {
            // 雙方同時請求：直接成為好友
            let pid = joint_pair_id(p.out_req_id.as_deref().unwrap_or(""), req_id);
            p.become_friend(pid.clone(), now);
            self.event(&d, "成為好友", "雙方同時請求");
            return View {
                status: "accepted".into(),
                pair_id: Some(pid),
                ..Default::default()
            };
        }
        p.in_req_id = Some(req_id.to_string());
        if p.rel == Rel::In {
            return View::of("pending");
        }
        p.rel = Rel::In;
        // 我手動刪除過的對象：不套用自動同意，一律人工審核
        let tomb = p.deleted_at > 0;
        let action = if tomb {
            crate::rules::Action::Manual
        } else {
            decide(p, friend_count)
        };
        let detail = if tomb {
            "曾被你刪除，等待人工審核".to_string()
        } else {
            format!("自動規則：{}", action.as_str())
        };
        self.event(&d, "收到好友請求", &detail);
        match action {
            crate::rules::Action::Accept => self.accept(&d, "自動同意", now),
            crate::rules::Action::Reject => self.reject(&d, "自動拒絕", now),
            crate::rules::Action::Block => self.auto_block(&d, "自動封鎖", now),
            crate::rules::Action::Manual => View::of("pending"),
        }
    }

    pub fn accept(&mut self, domain: &str, why: &str, now: u64) -> View {
        let Some(p) = self.get_mut(domain).filter(|p| p.rel == Rel::In) else {
            return View::of("error");
        };
        let pid = new_id();
        p.become_friend(pid.clone(), now);
        let d = p.domain.clone();
        self.event(&d, "成為好友", why);
        View {
            status: "accepted".into(),
            pair_id: Some(pid),
            ..Default::default()
        }
    }

    pub fn reject(&mut self, domain: &str, why: &str, now: u64) -> View {
        let days = self.reject_days;
        let p = self.ensure(domain, now);
        p.rel = Rel::None;
        p.in_req_id = None;
        p.pair_id = None;
        p.early_retries = 0;
        p.rejected_until = now + days * DAY;
        let until = p.rejected_until;
        let d = p.domain.clone();
        self.event(&d, "已拒絕", &format!("{why}，{days} 天內不能再請求"));
        View {
            status: "rejected".into(),
            until: Some(until),
            ..Default::default()
        }
    }

    /// 使用者（或對方行為不當的好友）封鎖：永遠不會被自動清掉。原本是自動封鎖的改成使用者封鎖
    pub fn block(&mut self, domain: &str, why: &str) -> View {
        self.block_inner(domain, why, None)
    }

    /// 自動封鎖（陌生人）：有數量上限，`AUTO_BLOCK_DAYS` 天後解除。已經是使用者封鎖的維持原樣
    pub fn auto_block(&mut self, domain: &str, why: &str, now: u64) -> View {
        let v = self.block_inner(domain, why, Some(now));
        self.cap_auto_blocks(&domain.to_ascii_lowercase());
        v
    }

    fn block_inner(&mut self, domain: &str, why: &str, auto: Option<u64>) -> View {
        let p = self.ensure(domain, auto.unwrap_or_else(now_ms));
        p.rel = Rel::None;
        p.in_req_id = None;
        p.out_req_id = None;
        p.pair_id = None;
        p.auto_block_at = match auto {
            // 使用者已經封鎖的：不降級成自動封鎖
            Some(_) if p.my_block && p.auto_block_at == 0 => 0,
            Some(t) => t.max(1),
            None => 0,
        };
        p.my_block = true;
        let d = p.domain.clone();
        self.event(&d, if auto.is_some() { "已自動封鎖" } else { "已封鎖" }, why);
        View::of("blocked")
    }

    /// 自動封鎖的紀錄（不會是好友或我送出的請求：封鎖時已經清掉關係）
    fn is_auto_blocked(p: &Peer) -> bool {
        p.my_block && p.auto_block_at > 0 && matches!(p.rel, Rel::None | Rel::In)
    }

    /// 自動封鎖超過上限：刪掉最舊的（`keep` 是剛封鎖的這一筆，不刪）
    fn cap_auto_blocks(&mut self, keep: &str) {
        let mut list: Vec<(u64, String)> = self
            .peers
            .values()
            .filter(|p| Self::is_auto_blocked(p))
            .map(|p| (p.auto_block_at, p.domain.clone()))
            .collect();
        if list.len() <= MAX_AUTO_BLOCKS {
            return;
        }
        list.sort();
        let n = list.len() - MAX_AUTO_BLOCKS;
        for (_, d) in list.into_iter().filter(|(_, d)| d != keep).take(n) {
            self.peers.remove(&d);
        }
    }

    /// 每小時：自動封鎖超過 `AUTO_BLOCK_DAYS` 天的解除（整筆刪掉）。回傳刪掉幾筆
    pub fn expire_auto_blocks(&mut self, now: u64) -> usize {
        let limit = now.saturating_sub(AUTO_BLOCK_DAYS * DAY);
        let before = self.peers.len();
        self.peers.retain(|_, p| !(Self::is_auto_blocked(p) && p.auto_block_at < limit));
        let n = before - self.peers.len();
        if n > 0 {
            info!("社群：{n} 筆自動封鎖已滿 {AUTO_BLOCK_DAYS} 天，解除");
        }
        n
    }

    pub fn unblock(&mut self, domain: &str) -> bool {
        let Some(p) = self.get_mut(domain).filter(|p| p.my_block) else {
            return false;
        };
        p.my_block = false;
        p.auto_block_at = 0;
        p.early_retries = 0;
        let d = p.domain.clone();
        self.event(&d, "解除封鎖", "");
        true
    }

    /// 刪除好友。manual = 手動（留墓碑）；自動刪除（例如長期連不上）不留墓碑
    pub fn remove(&mut self, domain: &str, manual: bool, why: &str, now: u64) -> Option<Option<String>> {
        let p = self.get_mut(domain)?;
        let old = p.pair_id.take();
        p.rel = Rel::None;
        p.out_req_id = None;
        p.in_req_id = None;
        if manual {
            p.deleted_at = now;
        }
        let d = p.domain.clone();
        self.event(&d, "已刪除好友", why);
        Some(old)
    }

    /// 已驗證簽名的 relation（對方同意 / 拒絕 / 封鎖 / 刪除了我）
    pub fn on_notify(&mut self, domain: &str, r: &View, now: u64) -> Follow {
        let Some(p) = self.get(domain) else { return Follow::default() };
        let ignore = match r.status.as_str() {
            "accepted" => p.rel != Rel::Out || (r.req_id.is_some() && r.req_id != p.out_req_id),
            // 舊配對的通知：忽略
            "deleted" | "not-friend" => p.rel != Rel::Friend || r.pair_id != p.pair_id,
            // 舊配對的拒絕 / 封鎖不能打壞現在的好友關係
            "rejected" | "blocked" => p.rel == Rel::Friend && r.pair_id.is_some() && r.pair_id != p.pair_id,
            _ => false,
        };
        if ignore {
            return Follow::default();
        }
        self.apply_response(domain, r, now)
    }

    /// 我這邊對對方的看法（sync / relation 的回應）
    pub fn view_of(&self, domain: &str, pair_id: Option<&str>, now: u64) -> View {
        let Some(p) = self.get(domain) else { return View::of("not-friend") };
        if p.my_block {
            return View::of("blocked");
        }
        if p.rel == Rel::Friend && pair_id.is_some() && p.pair_id.as_deref() == pair_id {
            return View {
                status: "accepted".into(),
                pair_id: p.pair_id.clone(),
                ..Default::default()
            };
        }
        if p.rejected_until > now {
            return View {
                status: "rejected".into(),
                until: Some(p.rejected_until),
                ..Default::default()
            };
        }
        if p.rel == Rel::In {
            return View::of("pending");
        }
        View::of("not-friend")
    }

    /// 連線失敗：退避 1h → 2h → … 最長 24h
    pub fn note_failure(&mut self, domain: &str, err: &str, now: u64) {
        if let Some(p) = self.get_mut(domain) {
            p.fail_count += 1;
            p.last_error = Some(crate::util::clip(err, 200));
            p.next_try = now + (1u64 << (p.fail_count - 1).min(5)).min(24) * HOUR;
        }
    }

    pub fn note_success(&mut self, domain: &str, now: u64) {
        if let Some(p) = self.get_mut(domain) {
            p.fail_count = 0;
            p.last_error = None;
            p.last_contact = now;
            p.last_sync_ok = now;
            p.old_version_since = 0;
        }
    }

    /// 長期連不上的好友：刪除（不留墓碑）。對方還在 v1 的不算（最多等 30 天）
    pub fn expire_stale(&mut self, stale_days: u32, now: u64) -> Vec<String> {
        let limit = now.saturating_sub(stale_days as u64 * DAY);
        let gone: Vec<String> = self
            .friends()
            .filter(|p| p.last_contact.max(p.friend_since) < limit)
            .filter(|p| p.old_version_since == 0 || now.saturating_sub(p.old_version_since) > 30 * DAY)
            .map(|p| p.domain.clone())
            .collect();
        for d in &gone {
            self.remove(d, false, &format!("{stale_days} 天無法通訊"), now);
        }
        gone
    }
}

// ---------------- 檔案格式與 v1 遷移（規格 03 第 11 節） ----------------

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeersFile {
    #[serde(default)]
    pub v: u32,
    #[serde(default)]
    pub saved_at: Value,
    #[serde(default)]
    pub peers: BTreeMap<String, Value>,
}

/// v1 的端點（https://網域[:埠]/.well-known/candydns 或 dot://網域:埠）→ v2 端點
fn endpoint_from_v1(ep: &str) -> Option<String> {
    let e = crate::transport::Endpoint::parse(ep)?;
    Some(e.to_string())
}

/// v1 的一筆好友 → v2：關係與旗標照搬、violations 丟掉、tried/ok/fail 換算成初始分數
pub fn migrate_peer(mut v: Value, now: u64) -> Option<Peer> {
    let o = v.as_object_mut()?;
    let pubkey = o.remove("pubkey");
    let endpoint = o.remove("endpoint");
    let stats = o.remove("stats");
    let mut p: Peer = serde_json::from_value(Value::Object(o.clone())).ok()?;
    p.domain = p.domain.to_ascii_lowercase();
    if let Some(raw) = pubkey.as_ref().and_then(Value::as_str).and_then(crate::identity::public_from_v1) {
        p.keys = vec![PeerKey {
            kid: hex(&crate::identity::kid_of(&raw)),
            public: crate::util::b64(&raw),
            since: p.created_at,
            until: None,
        }];
    }
    if let Some(e) = endpoint.as_ref().and_then(Value::as_str).and_then(endpoint_from_v1) {
        p.endpoints = vec![e];
    }
    let s = stats.unwrap_or(Value::Null);
    let n = |k: &str| s.get(k).and_then(Value::as_f64).unwrap_or(0.0).max(0.0) as u32;
    p.stats = PeerStats {
        offered: n("offered"),
        ..Default::default()
    };
    // v1 的命中率是「好友給的網站提示在我這邊驗證成功的比例」→ 換算成 site 的初始分數
    let (ok, fail) = (n("ok"), n("fail"));
    if ok + fail > 0 {
        let e = crate::score::entry(&mut p.score, crate::score::Kind::Site);
        e.add(crate::score::Outcome::Ok, ok, now);
        e.add(crate::score::Outcome::Fail, fail, now);
    }
    Some(p)
}

/// 讀 peers.json：v2 直接讀；v1 轉換（回傳 true 表示做過遷移）
pub fn load_peers(bytes: &[u8], now: u64) -> (BTreeMap<String, Peer>, bool) {
    let Ok(f) = serde_json::from_slice::<PeersFile>(bytes) else {
        return (BTreeMap::new(), false);
    };
    let v1 = f.v < 2;
    let mut out = BTreeMap::new();
    for (k, v) in f.peers {
        let p = if v1 {
            migrate_peer(v, now)
        } else {
            serde_json::from_value::<Peer>(v).ok()
        };
        if let Some(mut p) = p {
            if p.domain.is_empty() {
                p.domain = k.to_ascii_lowercase();
            }
            out.insert(p.domain.clone(), p);
        }
    }
    (out, v1)
}

pub fn save_peers(peers: &BTreeMap<String, Peer>, now: u64) -> Vec<u8> {
    let f = PeersFile {
        v: 2,
        saved_at: Value::from(now),
        peers: peers
            .iter()
            .map(|(k, p)| (k.clone(), serde_json::to_value(p).unwrap_or(Value::Null)))
            .collect(),
    };
    serde_json::to_vec_pretty(&f).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Action;

    fn store() -> PeerStore {
        PeerStore::new(7)
    }

    #[test]
    fn strangers_are_capped() {
        let mut s = store();
        let now = 1_000 * DAY;
        // 好友、我封鎖的、我送出的請求：不會被擠掉
        s.on_request("friend.test", "r", vec![], PeerInfo::default(), now, |_, _| Action::Accept);
        assert_eq!(s.get("friend.test").unwrap().rel, Rel::Friend);
        s.block("blocked.test", "手動");
        s.ensure("out.test", now).rel = Rel::Out;
        for i in 0..(MAX_STRANGERS + 50) {
            let r = s.on_request(
                &format!("s{i}.flood.test"),
                "r",
                vec![],
                PeerInfo::default(),
                now + i as u64,
                |_, _| Action::Manual,
            );
            assert_eq!(r.status, "pending");
        }
        assert_eq!(s.peers.len(), MAX_STRANGERS + 3);
        assert!(s.get("friend.test").is_some() && s.get("out.test").is_some());
        assert!(s.get("blocked.test").unwrap().my_block);
        assert!(s.get("s0.flood.test").is_none(), "最舊的先丟");
        assert!(s.get(&format!("s{}.flood.test", MAX_STRANGERS + 49)).is_some());
        // 已經有紀錄的網域再送一次：不會擠掉別人
        s.on_request("s100.flood.test", "r", vec![], PeerInfo::default(), now, |_, _| Action::Manual);
        assert_eq!(s.peers.len(), MAX_STRANGERS + 3);
        // 紀錄先建立了（驗證金鑰時）再處理請求：一樣守住上限，而且不會丟掉正在處理的這一筆
        s.ensure("late.flood.test", 1);
        s.on_request("late.flood.test", "r", vec![], PeerInfo::default(), now, |_, _| Action::Manual);
        assert_eq!(s.peers.len(), MAX_STRANGERS + 3);
        assert_eq!(s.get("late.flood.test").unwrap().rel, Rel::In);
    }

    #[test]
    fn request_accept_pending_flow() {
        let mut s = store();
        let now = 1_000 * DAY;
        let r = s.on_request("a.test", "r1", vec![], PeerInfo::default(), now, |_, _| Action::Manual);
        assert_eq!(r.status, "pending");
        assert_eq!(s.get("a.test").unwrap().rel, Rel::In);
        // 再送一次：仍是 pending，不產生新事件
        let n = s.events.len();
        assert_eq!(
            s.on_request("a.test", "r1", vec![], PeerInfo::default(), now, |_, _| Action::Accept)
                .status,
            "pending"
        );
        assert_eq!(s.events.len(), n);
        let a = s.accept("a.test", "手動同意", now);
        assert_eq!(a.status, "accepted");
        let p = s.get("a.test").unwrap();
        assert_eq!(p.rel, Rel::Friend);
        assert_eq!(p.pair_id, a.pair_id);
        // 好友再送請求：冪等
        assert_eq!(
            s.on_request("a.test", "r2", vec![], PeerInfo::default(), now, |_, _| Action::Manual)
                .pair_id,
            a.pair_id
        );
    }

    #[test]
    fn auto_blocks_are_capped_and_expire() {
        let mut s = store();
        let now = 1_000 * DAY;
        s.block("user.test", "手動");
        // 使用者封鎖過的再被自動封鎖：仍是使用者封鎖
        s.auto_block("user.test", "自動封鎖", now);
        assert_eq!(s.get("user.test").unwrap().auto_block_at, 0);
        // 拒絕期間重送三次 → 自動封鎖（有標記）
        s.on_request("r.test", "r1", vec![], PeerInfo::default(), now, |_, _| Action::Manual);
        s.reject("r.test", "手動拒絕", now);
        for _ in 0..3 {
            s.on_request("r.test", "r1", vec![], PeerInfo::default(), now + 1, |_, _| Action::Accept);
        }
        let r = s.get("r.test").unwrap();
        assert!(r.my_block);
        assert_eq!(r.auto_block_at, now + 1);
        // 自動規則封鎖也有標記；洪水般的自動封鎖只留最新的 MAX_AUTO_BLOCKS 筆
        for i in 0..(MAX_AUTO_BLOCKS + 20) {
            let v = s.on_request(
                &format!("a{i}.flood.test"),
                "r",
                vec![],
                PeerInfo::default(),
                now + 10 + i as u64,
                |_, _| Action::Block,
            );
            assert_eq!(v.status, "blocked");
        }
        let auto = s.peers.values().filter(|p| p.my_block && p.auto_block_at > 0).count();
        assert_eq!(auto, MAX_AUTO_BLOCKS);
        assert!(s.get("r.test").is_none(), "最舊的自動封鎖先清");
        assert!(s.get("a0.flood.test").is_none());
        assert!(s.get(&format!("a{}.flood.test", MAX_AUTO_BLOCKS + 19)).unwrap().my_block);
        assert!(s.get("user.test").unwrap().my_block, "使用者封鎖不會被清掉");

        // 存檔讀回：標記保留；舊版檔案（沒有這個欄位）的封鎖當成使用者封鎖
        let (back, _) = load_peers(&save_peers(&s.peers, now), now);
        assert_eq!(
            back[&format!("a{}.flood.test", MAX_AUTO_BLOCKS + 19)].auto_block_at,
            now + 10 + (MAX_AUTO_BLOCKS + 19) as u64
        );
        assert_eq!(back["user.test"].auto_block_at, 0);
        let user_json = serde_json::to_value(&s.peers["user.test"]).unwrap();
        assert!(user_json.get("autoBlockAt").is_none(), "使用者封鎖的格式跟舊版一樣");

        // 30 天後自動封鎖解除，使用者封鎖留著
        assert_eq!(s.expire_auto_blocks(now + 29 * DAY), 0);
        assert_eq!(s.expire_auto_blocks(now + AUTO_BLOCK_DAYS * DAY + 10_000), MAX_AUTO_BLOCKS);
        assert!(s.get("user.test").unwrap().my_block);
        assert_eq!(
            s.on_request("a5.flood.test", "r", vec![], PeerInfo::default(), now + 31 * DAY, |_, _| {
                Action::Manual
            })
            .status,
            "pending",
            "解除後重新照規則處理"
        );
        // 使用者手動封鎖自動封鎖的對象：改成使用者封鎖
        s.auto_block("x.test", "自動封鎖", now);
        s.block("x.test", "手動");
        assert_eq!(s.get("x.test").unwrap().auto_block_at, 0);
    }

    #[test]
    fn reject_then_early_retry_blocks() {
        let mut s = store();
        let now = 1_000 * DAY;
        s.on_request("a.test", "r1", vec![], PeerInfo::default(), now, |_, _| Action::Manual);
        let r = s.reject("a.test", "手動拒絕", now);
        assert_eq!(r.until, Some(now + 7 * DAY));
        for _ in 0..2 {
            assert_eq!(
                s.on_request("a.test", "r1", vec![], PeerInfo::default(), now, |_, _| Action::Accept)
                    .status,
                "rejected"
            );
        }
        assert_eq!(
            s.on_request("a.test", "r1", vec![], PeerInfo::default(), now, |_, _| Action::Accept)
                .status,
            "blocked"
        );
        assert!(s.get("a.test").unwrap().my_block);
        // 解除封鎖後 7 天過了才能再請求
        assert!(s.unblock("a.test"));
        assert_eq!(
            s.on_request("a.test", "r1", vec![], PeerInfo::default(), now + 8 * DAY, |_, _| Action::Accept)
                .status,
            "accepted"
        );
    }

    #[test]
    fn simultaneous_requests_same_pair() {
        let (mut a, mut b) = (store(), store());
        let now = 5 * DAY;
        let ra = a.start_request("b.test", true, now).req_id.unwrap();
        let rb = b.start_request("a.test", true, now).req_id.unwrap();
        let va = a.on_request("b.test", &rb, vec![], PeerInfo::default(), now, |_, _| Action::Manual);
        let vb = b.on_request("a.test", &ra, vec![], PeerInfo::default(), now, |_, _| Action::Manual);
        assert_eq!(va.status, "accepted");
        assert_eq!(va.pair_id, vb.pair_id);
    }

    #[test]
    fn deleted_rerequest_once_and_tombstone() {
        let (mut a, mut b) = (store(), store());
        let now = 10 * DAY;
        a.start_request("b.test", true, now);
        b.on_request("a.test", "r", vec![], PeerInfo::default(), now, |_, _| Action::Accept);
        let pid = b.get("a.test").unwrap().pair_id.clone();
        a.apply_response(
            "b.test",
            &View {
                status: "accepted".into(),
                pair_id: pid.clone(),
                ..Default::default()
            },
            now,
        );
        assert_eq!(a.get("b.test").unwrap().rel, Rel::Friend);
        // B 手動刪除 A（墓碑）→ 通知 A
        let old = b.remove("a.test", true, "手動刪除", now).unwrap();
        let f = a.on_notify(
            "b.test",
            &View {
                status: "deleted".into(),
                pair_id: old.clone(),
                ..Default::default()
            },
            now,
        );
        assert!(f.re_request);
        assert_eq!(a.get("b.test").unwrap().rel, Rel::None);
        // 舊配對的通知再來一次：忽略
        assert!(
            !a.on_notify(
                "b.test",
                &View {
                    status: "deleted".into(),
                    pair_id: old,
                    ..Default::default()
                },
                now
            )
            .re_request
        );
        // A 重新請求 → B 有墓碑，不套用自動同意
        let st = a.start_request("b.test", false, now);
        assert!(st.ok);
        let v = b.on_request("a.test", "r2", vec![], PeerInfo::default(), now, |_, _| Action::Accept);
        assert_eq!(v.status, "pending");
        assert!(b.events.last().unwrap().detail.contains("曾被你刪除"));
    }

    #[test]
    fn their_block_and_reject_gate_auto_requests() {
        let mut a = store();
        let now = 10 * DAY;
        a.start_request("b.test", true, now);
        a.apply_response(
            "b.test",
            &View {
                status: "rejected".into(),
                until: Some(now + 7 * DAY),
                ..Default::default()
            },
            now,
        );
        assert!(!a.start_request("b.test", false, now).ok);
        // 手動新增不受 theirRejectUntil 限制
        assert!(a.start_request("b.test", true, now).ok);
        a.apply_response("b.test", &View::of("blocked"), now);
        let r = a.start_request("b.test", false, now);
        assert!(!r.ok && r.reason.contains("封鎖"));
        assert!(a.start_request("b.test", true, now).ok);
    }

    #[test]
    fn stale_friends_removed_without_tombstone() {
        let mut s = store();
        let now = 100 * DAY;
        let p = s.ensure("old.test", now);
        p.rel = Rel::Friend;
        p.pair_id = Some("x".into());
        p.friend_since = now - 30 * DAY;
        p.last_contact = now - 8 * DAY;
        let q = s.ensure("v1.test", now);
        q.rel = Rel::Friend;
        q.friend_since = now - 30 * DAY;
        q.old_version_since = now - 10 * DAY;
        assert_eq!(s.expire_stale(7, now), vec!["old.test".to_string()]);
        assert_eq!(s.get("old.test").unwrap().rel, Rel::None);
        assert_eq!(s.get("old.test").unwrap().deleted_at, 0);
    }

    #[test]
    fn rejected_while_friend_means_not_friend() {
        let mut s = store();
        let now = 10 * DAY;
        let p = s.ensure("b.test", now);
        p.rel = Rel::Friend;
        p.pair_id = Some("p1".into());
        let f = s.apply_response("b.test", &View::of("rejected"), now);
        assert!(f.re_request);
        assert_eq!(s.get("b.test").unwrap().rel, Rel::None);
    }
}
