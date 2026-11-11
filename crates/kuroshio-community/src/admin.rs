//! 管理 API（規格 03 第 10 節）：`/api/community/*` 的回應格式沿用 2.x，v2 多的欄位與路徑另外加

use crate::identity::fingerprint;
use crate::node::Community;
use crate::peers::{Peer, Rel};
use crate::score::Kind;
use crate::util::{b64, hex, now_ms, unb64};
use serde_json::{json, Value};
use std::collections::HashMap;

fn nz(x: u64) -> Value {
    if x == 0 {
        Value::Null
    } else {
        json!(x)
    }
}

/// v1 的公鑰格式（base64 SPKI DER），LuCI 與 2.x 顯示用
fn spki_b64(public: &[u8]) -> String {
    let mut der = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    der.extend_from_slice(public);
    b64(&der)
}

impl Community {
    /// 路由：`path` = `/api/community/<名稱>`，`q` = 查詢參數；不是社群路徑回 None
    pub async fn admin(&self, path: &str, q: &HashMap<String, String>) -> Option<Value> {
        let name = path.strip_prefix("/api/community/")?;
        let d = q.get("domain").map(|s| s.trim().to_ascii_lowercase()).unwrap_or_default();
        let flag = |k: &str| q.get(k).map(|v| v == "1" || v == "true").unwrap_or(false);
        Some(match name {
            "status" => self.status(),
            "peers" => self.peers_json(),
            "events" => self.events_json(),
            "check" => self.check().await,
            "add" => self.send_request(&d, true).await,
            "accept" => self.decide(&d, "accept").await,
            "reject" => self.decide(&d, "reject").await,
            "block" if flag("remove") => self.remove_friend(&d, true).await,
            "block" => self.decide(&d, "block").await,
            "unblock" => self.unblock(&d),
            "delete" => self.remove_friend(&d, flag("block")).await,
            "sync" => self.sync_peer(&d).await,
            "rotate" => self.rotate(),
            "accept-key" => self.accept_key(&d),
            "scores" => self.scores_json(),
            "channel" => match q.get("channel") {
                Some(c) => self.set_channel(&d, c),
                None => self
                    .peer(&d)
                    .map(|p| json!({ "ok": true, "channel": p.channel, "prefer": p.prefer_channel }))
                    .unwrap_or(json!({ "ok": false, "reason": "沒有這個對象" })),
            },
            _ => return None,
        })
    }

    pub fn status(&self) -> Value {
        let cfg = self.config();
        let now = now_ms();
        let id = self.ident.read().unwrap();
        let keys: Vec<Value> = id
            .keys(now)
            .iter()
            .map(|k| json!({ "kid": hex(&k.kid), "fingerprint": fingerprint(&k.public), "since": k.since, "current": k.kid == id.key.kid }))
            .collect();
        let rotation = id
            .rotation
            .as_ref()
            .map(|r| json!({ "at": r.at, "oldKid": r.old_kid, "until": r.at + crate::identity::ROTATE_OVERLAP_MS }));
        let (fp, public, kid, txt) = (id.key.fingerprint(), spki_b64(&id.key.public), hex(&id.key.kid), id.txt_value());
        drop(id);
        let check = self.check_json();
        let st = self.lock();
        let peers: Vec<&Peer> = st.store.peers.values().collect();
        let count = |f: &dyn Fn(&&Peer) -> bool| peers.iter().filter(|p| f(p)).count();
        let mut site_keys = std::collections::HashSet::new();
        let mut cross_keys = std::collections::HashSet::new();
        let mut nodes = 0usize;
        for r in st.remote.values() {
            for x in r.recs.values() {
                match x.kind.as_str() {
                    "site" => {
                        site_keys.insert(x.key.clone());
                    }
                    "cross" => {
                        cross_keys.insert(x.key.clone());
                    }
                    "node" => nodes += 1,
                    _ => {}
                }
            }
        }
        json!({
            "enabled": cfg.enabled, "ready": st.check.ready, "check": check, "domain": cfg.domain,
            "fingerprint": fp, "publicKey": public, "kid": kid, "keys": keys, "rotation": rotation,
            "txt": { "name": format!("_kuroshio.{}", cfg.domain), "value": txt },
            "endpoints": self.endpoints_json(&cfg), "proto": [crate::envelope::PROTO],
            "externalConfirmed": st.last_inbound.as_ref().map(|(f, a)| json!({ "from": f, "at": a })),
            "counts": {
                "friends": count(&|p| p.rel == Rel::Friend), "incoming": count(&|p| p.rel == Rel::In),
                "outgoing": count(&|p| p.rel == Rel::Out), "blocked": count(&|p| p.my_block),
                "pendingKeys": count(&|p| p.pending_key.is_some()),
            },
            "hints": { "domains": site_keys.len(), "cross": cross_keys.len(), "nodes": nodes, "upstreams": crate::client::upstream_ids(&st).len() },
            "share": { "epoch": hex(&st.share.epoch), "seq": st.share.seq, "records": st.share.len() },
        })
    }

    fn peer_json(&self, p: &Peer, shared: Option<u64>, now: u64) -> Value {
        let scores: serde_json::Map<String, Value> = Kind::ALL
            .iter()
            .map(|k| {
                let s = p.score.get(k.as_str()).cloned().unwrap_or_default();
                let (ok, fail, inv) = s.totals(now);
                (k.as_str().to_string(), json!({ "score": (s.score(now) * 1000.0).round() / 1000.0, "ok": ok, "fail": fail, "invalid": inv, "paused": s.paused }))
            })
            .collect();
        // v1 的命中率欄位（tried / ok / fail）：用網站提示的分數換算，LuCI 舊版也能顯示
        let site = p.score.get("site").cloned().unwrap_or_default().totals(now);
        let current = p.active_keys(now).last().map(|k| k.public.clone());
        let keys: Vec<Value> = p
            .keys
            .iter()
            .map(|k| json!({ "kid": k.kid, "fingerprint": unb64(&k.public).map(|b| fingerprint(&b)), "since": k.since, "until": k.until }))
            .collect();
        json!({
            "domain": p.domain, "rel": p.rel.as_str(), "myBlock": p.my_block, "theirBlock": p.their_block,
            "rejectedUntil": nz(p.rejected_until), "theirRejectUntil": nz(p.their_reject_until), "deletedAt": nz(p.deleted_at),
            "fingerprint": current.and_then(|c| unb64(&c)).map(|b| fingerprint(&b)),
            "endpoint": p.endpoints.first(), "endpoints": p.endpoints, "channel": p.channel, "preferChannel": p.prefer_channel,
            "info": p.info, "ipMatch": p.info.ip_match, "hasTxt": p.info.has_txt, "proto": p.info.proto,
            "stats": { "offered": p.stats.offered, "invalid": p.stats.invalid, "tried": site.0 + site.1, "ok": site.0, "fail": site.1 },
            "scores": scores, "keys": keys,
            "pendingKey": p.pending_key.as_ref().map(|k| json!({ "kid": k.kid, "fingerprint": unb64(&k.public).map(|b| fingerprint(&b)) })),
            "oldVersion": p.old_version_since != 0, "oldVersionSince": nz(p.old_version_since),
            "friendSince": nz(p.friend_since), "lastContact": nz(p.last_contact), "lastSyncOk": nz(p.last_sync_ok),
            "lastError": p.last_error, "nextTry": nz(p.next_try), "shared": shared, "note": p.note,
        })
    }

    pub fn peers_json(&self) -> Value {
        let now = now_ms();
        let st = self.lock();
        let order = |r: Rel| match r {
            Rel::In => 0,
            Rel::Friend => 1,
            Rel::Out => 2,
            Rel::None => 3,
        };
        let mut v: Vec<&Peer> = st.store.peers.values().collect();
        v.sort_by(|a, b| order(a.rel).cmp(&order(b.rel)).then(a.domain.cmp(&b.domain)));
        Value::Array(
            v.into_iter()
                .map(|p| self.peer_json(p, st.remote.get(&p.domain).map(|r| r.updated), now))
                .collect(),
        )
    }

    pub fn events_json(&self) -> Value {
        serde_json::to_value(self.events()).unwrap_or(Value::Array(vec![]))
    }

    /// 各好友、各 kind 的資料品質分數
    pub fn scores_json(&self) -> Value {
        let now = now_ms();
        let min = self.config().min_hit_rate;
        let st = self.lock();
        let peers: Vec<Value> = st
            .store
            .friends()
            .map(|p| {
                let kinds: serde_json::Map<String, Value> = Kind::ALL
                    .iter()
                    .map(|k| {
                        let s = p.score.get(k.as_str()).cloned().unwrap_or_default();
                        let (ok, fail, inv) = s.totals(now);
                        let held = st.remote.get(&p.domain).map(|r| r.count(*k)).unwrap_or(0);
                        (
                            k.as_str().to_string(),
                            json!({ "score": s.score(now), "ok": ok, "fail": fail, "invalid": inv, "tries": ok + fail + inv,
                                    "paused": s.paused, "pausedAt": nz(s.paused_at), "lastRetry": nz(s.last_retry), "records": held }),
                        )
                    })
                    .collect();
                json!({ "domain": p.domain, "kinds": kinds })
            })
            .collect();
        json!({ "minHitRate": min, "windowDays": crate::score::WINDOW_DAYS, "minTries": crate::score::MIN_TRIES, "peers": peers })
    }
}
