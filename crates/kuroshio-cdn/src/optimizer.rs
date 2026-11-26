//! CDN 改寫（對齊 2.x `lib/cdn/optimizer.js`）：把繞國外的 CDN 位址換成台北 / 高雄節點
//!  - 未驗證：先回原始結果（`trialMode: original`）、TTL 10 秒，背景驗證
//!  - 驗證通過：照換，TTL 用原始 TTL
//!  - 驗證失敗：回原始 IP 與原始 TTL
//!  - IPv6：有台灣 v6 節點就換，沒有就丟棄該 CDN 的 AAAA（可設定）
//!  - HTTPS 記錄（type 65）的 ipv4hint / ipv6hint 一起改
//!
//! 另外提供解析流程要用的「機會成本基準」（`baseline`）、「固定上游自帶的優選 IP」（`pinned_alias`）
//! 與「這次回應有沒有拉回台灣」（`route`）。

use crate::cdn::{normalize, Cdn, State, Task};
use crate::db::{Domain, Policy, Strategy};
use crate::pools::{Classifier, Cls, Pools};
use crate::providers::{self, provider_by_cname};
use crate::svcb::{self, Hint};
use crate::util::{self, now_ms};
use kuroshio_proto::logic::terminal_name;
use kuroshio_proto::message::{rtype, Message, RData, Record};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rewrite {
    Alias,
    Ecs,
    Cross,
}

impl Rewrite {
    pub fn as_str(self) -> &'static str {
        match self {
            Rewrite::Alias => "alias",
            Rewrite::Ecs => "ecs",
            Rewrite::Cross => "cross",
        }
    }
}

/// `apply()` 的結果
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApplyResult {
    /// TTL 上限（未驗證時 10 秒）
    pub ttl_cap: Option<u32>,
    /// 給查詢紀錄看的標記（`CF→TW`、`CF:驗證中→原始`…）
    pub tags: Vec<String>,
    /// 認出來的 CDN
    pub provider: Option<&'static str>,
    pub rewritten: Option<Rewrite>,
    pub cross_to: Option<String>,
    /// 改寫後預估省下的毫秒
    pub gain_ms: Option<f64>,
}

/// 驗證狀態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VState {
    Ok,
    Fail,
    Trial,
}

fn ip_of(r: &Record) -> Option<IpAddr> {
    match r.data {
        RData::A(ip) => Some(IpAddr::V4(ip)),
        RData::Aaaa(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    }
}

/// 查詢名稱的第一個 CNAME 目標的鍵（`db::c1_key`）；沒有 CNAME 回空字串。不配置記憶體
fn first_cname_key<'a>(msg: &'a Message, name: &str) -> &'a str {
    msg.answers
        .iter()
        .find(|a| a.rtype == rtype::CNAME && a.name.trim_end_matches('.').eq_ignore_ascii_case(name))
        .and_then(|a| a.target())
        .map(crate::db::c1_key)
        .unwrap_or("")
}

fn is_svcb(r: &Record) -> bool {
    r.rtype == rtype::HTTPS || r.rtype == rtype::SVCB
}

fn label_of(provider: &str) -> String {
    match provider {
        "cloudflare" => "CF".into(),
        "cloudfront" => "CFR".into(),
        p => p.to_uppercase().chars().take(6).collect(),
    }
}

fn fmt0(x: f64) -> String {
    format!("{:.0}", x)
}

/// 用 `ips` 取代 `rtype` 中符合 `is_target` 的記錄（擁有者名稱與 TTL 用第一筆的）
fn replace(msg: &mut Message, rt: u16, ips: &[IpAddr], is_target: impl Fn(IpAddr) -> bool) {
    let first = msg
        .answers
        .iter()
        .find(|a| a.rtype == rt && ip_of(a).map(&is_target).unwrap_or(false));
    let Some(first) = first else { return };
    let (owner, ttl) = (first.name.clone(), first.ttl);
    msg.answers
        .retain(|a| !(a.rtype == rt && ip_of(a).map(&is_target).unwrap_or(false)));
    for ip in ips {
        match (rt, ip) {
            (rtype::A, IpAddr::V4(v)) => msg.answers.push(Record::a(&owner, ttl, *v)),
            (rtype::AAAA, IpAddr::V6(v)) => msg.answers.push(Record::aaaa(&owner, ttl, *v)),
            _ => {}
        }
    }
}

fn drop_provider(msg: &mut Message, rt: u16, pools: &Pools, provider: &str) {
    msg.answers.retain(|a| {
        !(a.rtype == rt
            && ip_of(a)
                .and_then(|ip| pools.classify(ip))
                .map(|c| c.provider == provider)
                .unwrap_or(false))
    });
}

/// 解析流程的「機會成本基準」：一般 DNS（固定上游以外）原本會給的 CDN 位址在不在台灣
#[derive(Debug, Clone, PartialEq)]
pub struct Baseline {
    pub provider: &'static str,
    pub abroad: bool,
    pub ms: Option<f64>,
}

/// 這次回應的路由統計（2.x 的 `stats.route()` 的參數）
#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    pub provider: String,
    pub abroad: bool,
    pub tw: bool,
    pub saved_ms: Option<f64>,
}

impl Cdn {
    /// 這個網域 / 家族目前的狀態
    fn vstate(pools: &Pools, entry: Option<&Domain>, family: u8, now: u64) -> VState {
        let Some(e) = entry else { return VState::Trial };
        if e.policy() == Policy::Always {
            return VState::Ok;
        }
        if let Some(v) = e.verdict(family) {
            if v.valid(now) {
                if v.is("ok") {
                    return VState::Ok;
                }
                if v.is("fail") {
                    // 舊版只試一個 IP 就判失敗；若當時那個 IP 後來確認是「特定產品專用」，重新驗證一次。
                    // 「比原本慢」（3.5.0 E7）不是這種失敗：照到期時間重測，不因此每次查詢都重新驗證
                    let restricted = match (v.ip, e.provider()) {
                        (Some(ip), Some(p)) => {
                            !v.reason.as_deref().unwrap_or("").contains("試了")
                                && v.extra.get(crate::verifier::SLOWER).is_none()
                                && v.extra.get(crate::verifier::ORIG_TW).is_none()
                                && pools.is_restricted(p, ip)
                        }
                        _ => false,
                    };
                    return if restricted { VState::Trial } else { VState::Fail };
                }
            }
        }
        VState::Trial
    }

    /// 這個回應是哪家 CDN（只判斷、不改寫、不排背景工作；串接上游給的答案用，3.4.1）
    pub fn provider_of(&self, msg: &Message, qtype: u16) -> Option<&'static str> {
        if !self.cfg.enabled || msg.answers.is_empty() {
            return None;
        }
        if qtype != rtype::A && qtype != rtype::AAAA && qtype != rtype::HTTPS {
            return None;
        }
        self.with_classifier(|c| Self::detect(c, msg)).map(|(p, _)| p)
    }

    /// 找出這個回應屬於哪家 CDN（IP 範圍優先，再看 CNAME 鏈最末端）
    /// 每個 A / AAAA / HTTPS 回應都會跑（絕大多數不是 CDN）：不拿狀態鎖、不配置記憶體
    fn detect(cls: &Classifier, msg: &Message) -> Option<(&'static str, &'static str)> {
        if let Some(c) = msg.answers.iter().filter_map(ip_of).find_map(|ip| cls.classify(ip)) {
            return Some((c.provider, "ip"));
        }
        for a in msg.answers.iter().filter(|a| is_svcb(a)) {
            if let RData::Raw(d) = &a.data {
                let (v4, v6) = svcb::hints(d);
                let mut ips = v4.into_iter().map(IpAddr::V4).chain(v6.into_iter().map(IpAddr::V6));
                if let Some(c) = ips.find_map(|ip| cls.classify(ip)) {
                    return Some((c.provider, "ip"));
                }
            }
        }
        msg.answers
            .iter()
            .rev()
            .filter(|a| a.rtype == rtype::CNAME)
            .filter_map(|a| a.target())
            .find_map(provider_by_cname)
            .map(|p| (p, "cname"))
    }

    /// 回給用戶端的 IP 中最快的延遲（測速快取或節點池紀錄）
    pub fn served_ms(&self, provider: &str, ips: &[IpAddr]) -> Option<f64> {
        let st = self.state();
        self.served_ms_in(&st.pools, provider, ips)
    }

    fn served_ms_in(&self, pools: &Pools, provider: &str, ips: &[IpAddr]) -> Option<f64> {
        let d = pools.p.get(provider);
        let mut best = f64::INFINITY;
        for ip in ips {
            let mut ms = self.net.cached(*ip).filter(|c| c.ok).map(|c| c.ms);
            if ms.is_none() {
                if let Some(d) = d {
                    if let Some(x) = d
                        .pool4
                        .iter()
                        .find(|p| p.ip == *ip)
                        .or_else(|| d.pool6.iter().find(|p| p.ip == *ip))
                    {
                        if x.ms.truthy() {
                            ms = x.ms.get();
                        }
                    }
                }
            }
            if let Some(m) = ms {
                if m < best {
                    best = m;
                }
            }
        }
        best.is_finite().then_some(best)
    }

    /// 在送出回應前呼叫（`msg` 是可以修改的副本）。`qtype` 只處理 A / AAAA / HTTPS
    pub fn apply(self: &Arc<Self>, msg: &mut Message, qname: &str, qtype: u16) -> ApplyResult {
        let mut res = ApplyResult::default();
        if !self.cfg.enabled || msg.answers.is_empty() {
            return res;
        }
        if qtype != rtype::A && qtype != rtype::AAAA && qtype != rtype::HTTPS {
            return res;
        }
        // 先用唯讀快照判斷是不是 CDN：不是（絕大多數的回應）就直接回去，不碰狀態鎖
        let Some((provider, via)) = self.with_classifier(|c| Self::detect(c, msg)) else {
            return res;
        };
        // 3.5.0 F11：內建一定通過的服務（時間同步、連線偵測、憑證撤銷、地震速報）不改寫——不驗證、不跨 CDN、不做 ECS，
        // 也不記進網域資料庫，只辨識、算一次統計就回去（判斷錯誤的最壞情況是「跟沒有黑潮一樣」）。
        // 只在已經判斷是 CDN 的回應上比對靜態後綴表：不配置、沒有鎖。`filter.protectComm` 關掉時不比對
        if crate::cdn::keep_untouched(qname) {
            res.provider = Some(provider);
            res.tags.push("內建服務:不改寫".into());
            self.note_essential_kept();
            return res;
        }
        let name = normalize(qname);
        // 記憶體控制移出的冷資料：查到時從磁碟讀回來（沒有移出任何網域時不做任何事）
        self.ensure_loaded(&name);
        let cname = terminal_name(msg, &name);
        // 第一層 CNAME 的鍵（3.5.0 B3）：只對已經判斷是 CDN 的回應做，切片比對、不配置
        // （鍵最長 C1_MAX 位元組，抄到堆疊上：下面要改 `msg`，不能一直借著它）
        let mut c1_buf = [0u8; crate::db::C1_MAX];
        let c1_len = {
            let k = first_cname_key(msg, &name);
            c1_buf[..k.len()].copy_from_slice(k.as_bytes());
            k.len()
        };
        let c1 = std::str::from_utf8(&c1_buf[..c1_len]).unwrap_or("");
        let mut tasks: Vec<Task> = Vec::new();
        let first_seen;
        {
            let mut st = self.state();
            let st = &mut *st;
            // 3.5.1 K4：先不收新網域（記憶體不能長大、或筆數超過磁碟預算的 2 倍）：照上游的答案回、不記、不排驗證。
            // 已經記著的網域照常；記憶體回來、淘汰追上之後自己恢復。
            // 3.5.1 H1：筆數接近 `cdn.maxEntries`（90%）時，新網域問第二次才記
            if let Err(why) = self.admits(st, &name) {
                st.stats.new_held = st.stats.new_held.saturating_add(1);
                res.provider = Some(provider);
                res.tags.push(why.into());
                return res;
            }
            self.apply_locked(st, msg, &name, qtype, provider, via, &cname, c1, &mut res, &mut tasks);
            // 小機器減量（3.4.2）：只問過一次的網域先不驗證（剛註冊、只出現一次的網域不值得驗）。
            // 答案照樣是原始結果、試用期 TTL 10 秒，真的有人在用的話很快會再問，那時才排驗證。
            // 3.5.0 F12：新網域很多（減量中）時所有機器都套用，而且它的 ECS 探測、節點延遲量測、跨 CDN 探索也一起不排
            // （都是為了一個可能再也不會出現的網域對外發請求）。`cdn.lite` 永遠在減量。查詢路徑只多讀一個 AtomicBool
            first_seen = st.db.get(&name).map_or(0, |e| e.hits) < 2;
            if first_seen && self.pacing_first_seen() {
                let before = tasks.len();
                let mut verifies = 0u32;
                tasks.retain(|t| match t {
                    Task::Verify { name: n, .. } if *n == name => {
                        verifies += 1;
                        false
                    }
                    Task::Ecs { name: n, .. } | Task::Cross { name: n, .. } if *n == name => false,
                    Task::Latency(_) => false,
                    _ => true,
                });
                if self.cfg.lite {
                    st.stats.lite_waited += verifies;
                }
                if tasks.len() != before {
                    self.note_pace_waited();
                }
            } else if first_seen && self.cfg.lite {
                let before = tasks.len();
                tasks.retain(|t| !matches!(t, Task::Verify { name: n, .. } if *n == name));
                st.stats.lite_waited += (before - tasks.len()) as u32;
            }
            if let Some(r) = res.rewritten {
                st.db.set_best(
                    &name,
                    match r {
                        Rewrite::Alias => Strategy::Alias,
                        Rewrite::Ecs => Strategy::Ecs,
                        Rewrite::Cross => Strategy::Cross,
                    },
                );
            }
        }
        self.schedule_from_apply(tasks, first_seen);
        res
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_locked(
        &self,
        st: &mut State,
        msg: &mut Message,
        name: &str,
        qtype: u16,
        provider: &'static str,
        via: &str,
        cname: &str,
        c1: &str,
        res: &mut ApplyResult,
        tasks: &mut Vec<Task>,
    ) {
        res.provider = Some(provider);
        let ips4: Vec<IpAddr> = msg.answers.iter().filter(|a| a.rtype == rtype::A).filter_map(ip_of).collect();
        let ips6: Vec<IpAddr> = msg.answers.iter().filter(|a| a.rtype == rtype::AAAA).filter_map(ip_of).collect();
        let touch = st.db.touch_at(name, provider, via, &ips4, &ips6, Some(cname), c1, now_ms());
        let Some(entry) = st.db.get(name) else { return };
        let policy = entry.policy();
        if policy == Policy::Never {
            res.tags.push("CDN-略過".into());
            return;
        }
        let best = entry.best;
        let prov = providers::get(provider);
        let label = label_of(provider);
        let fam_q = qtype == rtype::A || qtype == rtype::AAAA;
        if touch.invalidated {
            st.stats.src_invalidated += 1;
        }
        // App 自己選節點的服務（3.5.0 B3）：只辨識與統計，不改寫、不 ECS、不跨 CDN。手動設成「一定換」的照使用者的
        if self.cfg.app_layer && prov.is_some_and(|p| p.app_layer) && policy != Policy::Always {
            res.tags.push(format!("{label}:App 自選節點→原始"));
            st.stats.app_layer += 1;
            return;
        }
        // 台灣本地的 CDN（3.5.1，中華電信 HiNet CDN）：節點本來就在台灣，不換、不 ECS、不跨 CDN。手動設成「一定換」的照使用者的
        if prov.is_some_and(|p| p.tw_native) && policy != Policy::Always {
            res.tags.push(format!("{label}:已是台灣"));
            return;
        }
        // 業者專用 IP（3.5.1 K2，GitHub Pages）：別的節點不服務它，照原本的答案，不驗證、不跨 CDN。
        // 只有有這種規則的業者（Fastly）才逐一比答案裡的 IP（幾個整數比較）
        if providers::has_dedicated(provider) && policy != Policy::Always {
            let mut ips = ips4.iter().chain(&ips6);
            if (!ips4.is_empty() || !ips6.is_empty()) && ips.all(|ip| providers::dedicated_ip(provider, *ip)) {
                res.tags.push(format!("{label}:業者專用 IP→原始"));
                st.stats.dedicated = st.stats.dedicated.saturating_add(1);
                return;
            }
        }
        // 多來源（3.5.0 B3）：這一家沒有格子可以放（第三家，或太快又換一家）→ 照原始答案回，不驗證
        if touch.held {
            res.tags.push(format!("{label}:多來源→原始"));
            st.stats.multi_held += 1;
            return;
        }
        // 多來源、或剛換業者還沒定下來：網站自己在多家之間選，不替它換到別家
        let no_cross = touch.no_cross;

        // 這個網站上次是跨 CDN 成功的：先用跨 CDN（規格 06 第 3.5 節）
        if best == Some(Strategy::Cross)
            && !no_cross
            && fam_q
            && !st.pools.is_nearest(provider)
            && self.cross_rewrite(st, msg, name, provider, qtype, &label, res, tasks, &|_| true)
        {
            return;
        }

        // ---------- IP 置換型（任播 CDN） ----------
        if prov.map(|p| p.alias).unwrap_or(false) && st.pools.has(provider) {
            // 蒐集候選節點：已經在台灣的 v4、所有 v6
            for ip in &ips4 {
                if st.pools.classify(*ip).map(|c| c.cls == Cls::Tw).unwrap_or(false) {
                    st.db.add_harvest(provider, *ip);
                }
            }
            for ip in &ips6 {
                let Some(c) = st.pools.classify(*ip) else { continue };
                st.db.add_harvest(provider, *ip);
                // 同一個 /48 六小時內試過、或本機沒有 IPv6：不必排背景工作（try_v6 裡也會再檢查）
                let tried = st.pools.p.get(provider).map(|d| {
                    d.pool6.iter().any(|x| x.ip == *ip)
                        || util::v6_48(*ip)
                            .and_then(|k| d.tried6.get(&k))
                            .map(|t| now_ms().saturating_sub(*t) < 6 * util::HOUR_MS)
                            .unwrap_or(false)
                });
                if c.cls != Cls::Tw && tried == Some(false) && self.net.v6_usable() != Some(false) {
                    tasks.push(Task::TryV6 {
                        provider: provider.to_string(),
                        ip: *ip,
                    });
                }
            }
            // 沒有台灣節點的 CDN（Fastly）：先看這個網站是不是也放在別家有台灣節點的 CDN 上
            if st.pools.is_nearest(provider) && !no_cross {
                let pools = &st.pools;
                let is_t = |ip: IpAddr| pools.classify(ip).map(|c| c.provider == provider).unwrap_or(false);
                let t_ips: HashSet<IpAddr> = msg.answers.iter().filter_map(ip_of).filter(|ip| is_t(*ip)).collect();
                let is_target = move |ip: IpAddr| t_ips.contains(&ip);
                if qtype == rtype::HTTPS {
                    if self.cross_svcb(st, msg, name, &label, res) {
                        return;
                    }
                } else if self.cross_rewrite(st, msg, name, provider, qtype, &label, res, tasks, &is_target) {
                    return;
                }
            }
            match qtype {
                rtype::A => self.alias_family(st, msg, name, provider, 4, &label, res, tasks),
                rtype::AAAA => self.alias_family(st, msg, name, provider, 6, &label, res, tasks),
                _ => self.alias_svcb(st, msg, name, provider, &label, res, tasks),
            }
            return;
        }

        // ---------- ECS 突破型（DNS 分流 CDN） ----------
        if self.cfg.is_ecs(provider) && fam_q {
            let now = now_ms();
            let ecs = st.db.get(name).and_then(|e| e.ecs.clone());
            match ecs {
                Some(e) if e.until.unwrap_or(0) > now => {
                    // ECS 找不到台灣節點：試試跨 CDN
                    if !e.is("ok") && !no_cross && self.cross_rewrite(st, msg, name, provider, qtype, &label, res, tasks, &|_| true) {
                        return;
                    }
                    if e.is("ok") {
                        let list = if qtype == rtype::A { e.ips4.clone() } else { e.ips6.clone() }.unwrap_or_default();
                        if !list.is_empty() {
                            replace(msg, qtype, &list, |_| true);
                            res.rewritten = Some(Rewrite::Ecs);
                            res.gain_ms = e.gain_ms.get().filter(|g| *g != 0.0 && g.is_finite());
                            res.tags.push(format!("{label}→ECS"));
                            st.stats.ecs_rewrites += 1;
                        }
                    }
                }
                _ => {
                    if qtype == rtype::A && !ips4.is_empty() {
                        tasks.push(Task::Ecs {
                            name: name.to_string(),
                            ips4: ips4.clone(),
                            ips6: ips6.clone(),
                        });
                    }
                }
            }
            return;
        }

        // ---------- 只能用 CNAME 認出來的 CDN（Edgio、BunnyCDN、CDN77…）：原本就慢才試跨 CDN ----------
        if fam_q && !no_cross {
            self.cross_rewrite(st, msg, name, provider, qtype, &label, res, tasks, &|_| true);
        }
    }

    /// 跨 CDN 的狀態：none / ok / ok-recheck / wait
    pub(crate) fn cross_state(e: Option<&Domain>, now: u64) -> &'static str {
        let Some(x) = e.and_then(|e| e.cross4.as_deref()) else {
            return "none";
        };
        let until = x.until.unwrap_or(0);
        if x.is("ok") && until > now {
            return if x.recheck_at.unwrap_or(0) > now { "ok" } else { "ok-recheck" };
        }
        if until > now {
            return "wait";
        }
        "none"
    }

    /// 跨 CDN 要回給用戶端的 IP（驗證通過、而且該節點仍在節點池可用）
    pub(crate) fn cross_serve_ips(pools: &Pools, e: &Domain) -> Vec<IpAddr> {
        let Some(x) = e.cross4.as_deref().filter(|x| x.is("ok")) else {
            return vec![];
        };
        // 跨 CDN 只驗證 IPv4（cross4）：IPv6 一律不回（不然 A 記錄被換成空的）。
        // Akamai 的節點是這台自己帶台灣網段解析到的（不在節點池）；其他家要仍在節點池可用
        let ips = x.ips.clone().unwrap_or_default().into_iter().filter(IpAddr::is_ipv4);
        let to = x.to.as_deref().unwrap_or("");
        let mut out: Vec<IpAddr> = if to == "akamai" {
            ips.collect()
        } else {
            ips.filter(|ip| pools.usable(to, *ip)).collect()
        };
        out.truncate(4);
        out
    }

    /// 跨 CDN 備援：已驗證這個網站也能走別家 CDN 的台灣節點就直接用；沒有紀錄就排入背景探索。回傳 true 表示已改寫
    #[allow(clippy::too_many_arguments)]
    fn cross_rewrite(
        &self,
        st: &mut State,
        msg: &mut Message,
        name: &str,
        provider: &str,
        qtype: u16,
        label: &str,
        res: &mut ApplyResult,
        tasks: &mut Vec<Task>,
        is_target: &dyn Fn(IpAddr) -> bool,
    ) -> bool {
        if !self.cfg.cross.enabled || (qtype != rtype::A && qtype != rtype::AAAA) {
            return false;
        }
        // 通訊類網域（推播，3.5.0）：不換到別家 CDN（長連線重連的代價高，換節點照常）。
        // 只有可能走跨 CDN 的網域才比對（幾個後綴的字串比較，不配置）
        if kuroshio_net::comm::is_comm(name) {
            return false;
        }
        let now = now_ms();
        let Some(entry) = st.db.get(name) else { return false };
        let s = Self::cross_state(Some(entry), now);
        if (s == "none" || s == "ok-recheck") && qtype == rtype::A {
            let o = msg
                .answers
                .iter()
                .filter(|a| a.rtype == rtype::A)
                .filter_map(ip_of)
                .find(|ip| is_target(*ip));
            if let Some(o) = o {
                let explore = Task::Cross {
                    name: name.to_string(),
                    from: provider.to_string(),
                    orig: o,
                };
                match self.net.cached(o) {
                    // 已經在用跨 CDN 的結果、到了複驗時間：不管原始節點現在快不快都要重新確認
                    // （以前原始節點變快、或還沒量過延遲時不會複驗，舊結果一路用到 3 天後過期）
                    _ if s == "ok-recheck" => tasks.push(explore),
                    Some(c) if c.ok && c.ms >= self.cfg.cross.min_orig_ms => tasks.push(explore),
                    Some(_) => {}
                    None => tasks.push(Task::Latency(o)),
                }
            }
        }
        if s != "ok" && s != "ok-recheck" {
            return false;
        }
        let ips = Self::cross_serve_ips(&st.pools, entry);
        if ips.is_empty() {
            return false;
        }
        let x = entry.cross4.as_deref().unwrap();
        let (to, orig_ms, ms) = (x.to.as_deref().unwrap_or("").to_string(), x.orig_ms.get(), x.ms.get());
        if qtype == rtype::A {
            if !msg
                .answers
                .iter()
                .any(|a| a.rtype == rtype::A && ip_of(a).map(is_target).unwrap_or(false))
            {
                return false;
            }
            replace(msg, rtype::A, &ips, is_target);
        } else {
            // 跨過去的那家只驗證了 IPv4：拿掉原本的 AAAA，避免裝置走 IPv6 繞回原本的 CDN
            let before = msg.answers.len();
            msg.answers
                .retain(|a| !(a.rtype == rtype::AAAA && ip_of(a).map(is_target).unwrap_or(false)));
            if msg.answers.len() == before {
                return false;
            }
        }
        res.rewritten = Some(Rewrite::Cross);
        res.gain_ms = match (orig_ms, ms) {
            (Some(o), Some(m)) if o != 0.0 && m != 0.0 => Some(util::round(o - m, 1)),
            _ => None,
        };
        res.tags.push(format!("{label}⇄{}", providers::label(&to)));
        res.cross_to = Some(to);
        st.stats.cross_rewrites += 1;
        true
    }

    /// HTTPS 記錄：跨 CDN 時 ipv4hint 換成新節點、ipv6hint 拿掉
    fn cross_svcb(&self, st: &mut State, msg: &mut Message, name: &str, label: &str, res: &mut ApplyResult) -> bool {
        let Some(entry) = st.db.get(name) else { return false };
        let s = Self::cross_state(Some(entry), now_ms());
        if s != "ok" && s != "ok-recheck" {
            return false;
        }
        let ips: Vec<Ipv4Addr> = Self::cross_serve_ips(&st.pools, entry)
            .into_iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v) => Some(v),
                _ => None,
            })
            .collect();
        if ips.is_empty() {
            return false;
        }
        let to = entry.cross4.as_ref().and_then(|x| x.to.as_deref()).unwrap_or("").to_string();
        let mut changed = false;
        for a in msg.answers.iter_mut().filter(|a| is_svcb(a)) {
            if let RData::Raw(d) = &a.data {
                if let Some(n) = svcb::rewrite(d, &Hint::Set(ips.clone()), &Hint::Remove) {
                    a.data = RData::Raw(n);
                    changed = true;
                }
            }
        }
        if changed {
            res.rewritten = Some(Rewrite::Cross);
            res.cross_to = Some(to);
            res.tags.push(format!("{label}⇄HTTPS 提示"));
        }
        changed
    }

    #[allow(clippy::too_many_arguments)]
    fn alias_family(
        &self,
        st: &mut State,
        msg: &mut Message,
        name: &str,
        provider: &str,
        family: u8,
        label: &str,
        res: &mut ApplyResult,
        tasks: &mut Vec<Task>,
    ) {
        let rt = if family == 6 { rtype::AAAA } else { rtype::A };
        let now = now_ms();
        let recs: Vec<IpAddr> = msg.answers.iter().filter(|a| a.rtype == rt).filter_map(ip_of).collect();
        let cls: Vec<Option<crate::Class>> = recs.iter().map(|ip| st.pools.classify(*ip)).collect();
        let hits: Vec<usize> = (0..recs.len())
            .filter(|&i| cls[i].map(|c| c.provider == provider).unwrap_or(false))
            .collect();
        if hits.is_empty() {
            return;
        }
        // 只置換「Global（會被導去國外）」與「未掃描」的位址；已是台灣節點或 Dead 的不動
        let needs: Vec<IpAddr> = hits
            .iter()
            .filter(|&&i| matches!(cls[i].unwrap().cls, Cls::Global | Cls::Unknown))
            .map(|&i| recs[i])
            .collect();
        if needs.is_empty() {
            res.tags.push(format!("{label}:已是台灣"));
            return;
        }
        let pc_min_gain = self.cfg.nearest_min_gain_ms;
        // 多家 CDN：同一個答案裡已經有別家而且更快，就不換節點，直接把這家較慢的 IP 拿掉
        let others: Vec<IpAddr> = (0..recs.len()).filter(|i| !hits.contains(i)).map(|i| recs[i]).collect();
        if !others.is_empty() {
            let other_ms = self.served_ms_in(&st.pools, provider, &others);
            let mine = [self.served_ms_in(&st.pools, provider, &needs), st.pools.best_ms(provider, family)]
                .into_iter()
                .flatten()
                .fold(f64::INFINITY, f64::min);
            if let Some(om) = other_ms {
                if mine.is_finite() && om + pc_min_gain <= mine {
                    drop_provider(msg, rt, &st.pools, provider);
                    res.tags.push(format!("{label}:別家 CDN 更快（{}ms）", fmt0(om)));
                    return;
                }
            }
        }

        let pool = st.pools.map_ips(provider, family, &needs);
        let v6_policy = self.cfg.v6_policy_of(provider).to_string();
        let nearest = st.pools.is_nearest(provider);
        // 保留最後一段的 CDN：這組憑證還沒找到可用網段時 pool 是空的，但仍要走驗證流程
        let octet = st.pools.octet_mode(provider) && family == 4 && !st.pools.pop_view(provider).pops.is_empty();
        if pool.is_empty() && !octet {
            // 沒有台灣 v6 節點：只有在這家 CDN 的 v4 正在被導向台灣時才丟棄 v6，避免用戶端走 v6 繞出國
            if family == 6 && v6_policy == "drop" && st.pools.pool_size(provider, 4) > 0 {
                // 最近節點型（Fastly）：只有這個網域的 v4 已驗證能換到好節點時才丟 v6
                let nearest_ok = !nearest || Self::vstate(&st.pools, st.db.get(name), 4, now) == VState::Ok;
                if nearest_ok {
                    drop_provider(msg, rt, &st.pools, provider);
                    res.tags.push(format!("{label}:V6丟棄"));
                    st.stats.v6dropped += 1;
                }
            }
            return;
        }
        // 沒有台灣節點的 CDN（例如 Fastly）：只有在「最近節點」明顯比原本快時才換
        if nearest {
            let orig_ms = self.served_ms_in(&st.pools, provider, &needs);
            let pop = match pool.first() {
                Some(ip) => st.pools.pop_of_ip(provider, *ip),
                None => st.pools.pop_view(provider).pops.first().map(|x| x.0.clone()),
            };
            let pool_ms = pop
                .and_then(|p| st.pools.pop_score(provider, &p))
                .filter(|s| *s != 0.0 && !s.is_nan())
                .or_else(|| st.pools.best_ms(provider, family));
            let enough = matches!((orig_ms, pool_ms), (Some(o), Some(p)) if o - p >= pc_min_gain);
            if !enough {
                if orig_ms.is_none() {
                    tasks.push(Task::Latency(needs[0]));
                }
                res.tags.push(format!("{label}:已是最近節點"));
                return;
            }
        }
        let state = Self::vstate(&st.pools, st.db.get(name), family, now);
        if state == VState::Fail {
            if family == 6 && v6_policy == "drop" && !nearest {
                drop_provider(msg, rt, &st.pools, provider);
                res.tags.push(format!("{label}:V6丟棄"));
                st.stats.v6dropped += 1;
            } else {
                res.tags.push(format!("{label}:驗證失敗→原始"));
            }
            return;
        }
        let orig_ip = needs[0];
        let serve = self.serve_pool(st, provider, family, name, &pool, Some(&needs), tasks);
        let trial_ttl = self.cfg.trial_ttl;
        if state == VState::Trial {
            // 第一次遇到、還沒驗證：先回「已知最快」的原始結果（TTL 10 秒），背景驗證；
            // 驗證通過後，下一次查詢才換成台灣節點（服務中斷比慢更傷體驗）
            res.ttl_cap = Some(trial_ttl);
            st.stats.trials += 1;
            let pending = st
                .db
                .get(name)
                .and_then(|e| e.verdict(family))
                .map(|v| v.is("unknown") && v.valid(now))
                .unwrap_or(false);
            if !pending {
                tasks.push(Task::Verify {
                    name: name.to_string(),
                    provider: provider.to_string(),
                    family,
                    orig: Some(orig_ip),
                });
            }
            if self.cfg.trial_original {
                res.tags.push(format!("{label}:驗證中→原始"));
                return;
            }
            res.tags.push(format!("{label}→TW 試用"));
        } else {
            res.tags.push(if nearest {
                format!("{label}→最近節點")
            } else {
                format!("{label}→TW")
            });
            // 3.5.0 F9：上一次驗證握手比原本慢（`slow1`）、已經過了 10 分鐘（24 小時內）→ 照常回台灣節點，同時排一次驗證確認。
            // 幾乎所有網域的 `extra` 是空的（一個指標比較）；排程有重複檢查與 F12 的名額，排不進就下一次查詢再排
            if let Some(at) = st.db.get(name).and_then(|e| e.verdict(family)).and_then(crate::verifier::slow1_at) {
                let age = now.saturating_sub(at);
                if (crate::reach::SLOWER_CONFIRM_GAP_MS..=crate::reach::SLOWER_FIRST_TTL_MS).contains(&age) {
                    tasks.push(Task::Verify {
                        name: name.to_string(),
                        provider: provider.to_string(),
                        family,
                        orig: Some(orig_ip),
                    });
                }
            }
        }
        if serve.is_empty() {
            // 驗證過的網段所在 POP 變差了，或驗證過的 IP 都已不在節點池 → 重新驗證，先回原始結果
            if state == VState::Ok {
                res.ttl_cap = Some(trial_ttl);
                tasks.push(Task::Verify {
                    name: name.to_string(),
                    provider: provider.to_string(),
                    family,
                    orig: Some(orig_ip),
                });
            }
            res.tags.push(format!("{label}:尚無可用網段→原始"));
            return;
        }
        let pools = &st.pools;
        replace(msg, rt, &serve, |ip| {
            pools.classify(ip).map(|c| c.provider == provider).unwrap_or(false)
        });
        st.stats.rewrites += 1;
        res.rewritten = Some(Rewrite::Alias);
    }

    /// 驗證通過時用的那個 IP 排第一（確定能服務這個網站），其餘接在後面當備援
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn serve_pool(
        &self,
        st: &State,
        provider: &str,
        family: u8,
        name: &str,
        pool: &[IpAddr],
        orig: Option<&[IpAddr]>,
        tasks: &mut Vec<Task>,
    ) -> Vec<IpAddr> {
        let entry = st.db.get(name);
        let v = entry.and_then(|e| e.verdict(family));
        if st.pools.octet_mode(provider) && family == 4 {
            let Some(v) = v.filter(|v| v.is("ok")) else { return pool.to_vec() };
            // 只回「針對這個網站驗證過」的 IP：驗證時用的那個排第一，其餘驗證通過的當備援。
            // 以前驗證用的 IP 不能用（POP 變差、網站換了憑證組）時會改回節點池裡「別的網站驗證過」的 IP，
            // 那些沒有針對這個網站驗證過憑證；現在回空的，讓呼叫端先回原始結果並重新驗證
            let mut out: Vec<IpAddr> = Vec::new();
            for ip in v.ip.iter().chain(v.ips.iter().flatten()) {
                // 最後一段要跟這次答案一樣才能用（網站換了憑證組就不能用舊的）
                let same_octet = orig
                    .map(|o| o.iter().any(|x| util::last_octet(*x) == util::last_octet(*ip)))
                    .unwrap_or(true);
                if same_octet && !out.contains(ip) && st.pools.usable(provider, *ip) {
                    out.push(*ip);
                }
            }
            out.truncate(pool.len().max(1));
            return out;
        }
        // 任播型（Cloudflare 等）：只回「針對這個網站驗證過」的 IP。
        // 池內其他 IP 不一定能服務這個網站（Error 1034 Edge IP Restricted），不能當備援塞進去
        let Some(v) = v.filter(|v| v.is("ok")) else { return pool.to_vec() };
        let mut verified: Vec<IpAddr> = Vec::new();
        for ip in v.ip.iter().chain(v.ips.iter().flatten()) {
            if !verified.contains(ip) && st.pools.usable(provider, *ip) {
                verified.push(*ip);
            }
        }
        if verified.is_empty() {
            if v.ip.is_some() {
                tasks.push(Task::Verify {
                    name: name.to_string(),
                    provider: provider.to_string(),
                    family,
                    orig: entry.and_then(|e| e.orig_ip(family)),
                });
            }
            return vec![];
        }
        verified.truncate(if pool.is_empty() { 4 } else { pool.len() }.max(1));
        verified
    }

    /// HTTPS 記錄（type 65）的 ipv4hint / ipv6hint 也要同步改，不然瀏覽器會照提示連去國外
    #[allow(clippy::too_many_arguments)]
    fn alias_svcb(
        &self,
        st: &mut State,
        msg: &mut Message,
        name: &str,
        provider: &str,
        label: &str,
        res: &mut ApplyResult,
        tasks: &mut Vec<Task>,
    ) {
        let now = now_ms();
        let v6_policy = self.cfg.v6_policy_of(provider).to_string();
        let pool4 = st.pools.serve_ips(provider, 4);
        let pool6 = st.pools.serve_ips(provider, 6);
        let s4 = Self::vstate(&st.pools, st.db.get(name), 4, now);
        let s6 = Self::vstate(&st.pools, st.db.get(name), 6, now);
        let octet = st.pools.octet_mode(provider);
        let nearest = st.pools.is_nearest(provider);
        let original = self.cfg.trial_original;
        let (mut trial, mut changed) = (false, false);
        for i in 0..msg.answers.len() {
            if !is_svcb(&msg.answers[i]) {
                continue;
            }
            let RData::Raw(data) = &msg.answers[i].data else { continue };
            let (h4, h6) = svcb::hints(data);
            let h4ip: Vec<IpAddr> = h4.iter().map(|v| IpAddr::V4(*v)).collect();
            let mut opt4: Option<Vec<IpAddr>> = None;
            let mut opt6: Option<Option<Vec<IpAddr>>> = None; // Some(None) = 拿掉
            let glob4 = h4ip.iter().any(|ip| {
                st.pools
                    .classify(*ip)
                    .map(|c| c.provider == provider && matches!(c.cls, Cls::Global | Cls::Unknown))
                    .unwrap_or(false)
            });
            let p4 = if octet {
                st.pools.map_ips(provider, 4, &h4ip)
            } else {
                pool4.clone()
            };
            if glob4 && (!p4.is_empty() || octet) && s4 != VState::Fail {
                if s4 == VState::Trial {
                    trial = true;
                    tasks.push(Task::Verify {
                        name: name.to_string(),
                        provider: provider.to_string(),
                        family: 4,
                        orig: h4ip.first().copied(),
                    });
                    if !original {
                        opt4 = Some(p4.clone());
                    }
                } else {
                    opt4 = Some(self.serve_pool(st, provider, 4, name, &p4, Some(&h4ip), tasks));
                }
            }
            let in6 = h6.iter().any(|ip| {
                st.pools
                    .classify(IpAddr::V6(*ip))
                    .map(|c| c.provider == provider && c.cls != Cls::Tw)
                    .unwrap_or(false)
            });
            if in6 && nearest {
                if v6_policy == "drop" && s4 == VState::Ok && opt4.is_some() {
                    opt6 = Some(None);
                }
            } else if in6 {
                if !pool6.is_empty() && s6 != VState::Fail {
                    if s6 == VState::Trial {
                        trial = true;
                        if !original {
                            opt6 = Some(Some(pool6.clone()));
                        }
                    } else {
                        opt6 = Some(Some(self.serve_pool(st, provider, 6, name, &pool6, None, tasks)));
                    }
                } else if v6_policy == "drop" && !pool4.is_empty() && s4 == VState::Ok {
                    opt6 = Some(None);
                }
            }
            if opt4.as_ref().map(|v| v.is_empty()).unwrap_or(false) {
                opt4 = None; // 還沒找到可用網段：不要把提示清空
            }
            if opt4.is_none() && opt6.is_none() {
                continue;
            }
            let h4 = match &opt4 {
                None => Hint::Keep,
                Some(l) => Hint::Set(
                    l.iter()
                        .filter_map(|ip| if let IpAddr::V4(v) = ip { Some(*v) } else { None })
                        .collect(),
                ),
            };
            let h6: Hint<Ipv6Addr> = match &opt6 {
                None => Hint::Keep,
                Some(None) => Hint::Remove,
                Some(Some(l)) => Hint::Set(
                    l.iter()
                        .filter_map(|ip| if let IpAddr::V6(v) = ip { Some(*v) } else { None })
                        .collect(),
                ),
            };
            if let Some(n) = svcb::rewrite(data, &h4, &h6) {
                msg.answers[i].data = RData::Raw(n);
                changed = true;
            }
        }
        if trial {
            res.ttl_cap = Some(self.cfg.trial_ttl);
        }
        if changed {
            res.rewritten = Some(Rewrite::Alias);
            res.tags.push(format!("{label}:HTTPS提示改寫"));
        } else if trial {
            res.tags.push(format!("{label}:驗證中→原始"));
        }
    }

    // ------------------------------------------------------------ 給解析流程用

    /// 固定上游（例如路由器）回的任播 CDN IP 是它自己「優選」換過的嗎？
    /// 這類 IP 沒有針對這個網站驗證（Cloudflare 會出現 Error 1034）。回傳要排除的 IP。
    /// `others` 是其他上游的回應：有給答案時，跟其他上游一樣的 IP 保留；`Some(&[])`（沒有其他上游）時不排除。
    pub fn pinned_alias(&self, pinned: &Message, qtype: u16, others: Option<&[&Message]>) -> HashSet<IpAddr> {
        let mut out = HashSet::new();
        if qtype != rtype::A && qtype != rtype::AAAA {
            return out;
        }
        let seen: HashSet<IpAddr> = others
            .into_iter()
            .flatten()
            .flat_map(|m| m.answers.iter().filter(|a| a.rtype == qtype).filter_map(ip_of))
            .collect();
        // 只需要分類：用唯讀快照，不拿狀態鎖（每個上游回應都會跑）
        let cls = self.classifier();
        for ip in pinned.answers.iter().filter(|a| a.rtype == qtype).filter_map(ip_of) {
            if seen.contains(&ip) {
                continue;
            }
            if let Some(c) = cls.classify(ip) {
                if Cdn::is_alias(c.provider) && !Cdn::is_nearest(c.provider) {
                    out.insert(ip);
                }
            }
        }
        if !out.is_empty() && others.map(|o| o.is_empty()).unwrap_or(false) {
            out.clear(); // 沒有其他上游可比較：只能用它的
        }
        out
    }

    /// 機會成本基準：其他上游（不含固定上游）的 A 記錄。不是可追蹤的 CDN 或沒有回答時回 None
    pub fn baseline(&self, others: &[&Message]) -> Option<Baseline> {
        if others.is_empty() {
            return None;
        }
        let cls = self.classifier();
        let mut provider: Option<&'static str> = None;
        let (mut abroad, mut tw) = (0, 0);
        let mut ips = Vec::new();
        for m in others {
            let (mut a, mut t) = (false, false);
            for ip in m.answers.iter().filter(|r| r.rtype == rtype::A).filter_map(ip_of) {
                let Some(c) = cls.classify(ip) else { continue };
                if Cdn::is_nearest(c.provider) {
                    continue; // 沒有台灣節點的 CDN 不列入「拉回台灣」
                }
                let p = *provider.get_or_insert(c.provider);
                if c.provider != p {
                    continue;
                }
                ips.push(ip);
                match c.cls {
                    Cls::Tw => t = true,
                    Cls::Global | Cls::Unknown => a = true,
                    Cls::Dead => {}
                }
            }
            if t {
                tw += 1;
            } else if a {
                abroad += 1;
            }
        }
        let provider = provider?;
        if abroad + tw == 0 {
            return None;
        }
        let ms = ips
            .iter()
            .filter_map(|ip| self.net.cached(*ip).filter(|c| c.ok).map(|c| c.ms))
            .fold(f64::INFINITY, f64::min);
        Some(Baseline {
            provider,
            abroad: abroad > tw,
            ms: ms.is_finite().then(|| util::round(ms, 1)),
        })
    }

    /// 每一次 A 回應 ≈ 一次連線：記錄是否把「原本會出國」的連線拉回台灣（2.x 的 `stats.route()` 參數）
    pub fn route(&self, baseline: Option<&Baseline>, res: &ApplyResult, served: &Message) -> Option<Route> {
        if let Some(b) = baseline {
            let ips: Vec<IpAddr> = served.answers.iter().filter(|a| a.rtype == rtype::A).filter_map(ip_of).collect();
            let served_tw = res.rewritten == Some(Rewrite::Alias)
                || self.with_classifier(|c| ips.iter().any(|ip| c.classify(*ip).map(|c| c.cls == Cls::Tw).unwrap_or(false)));
            let mut saved = None;
            if b.abroad && served_tw {
                if let (Some(bm), Some(sm)) = (b.ms.filter(|m| *m != 0.0), self.served_ms(b.provider, &ips)) {
                    saved = Some(bm - sm);
                }
            }
            return Some(Route {
                provider: b.provider.to_string(),
                abroad: b.abroad,
                tw: served_tw,
                saved_ms: saved,
            });
        }
        if res.rewritten == Some(Rewrite::Ecs) {
            return Some(Route {
                provider: res.provider.unwrap_or("").to_string(),
                abroad: true,
                tw: true,
                saved_ms: res.gain_ms,
            });
        }
        None
    }
}
