//! 線路感知（3.5.0 E 組，規格 11 第 5 節）：這條線到得了哪些台灣機房（E3）、機房以本機量到的為準（E4）、
//! 機房層級的健康與切換（E5），以及給主程式觀測用的計數（E2 讀、E7 累加）。
//!
//! 機房是「IP × 這條線路」量出來的，不是 IP 的屬性：別人量到的機房只當參考，這台用的一律是自己量到的。
//! 這裡不新增背景工作，也不碰查詢路徑；對外的請求只有 E4 串接中的機房抽查（搭既有抽查的名額，有四層上限）。
//! 狀態都在記憶體（`State.line`，跟著狀態鎖）、有上限、重新啟動清空，不寫 Flash；
//! 唯一存檔的是節點上的 `upPop`（在既有的 `pools.json` 裡，不增加寫入次數）。
//!
//! 時間：JSON 一律是 Unix 毫秒（跟其他管理 API 一樣）；[`ObserveCounters`] 是 Unix 秒（`u32`）。

use crate::cdn::{Cdn, FRIEND_MAX_NODES};
use crate::pools::{self, pop3, unmap, PoolNode, Pools};
use crate::providers::{self, is_tw_pop};
use crate::util::{self, now_ms, DAY_MS, HOUR_MS};
use serde_json::{json, Map, Value};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{info, warn};

/// 給主程式的發現清單（E2）讀的計數：都是啟動後的累計值（`u32`，飽和；32 位元 MIPS 沒有 64 位元原子操作），
/// 時間是 Unix 秒（`u32`；0 = 還沒發生）。E2 用「計數的增加量」算次數，所以沒人開狀態頁的那幾天也是對的。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ObserveCounters {
    /// 台灣節點驗證通過／失敗的次數（E2 的 `cdn-verify-fail-high`；在 `verifier.rs` 的 `done()` 累加）。
    /// E7「比原本慢」只算在 `slower_fallback`，不算失敗（節點是好的）
    pub verify_ok: u32,
    pub verify_fail: u32,
    /// 上游給的節點，本機量到的機房一樣／不一樣的次數（E4）與最近一次不一樣的時間
    pub pop_confirmed: u32,
    pub pop_mismatch: u32,
    pub pop_mismatch_at: u32,
    /// 機房串接中抽查的次數（E4，一天最多 24 個）
    pub pop_probes: u32,
    /// 機房切換（暫緩）發生的次數與最近一次的時間（E5 的 `pop-switched`）
    pub pop_switches: u32,
    pub pop_switch_at: u32,
    /// 想切換但已經達到每日上限、沒有切的次數與最近一次的時間（E5 的 `pop-flapping`）
    pub pop_flapping: u32,
    pub pop_flapping_at: u32,
    /// 因為台灣節點實測比原本慢、暫時用原本答案的次數與最近一次的時間（E7 的 `slower-fallback`）
    pub slower_fallback: u32,
    pub slower_fallback_at: u32,
    /// E7 的保險絲跳到幾點（Unix 秒；0 = 沒跳，或已經到期）
    pub slower_fuse_until: u32,
}

/// 這台目前的情況（主程式用 [`Cdn::set_line_env`] 提供；沒設 = 沒有串接、記憶體正常）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineEnv {
    /// 串接中（CDN 由上游黑潮處理）：E5 不切換、`reach` 標成過期
    pub chained: bool,
    /// 記憶體壓力是 `Normal`：不是的時候 E4 不抽查、E5 不切換
    pub memory_normal: bool,
}

impl Default for LineEnv {
    fn default() -> LineEnv {
        LineEnv {
            chained: false,
            memory_normal: true,
        }
    }
}

fn secs(ms: u64) -> u32 {
    (ms / 1000).min(u32::MAX as u64) as u32
}

fn ms_or_null(ms: u64) -> Value {
    if ms == 0 {
        Value::Null
    } else {
        json!(ms)
    }
}

fn median(v: &mut [f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    let n = v.len();
    let m = if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 };
    Some(util::round(m, 1))
}

fn fam_idx(family: u8) -> usize {
    usize::from(family == 6)
}

// ============================================================ E3 到得了哪些台灣機房

/// 每個家族最多列幾個機房（台灣 POP 代碼只有 6 個）
pub const REACH_MAX_POPS: usize = 8;
/// 最近節點型（Fastly）的鄰近機房最多列幾筆
pub const REACH_MAX_NEARBY: usize = 8;
/// 啟動後（或 WAN 變動後）頭幾輪健檢判斷 E5 的資格，之後沿用
pub const ELIG_ROUNDS: u8 = 2;

/// 機房代碼 → 城市（TPE、TSA → 台北；KHH → 高雄；RMQ、TXG → 台中；TNN → 台南）
pub fn city_of(pop: &str) -> &'static str {
    match pop3(pop).as_str() {
        "TPE" | "TSA" => "台北",
        "KHH" => "高雄",
        "RMQ" | "TXG" => "台中",
        "TNN" => "台南",
        _ => "",
    }
}

/// 一個家族裡的一個機房
#[derive(Debug, Clone, PartialEq)]
pub struct PopReach {
    /// 機房代碼（前三碼大寫）
    pub pop: String,
    pub city: &'static str,
    /// 本機確認過、可用的節點數
    pub nodes: u32,
    /// 幾個網段（IPv4 /24、IPv6 /48）
    pub prefixes: u32,
    /// 幾家 CDN
    pub providers: u32,
    pub median_ms: Option<f64>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FamReach {
    /// 依節點數多到少（最多 [`REACH_MAX_POPS`] 個）
    pub pops: Vec<PopReach>,
    /// 到得了兩個以上的城市，每個城市至少 2 個節點、分在 2 個以上的網段（E5 的資格用）
    pub multi: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Nearby {
    pub provider: &'static str,
    pub pop: String,
    pub prefixes: u32,
}

/// 這條線到得了哪些台灣機房（E3）：節點池變動或健檢結束時算好，`/api/status` 只複製
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Reach {
    /// 算的時間（Unix 毫秒；0 = 還沒算過）
    pub at: u64,
    pub v4: FamReach,
    pub v6: FamReach,
    /// 最近節點型（Fastly）：直接讀既有的 `pop_view()`（依品質排好），不另外算
    pub nearby: Vec<Nearby>,
    /// 上游給的、本機還沒量過機房的節點（不在 `bad` 裡；E4 的 `upPop` 還在）
    pub unconfirmed: u32,
    /// 所有 `upPop` 還在的節點（含壞的；E4 的 `popAudit.pending`）
    pub pending: u32,
}

struct Acc {
    pop: String,
    nodes: u32,
    nets: Vec<u128>,
    provs: Vec<&'static str>,
    ms: Vec<f64>,
}

fn fam_reach(mut accs: Vec<Acc>) -> FamReach {
    // multi：依城市合併（台北的 TPE、TSA 算同一個）
    let mut cities: Vec<(&'static str, u32, Vec<u128>)> = Vec::new();
    for a in &accs {
        let c = city_of(&a.pop);
        match cities.iter_mut().find(|x| x.0 == c) {
            Some(x) => {
                x.1 += a.nodes;
                x.2.extend_from_slice(&a.nets);
            }
            None => cities.push((c, a.nodes, a.nets.clone())),
        }
    }
    for c in cities.iter_mut() {
        c.2.sort_unstable();
        c.2.dedup();
    }
    let multi = cities.iter().filter(|(_, n, nets)| *n >= 2 && nets.len() >= 2).count() >= 2;
    for a in accs.iter_mut() {
        a.nets.sort_unstable();
        a.nets.dedup();
    }
    accs.sort_by(|a, b| b.nodes.cmp(&a.nodes).then_with(|| a.pop.cmp(&b.pop)));
    accs.truncate(REACH_MAX_POPS);
    FamReach {
        pops: accs
            .into_iter()
            .map(|mut a| PopReach {
                city: city_of(&a.pop),
                nodes: a.nodes,
                prefixes: a.nets.len() as u32,
                providers: a.provs.len() as u32,
                median_ms: median(&mut a.ms),
                pop: a.pop,
            })
            .collect(),
        multi,
    }
}

/// 依節點池算 `reach`：只算本機確認過的台灣節點（不在 `bad`、是台灣機房、不是種子、沒有 `upPop`）。不發任何探測
pub fn compute_reach(pools: &Pools, now: u64) -> Reach {
    let mut r = Reach {
        at: now,
        ..Default::default()
    };
    let mut accs: [Vec<Acc>; 2] = [Vec::new(), Vec::new()];
    for (&name, d) in &pools.p {
        if pools.is_nearest(name) {
            for (pop, pfs) in &pools.pop_view(name).pops {
                if r.nearby.len() < REACH_MAX_NEARBY {
                    r.nearby.push(Nearby {
                        provider: name,
                        pop: pop.clone(),
                        prefixes: pfs.len() as u32,
                    });
                }
            }
        }
        for family in [4u8, 6] {
            for x in d.pool(family) {
                let bad = d.bad.contains_key(&x.ip);
                if x.up_pop().is_some() {
                    r.pending += 1;
                    if !bad {
                        r.unconfirmed += 1;
                    }
                    continue;
                }
                if bad || !is_tw_pop(x.pop_str()) {
                    continue;
                }
                let list = &mut accs[fam_idx(family)];
                let p3 = pop3(x.pop_str());
                let i = match list.iter().position(|a| a.pop == p3) {
                    Some(i) => i,
                    None => {
                        list.push(Acc {
                            pop: p3,
                            nodes: 0,
                            nets: Vec::new(),
                            provs: Vec::new(),
                            ms: Vec::new(),
                        });
                        list.len() - 1
                    }
                };
                let a = &mut list[i];
                a.nodes += 1;
                a.nets.extend(pools::net_key(x.ip));
                if !a.provs.contains(&name) {
                    a.provs.push(name);
                }
                if let Some(ms) = x.ms.get().filter(|m| m.is_finite() && *m > 0.0) {
                    a.ms.push(ms);
                }
            }
        }
    }
    let [a4, a6] = accs;
    r.v4 = fam_reach(a4);
    r.v6 = fam_reach(a6);
    r
}

/// 一句白話：「這條線目前只到得了台北機房」
pub fn reach_text(family: u8, f: &FamReach) -> String {
    let who = if family == 6 { "這條線的 IPv6 " } else { "這條線" };
    let mut cities: Vec<&str> = Vec::new();
    for p in &f.pops {
        if !p.city.is_empty() && !cities.contains(&p.city) {
            cities.push(p.city);
        }
    }
    match cities.len() {
        0 => format!("{who}目前量不到台灣機房（節點池還沒建立，或節點都連不上）"),
        1 => format!("{who}目前只到得了{}機房", cities[0]),
        _ => format!("{who}目前到得了{}機房", cities.join("、")),
    }
}

impl Reach {
    fn fam_json(family: u8, f: &FamReach) -> Value {
        json!({
            "text": reach_text(family, f), "multi": f.multi,
            "pops": f.pops.iter().map(|p| json!({
                "pop": p.pop, "city": p.city, "nodes": p.nodes, "prefixes": p.prefixes,
                "providers": p.providers, "medianMs": p.median_ms,
            })).collect::<Vec<_>>(),
        })
    }

    pub fn json(&self, wan_epoch: u32, stale: bool) -> Value {
        json!({
            "at": ms_or_null(self.at), "wanEpoch": wan_epoch, "stale": stale, "unconfirmed": self.unconfirmed,
            "v4": Reach::fam_json(4, &self.v4), "v6": Reach::fam_json(6, &self.v6),
            "nearby": self.nearby.iter().map(|n| json!({ "provider": n.provider, "pop": n.pop, "prefixes": n.prefixes })).collect::<Vec<_>>(),
        })
    }
}

/// E5 的資格（每個家族）：啟動後或 WAN 變動後的頭 [`ELIG_ROUNDS`] 輪有資料的健檢判斷，之後沿用
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Elig {
    judged: u8,
    streak: u8,
    eligible: bool,
}

// ============================================================ E5 機房層級的健康與切換

/// 機房變差：這一輪失敗率 ≥ 20%（而且節點數 ≥ 3 或壞的 ≥ 2 個）
pub const POP_BAD_RATE: f64 = 0.20;
/// 連續幾輪才算
pub const POP_BAD_ROUNDS: u8 = 3;
/// 另一個機房的延遲中位數最多比變差的機房多幾毫秒
pub const POP_NEAR_MS: f64 = 20.0;
/// 暫緩多久（不提早結束）
pub const POP_HOLD_MS: u64 = 4 * HOUR_MS;
/// 同一個（CDN、家族）24 小時內最多暫緩幾次
pub const POP_MAX_HOLDS_24H: usize = 2;
/// `popHealth` 最多幾筆
pub const POP_HEALTH_MAX: usize = 64;

/// 一輪健檢裡一個節點的結果（彙總用）：`pop` 是檢查前的機房（壞掉的節點算在它原本的機房頭上）
#[derive(Debug, Clone)]
pub struct RoundNode {
    pub pop: String,
    pub ok: bool,
    pub ms: f64,
    pub ip: IpAddr,
}

/// （CDN、家族、機房）的健康
#[derive(Debug, Clone, PartialEq)]
pub struct PopHealth {
    pub provider: &'static str,
    pub family: u8,
    pub pop: String,
    pub nodes: u32,
    pub bad: u32,
    pub fail_rate: f64,
    /// 可用節點的延遲中位數
    pub median_ms: Option<f64>,
    /// 可用節點分在幾個網段
    pub usable_prefixes: u32,
    /// 連續幾輪「變差」／「乾淨」（失敗率 0、可用 ≥ 2 個而且分在 2 個以上的網段）
    pub bad_streak: u8,
    pub clean_streak: u8,
}

impl PopHealth {
    pub fn degraded(&self) -> bool {
        self.fail_rate >= POP_BAD_RATE && (self.nodes >= 3 || self.bad >= 2)
    }
    pub fn clean(&self) -> bool {
        self.bad == 0 && self.nodes >= 2 && self.usable_prefixes >= 2
    }
}

/// 依檢查前的機房彙總一輪健檢（只算台灣機房）
pub fn aggregate(provider: &'static str, family: u8, nodes: &[RoundNode]) -> Vec<PopHealth> {
    let mut out: Vec<(PopHealth, Vec<f64>, Vec<u128>)> = Vec::new();
    for n in nodes {
        if !is_tw_pop(&n.pop) {
            continue;
        }
        let p3 = pop3(&n.pop);
        let i = match out.iter().position(|x| x.0.pop == p3) {
            Some(i) => i,
            None => {
                out.push((
                    PopHealth {
                        provider,
                        family,
                        pop: p3,
                        nodes: 0,
                        bad: 0,
                        fail_rate: 0.0,
                        median_ms: None,
                        usable_prefixes: 0,
                        bad_streak: 0,
                        clean_streak: 0,
                    },
                    Vec::new(),
                    Vec::new(),
                ));
                out.len() - 1
            }
        };
        let (h, ms, nets) = &mut out[i];
        h.nodes += 1;
        if n.ok {
            if n.ms.is_finite() {
                ms.push(n.ms);
            }
            nets.extend(pools::net_key(n.ip));
        } else {
            h.bad += 1;
        }
    }
    out.into_iter()
        .map(|(mut h, mut ms, mut nets)| {
            h.fail_rate = if h.nodes == 0 { 0.0 } else { h.bad as f64 / h.nodes as f64 };
            h.median_ms = median(&mut ms);
            nets.sort_unstable();
            nets.dedup();
            h.usable_prefixes = nets.len() as u32;
            h
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hold {
    pub provider: &'static str,
    pub family: u8,
    pub pop: String,
    pub until: u64,
    /// 當時明顯較好的那個機房（只是紀錄）
    pub other: String,
}

// ============================================================ E4 機房以本機量到的為準

/// 串接中的機房抽查：兩次之間至少隔多久、24 小時內最多幾個（`cdn.lite` 減量：30 分鐘 1 個、一天 8 個）
pub const AUDIT_GAP_MS: u64 = 10 * 60_000;
pub const AUDIT_DAY_MAX: usize = 24;
pub const AUDIT_GAP_LITE_MS: u64 = 30 * 60_000;
pub const AUDIT_DAY_MAX_LITE: usize = 8;
/// 24 小時內比對過的節點有一半以上不一致（至少這麼多個）→ `chainPopUnreliable`
pub const UNRELIABLE_MIN: usize = 4;
const AUDIT_RECENT_MAX: usize = 512;
const AUDIT_ASKED_MAX: usize = 256;

/// 上游宣稱的機房跟本機量到的比
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopCheck {
    /// 一樣
    Same,
    /// 不一樣但還是可以用的機房（台灣機房；最近節點型是任何機房）
    Moved,
    /// 不是台灣機房：照既有的流程標成壞節點
    NotTw,
}

pub fn compare_pop(up: &str, local: &str, nearest: bool) -> PopCheck {
    if pop3(up) == pop3(local) {
        PopCheck::Same
    } else if nearest || is_tw_pop(local) {
        PopCheck::Moved
    } else {
        PopCheck::NotTw
    }
}

/// 這個機房是本機量到的嗎（不是種子、有值、沒有 `upPop`）
fn locally_measured(x: &PoolNode) -> bool {
    x.up_pop().is_none() && !x.pop_str().is_empty() && x.pop_str() != "seed"
}

/// 串接匯入的一個節點（E4 第 1 點）：先拿掉上游帶來的 `upPop`（那是上游自己的查核狀態），
/// 再依這台原本的同一個節點決定：
/// - 這台原本就有、本機量過、機房一樣 → 不放 `upPop`
/// - 這台原本就有、本機量過、機房不一樣 → 機房用這台量到的（以本機為準），不放 `upPop`
/// - 其他 → `upPop` = 上游給的機房（種子、沒有機房的不放）
pub fn mark_incoming(n: &mut PoolNode, own: Option<&PoolNode>) {
    n.take_up_pop();
    let up = n.pop_str().to_string();
    if up.is_empty() || up == "seed" {
        return;
    }
    match own {
        Some(o) if locally_measured(o) => {
            if pop3(o.pop_str()) != pop3(&up) {
                n.pop = o.pop.clone();
            }
        }
        _ => n.set_up_pop(&up),
    }
}

#[derive(Debug, Default)]
pub struct Audit {
    /// 24 小時內比對過的（時間，不一樣）
    recent: VecDeque<(u64, bool)>,
    confirmed: u32,
    mismatch: u32,
    mismatch_at: u64,
    unreliable_until: u64,
    probes: u32,
    /// 24 小時內抽查的時間
    probe_times: VecDeque<u64>,
    /// 已經抽查過的節點（每個節點只量一次；量不到機房的也不再問）
    asked: VecDeque<IpAddr>,
}

impl Audit {
    /// 記一次比對（健檢、節點池工作、抽查）
    pub fn note(&mut self, mismatch: bool, now: u64) {
        if mismatch {
            self.mismatch = self.mismatch.saturating_add(1);
            self.mismatch_at = now;
        } else {
            self.confirmed = self.confirmed.saturating_add(1);
        }
        self.recent.push_back((now, mismatch));
        while self
            .recent
            .front()
            .is_some_and(|x| now.saturating_sub(x.0) > DAY_MS || self.recent.len() > AUDIT_RECENT_MAX)
        {
            self.recent.pop_front();
        }
        if !mismatch {
            return;
        }
        let total = self.recent.len();
        let m = self.recent.iter().filter(|x| x.1).count();
        let was = self.unreliable(now);
        // 不可靠期間每一次新的不一致都往後延 24 小時；24 小時沒有新的不一致就自己解除
        if was || (m >= UNRELIABLE_MIN && m * 2 >= total) {
            self.unreliable_until = now + DAY_MS;
            if !was {
                warn!("上游給的節點有 {m} 個（24 小時內比對 {total} 個）從這台量到的機房不一樣：機房切換暫停 24 小時（上游可能有多條對外線路）");
            }
        }
    }

    pub fn unreliable(&self, now: u64) -> bool {
        now < self.unreliable_until
    }

    /// 要不要用一個抽查名額量這個節點（10 分鐘 1 個、24 小時 24 個、每個節點一次；`lite` 30 分鐘 1 個、8 個）
    pub fn take_slot(&mut self, ip: IpAddr, now: u64, lite: bool) -> bool {
        if self.asked.contains(&ip) {
            return false;
        }
        while self.probe_times.front().is_some_and(|t| now.saturating_sub(*t) >= DAY_MS) {
            self.probe_times.pop_front();
        }
        let (gap, max) = if lite {
            (AUDIT_GAP_LITE_MS, AUDIT_DAY_MAX_LITE)
        } else {
            (AUDIT_GAP_MS, AUDIT_DAY_MAX)
        };
        if self.probe_times.len() >= max || self.probe_times.back().is_some_and(|t| now.saturating_sub(*t) < gap) {
            return false;
        }
        self.probe_times.push_back(now);
        self.probes = self.probes.saturating_add(1);
        if self.asked.len() >= AUDIT_ASKED_MAX {
            self.asked.pop_front();
        }
        self.asked.push_back(ip);
        true
    }

    pub fn probes_24h(&self, now: u64) -> usize {
        self.probe_times.iter().filter(|t| now.saturating_sub(**t) < DAY_MS).count()
    }
}

// ============================================================ E7 比原本慢就退回

// 3.5.0 F9（E7 第二版）：比握手時間（連線＋TLS 握手，`Timing::handshake_ms()`，跟 F13 同一個函式）、台灣加權、
// 連續兩次（相隔 10 分鐘以上）才退回、退回 15 分鐘（`cdn.lite` 1 小時）、到期後有人查才重驗、重驗一次不慢就回台灣

/// 台灣加權：`台灣握手 × 0.7 > 原本握手 ＋ 10 毫秒` 才算慢（偏向台灣）
pub const SLOWER_TW_WEIGHT: f64 = 0.7;
pub const SLOWER_ABS_MS: f64 = 10.0;
/// 第一次慢之後，至少隔多久的第二次驗證才算確認
pub const SLOWER_CONFIRM_GAP_MS: u64 = 10 * 60_000;
/// 第一次慢的紀錄（`slow1`）多久沒確認就作廢、重來
pub const SLOWER_FIRST_TTL_MS: u64 = DAY_MS;
/// 確認比原本慢之後退回多久（不走失敗的逐次拉長）；到期後有人查這個網域才重驗
pub const SLOWER_RETEST_MS: u64 = 15 * 60_000;
pub const SLOWER_RETEST_LITE_MS: u64 = HOUR_MS;
/// 保險絲：最近一小時兩邊都量到的驗證裡「比原本慢」超過 30%（至少 10 次）→ 6 小時內不判
pub const FUSE_RATE: f64 = 0.30;
pub const FUSE_MIN: u32 = 10;
pub const FUSE_MS: u64 = 6 * HOUR_MS;

/// 台灣節點的握手時間算不算比原本慢（3.5.0 F9：加權 0.7、多 10 毫秒以上；進去要兩次、回來只要一次，沒有另外的遲滯）
pub fn slower_than(tw: f64, orig: f64) -> bool {
    // 浮點數的邊界：剛好相等（例如 110 × 0.7 對 67 ＋ 10）不算慢
    tw * SLOWER_TW_WEIGHT - (orig + SLOWER_ABS_MS) > 1e-9
}

/// 每分鐘一格、60 格（固定大小）
#[derive(Debug)]
pub struct SlowerFuse {
    ring: Vec<(u32, u16, u16)>,
    until: u64,
    trips: u32,
}

impl Default for SlowerFuse {
    fn default() -> SlowerFuse {
        SlowerFuse {
            ring: vec![(u32::MAX, 0, 0); 60],
            until: 0,
            trips: 0,
        }
    }
}

impl SlowerFuse {
    pub fn active(&self, now: u64) -> bool {
        now < self.until
    }

    /// 最近一小時（兩邊都量到的驗證數，其中「比原本慢」的數）
    pub fn window(&self, now: u64) -> (u32, u32) {
        let m = (now / 60_000) as u32;
        self.ring
            .iter()
            .filter(|x| x.0 != u32::MAX && m.wrapping_sub(x.0) < 60)
            .fold((0, 0), |a, x| (a.0 + x.1 as u32, a.1 + x.2 as u32))
    }

    /// 記一次兩邊都量到的驗證；回傳保險絲是不是這一次跳的（跳了這一次也照驗證通過處理）
    pub fn note(&mut self, slower: bool, now: u64) -> bool {
        let m = (now / 60_000) as u32;
        let slot = &mut self.ring[(m % 60) as usize];
        if slot.0 != m {
            *slot = (m, 0, 0);
        }
        slot.1 = slot.1.saturating_add(1);
        if slower {
            slot.2 = slot.2.saturating_add(1);
        }
        if !slower || self.active(now) {
            return false;
        }
        let (total, slow) = self.window(now);
        if slow >= FUSE_MIN && slow as f64 > total as f64 * FUSE_RATE {
            self.until = now + FUSE_MS;
            self.trips = self.trips.saturating_add(1);
            warn!("最近一小時 {total} 個驗證裡有 {slow} 個「台灣節點比原本慢」：多半是線路壅塞或量測問題，6 小時內不再判「比原本慢」（照驗證通過處理）");
            return true;
        }
        false
    }

    pub fn until(&self, now: u64) -> u64 {
        if self.active(now) {
            self.until
        } else {
            0
        }
    }
}

// ============================================================ 狀態

/// 線路感知的狀態（在 `State` 裡，跟著狀態鎖；重新啟動、重新載入設定清空）
#[derive(Debug, Default)]
pub struct Line {
    pub(crate) reach: Arc<Reach>,
    wan_epoch: u32,
    stale: bool,
    elig: [Elig; 2],
    health: Vec<PopHealth>,
    holds: Vec<Hold>,
    /// 24 小時內的暫緩：（CDN，家族，時間）
    switches: Vec<(&'static str, u8, u64)>,
    pop_switches: u32,
    pop_switch_at: u64,
    pop_flapping: u32,
    pop_flapping_at: u64,
    pub(crate) audit: Audit,
    pub(crate) fuse: SlowerFuse,
    slower_n: u32,
    slower_at: u64,
}

impl Line {
    pub(crate) fn recompute_reach(&mut self, pools: &Pools, now: u64) {
        self.reach = Arc::new(compute_reach(pools, now));
    }

    /// 一輪定時健檢結束：重算 `reach`、不再是過期的；頭幾輪順便判斷 E5 的資格
    pub(crate) fn after_health(&mut self, pools: &Pools, now: u64) {
        self.recompute_reach(pools, now);
        self.stale = false;
        let reach = self.reach.clone();
        for (i, f) in [&reach.v4, &reach.v6].into_iter().enumerate() {
            let e = &mut self.elig[i];
            // 還沒有任何確認過的節點（節點池還沒建立、這個家族沒有節點）不算一輪
            if e.judged >= ELIG_ROUNDS || f.pops.is_empty() {
                continue;
            }
            e.judged += 1;
            e.streak = if f.multi { e.streak + 1 } else { 0 };
            e.eligible = e.streak >= ELIG_ROUNDS;
        }
    }

    /// WAN 變動：`wanEpoch` 加 1、`reach` 過期、清掉 E5 的連續計數與暫緩、資格重新判斷（不補探測）
    pub(crate) fn wan_changed(&mut self) {
        self.wan_epoch = self.wan_epoch.wrapping_add(1);
        self.stale = true;
        self.elig = Default::default();
        self.holds.clear();
        for h in &mut self.health {
            h.bad_streak = 0;
            h.clean_streak = 0;
        }
    }

    /// 這個（CDN、家族）目前暫緩的機房
    pub(crate) fn held_pop(&self, provider: &str, family: u8, now: u64) -> Option<&str> {
        self.holds
            .iter()
            .find(|h| h.provider == provider && h.family == family && now < h.until)
            .map(|h| h.pop.as_str())
    }

    fn family_eligible(&self, family: u8) -> bool {
        self.elig[fam_idx(family)].eligible
    }

    /// 這台整體為什麼不做機房切換（`None` = 可以）
    fn global_block(&self, on: bool, env: LineEnv, now: u64) -> Option<&'static str> {
        if !on {
            Some("disabled")
        } else if env.chained {
            Some("chained")
        } else if self.audit.unreliable(now) {
            Some("chain-pop-unreliable")
        } else if !env.memory_normal {
            Some("memory")
        } else {
            None
        }
    }

    /// 這個（CDN、家族）能不能做機房切換（`None` = 可以；否則是 `popSwitch.reason` 的代碼）
    pub(crate) fn block(&self, provider: &str, family: u8, on: bool, env: LineEnv, now: u64) -> Option<&'static str> {
        if Cdn::is_nearest(provider) {
            return Some("nearest-provider");
        }
        self.global_block(on, env, now)
            .or_else(|| (!self.family_eligible(family)).then_some("single-pop"))
    }

    /// 一輪健檢（一家、一個家族）的機房彙總與切換規則；回傳這一輪排序要往後排的機房
    pub(crate) fn pop_round(
        &mut self,
        provider: &'static str,
        family: u8,
        mut aggs: Vec<PopHealth>,
        block: Option<&'static str>,
        now: u64,
    ) -> Option<String> {
        let label = providers::label(provider);
        for h in aggs.iter_mut() {
            let (b, c) = self
                .health
                .iter()
                .find(|p| p.provider == provider && p.family == family && p.pop == h.pop)
                .map(|p| (p.bad_streak, p.clean_streak))
                .unwrap_or((0, 0));
            h.bad_streak = if h.degraded() { b.saturating_add(1) } else { 0 };
            h.clean_streak = if h.clean() { c.saturating_add(1) } else { 0 };
        }
        // 暫緩中：到期、兩邊都差、不再符合資格 → 結束，回到節點層級的排序；連續計數歸零
        if let Some(i) = self.holds.iter().position(|h| h.provider == provider && h.family == family) {
            let h = &self.holds[i];
            let other_bad = aggs.iter().any(|a| a.pop != h.pop && a.nodes > 0 && a.fail_rate >= POP_BAD_RATE);
            let why = if now >= h.until {
                Some("4 小時到期")
            } else if other_bad {
                Some("另一個機房也變差，兩邊都差時不切")
            } else {
                block.map(|_| "不再符合機房切換的條件")
            };
            if let Some(why) = why {
                info!("{label} IPv{family} 機房 {} 的暫緩結束（{why}），回到依延遲的排序", h.pop);
                self.holds.remove(i);
                for a in aggs.iter_mut() {
                    a.bad_streak = 0;
                    a.clean_streak = 0;
                }
            }
        }
        let holding = self.holds.iter().any(|h| h.provider == provider && h.family == family);
        if !holding && block.is_none() {
            self.try_hold(provider, family, &mut aggs, now);
        }
        // 換上這一輪的彙總（最多 POP_HEALTH_MAX 筆）
        self.health.retain(|p| !(p.provider == provider && p.family == family));
        for a in aggs {
            if self.health.len() >= POP_HEALTH_MAX {
                break;
            }
            self.health.push(a);
        }
        self.held_pop(provider, family, now).map(String::from)
    }

    fn try_hold(&mut self, provider: &'static str, family: u8, aggs: &mut [PopHealth], now: u64) {
        let label = providers::label(provider);
        // 變差的機房：失敗率最高的那一個
        let Some(pi) = (0..aggs.len())
            .filter(|&i| aggs[i].bad_streak >= POP_BAD_ROUNDS)
            .max_by(|&a, &b| aggs[a].fail_rate.total_cmp(&aggs[b].fail_rate))
        else {
            return;
        };
        let bad_ms = aggs[pi].median_ms;
        let near = |q: Option<f64>| match (bad_ms, q) {
            // 變差的機房已經沒有可用節點：另一個比較慢也比連不上好
            (None, Some(_)) => true,
            (Some(b), Some(q)) => q <= b + POP_NEAR_MS,
            _ => false,
        };
        let Some(qi) = (0..aggs.len()).find(|&i| i != pi && aggs[i].clean_streak >= POP_BAD_ROUNDS && near(aggs[i].median_ms)) else {
            return;
        };
        let (pop, other) = (aggs[pi].pop.clone(), aggs[qi].pop.clone());
        aggs[pi].bad_streak = 0;
        self.switches.retain(|s| now.saturating_sub(s.2) < DAY_MS);
        let n = self.switches.iter().filter(|s| s.0 == provider && s.1 == family).count();
        if n >= POP_MAX_HOLDS_24H {
            self.pop_flapping = self.pop_flapping.saturating_add(1);
            self.pop_flapping_at = now;
            warn!("{label} IPv{family} 機房 {pop} 又連續 {POP_BAD_ROUNDS} 輪變差：24 小時內已經暫緩 {n} 次，這次不切（避免來回）");
            return;
        }
        self.switches.push((provider, family, now));
        self.pop_switches = self.pop_switches.saturating_add(1);
        self.pop_switch_at = now;
        self.holds.push(Hold {
            provider,
            family,
            pop: pop.clone(),
            until: now + POP_HOLD_MS,
            other: other.clone(),
        });
        warn!(
            "{label} IPv{family} 機房 {pop} 連續 {POP_BAD_ROUNDS} 輪失敗率 {:.0}% 以上，機房 {other} 正常：{pop} 的節點暫緩 4 小時（排到其他可用節點後面，不移出節點池）",
            POP_BAD_RATE * 100.0
        );
    }

    pub(crate) fn note_slower(&mut self, now: u64) {
        self.slower_n = self.slower_n.saturating_add(1);
        self.slower_at = now;
    }
}

/// 節點池工作換上新的節點池之前（3.5.0 E4）：舊池裡還在等確認（`upPop`）的節點，這次節點池工作在本機量到了
/// （新節點是重新建的、沒有 `upPop`）就比對、計數。保留舊節點池時（節點照舊、`upPop` 還在）不算
pub(crate) fn audit_rebuilt(st: &mut crate::cdn::State, name: &str, pool4: &[PoolNode], pool6: &[PoolNode], now: u64) {
    let nearest = Cdn::is_nearest(name);
    let Some(d) = st.pools.p.get(name) else { return };
    let (mut same, mut moved) = (0u32, 0u32);
    for (old, new) in [(&d.pool4, pool4), (&d.pool6, pool6)] {
        for o in old.iter() {
            let Some(up) = o.up_pop() else { continue };
            let Some(n) = new.iter().find(|n| n.ip == o.ip && locally_measured(n)) else {
                continue;
            };
            let check = compare_pop(up, n.pop_str(), nearest);
            st.line.audit.note(check != PopCheck::Same, now);
            if check == PopCheck::Same {
                same += 1;
            } else {
                moved += 1;
            }
        }
    }
    if same + moved > 0 {
        info!(
            "{}：上游給的節點這次節點池工作量到機房一樣 {same} 個、不一樣 {moved} 個（一律用這台量到的）",
            providers::label(name)
        );
    }
}

#[cfg(test)]
impl Line {
    /// 測試用：記住的時間全部往前推 `ms`（等於時間過了 `ms`）
    pub(crate) fn age(&mut self, ms: u64) {
        for h in &mut self.holds {
            h.until = h.until.saturating_sub(ms);
        }
        for s in &mut self.switches {
            s.2 = s.2.saturating_sub(ms);
        }
        self.fuse.until = self.fuse.until.saturating_sub(ms);
        let m = (ms / 60_000) as u32;
        for x in &mut self.fuse.ring {
            if x.0 != u32::MAX {
                x.0 = x.0.saturating_sub(m);
            }
        }
        let a = &mut self.audit;
        a.unreliable_until = a.unreliable_until.saturating_sub(ms);
        for t in a.probe_times.iter_mut() {
            *t = t.saturating_sub(ms);
        }
        for x in a.recent.iter_mut() {
            x.0 = x.0.saturating_sub(ms);
        }
    }
}

// ============================================================ Cdn 的介面

impl Cdn {
    /// 主程式提供「這台目前的情況」（串接中、記憶體壓力）：E4 的抽查與 E5 的切換依它決定做不做。
    /// 沒設 = 沒有串接、記憶體正常。每輪健檢與每次抽查詢問時各呼叫一次（不在查詢路徑上）
    pub fn set_line_env(&self, f: impl Fn() -> LineEnv + Send + Sync + 'static) {
        *self.line_env.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(f));
    }

    pub(crate) fn line_env(&self) -> LineEnv {
        let f = self.line_env.read().unwrap_or_else(|e| e.into_inner()).clone();
        f.map(|f| f()).unwrap_or_default()
    }

    /// WAN 變動（`/api/notify/wan-changed`）：`wanEpoch` 加 1、`reach` 標成過期、清掉 E5 的連續計數與暫緩。
    /// 不因此補跑健檢或掃描，等下一輪定時健檢自然更新（E3）
    pub fn on_wan_changed(&self) {
        self.with_state(|st| st.line.wan_changed());
        info!("WAN 變動：這條線到得了哪些台灣機房等下一輪健檢重新量（不另外探測）；機房切換的連續計數與暫緩清掉");
    }

    /// `/api/status` 的 `cdn` 多帶的觀測欄位：`reach`、`popHealth`、`popSwitch`、`popAudit`、`slowerFuseUntil`
    /// （E3～E5、E7；`slowerFuseUntil` 跳了才有）。在背景工作結束時算好，這裡只複製一份小 JSON
    pub fn observe_json(&self) -> Value {
        let env = self.line_env();
        let now = now_ms();
        let cfg = &self.cfg;
        let st = self.state();
        let l = &st.line;
        let reach = l.reach.clone();
        let (wan_epoch, stale) = (l.wan_epoch, l.stale || env.chained);
        let health: Vec<Value> = l
            .health
            .iter()
            .map(|h| {
                let held = l
                    .holds
                    .iter()
                    .find(|x| x.provider == h.provider && x.family == h.family && x.pop == h.pop && now < x.until);
                json!({
                    "provider": h.provider, "family": h.family, "pop": h.pop, "nodes": h.nodes, "bad": h.bad,
                    "failRate": util::round(h.fail_rate, 3), "medianMs": h.median_ms, "badStreak": h.bad_streak,
                    "held": held.is_some(), "heldUntil": held.map(|x| x.until),
                })
            })
            .collect();
        let holds: Vec<Value> = l
            .holds
            .iter()
            .filter(|h| now < h.until)
            .map(|h| json!({ "provider": h.provider, "family": h.family, "pop": h.pop, "until": h.until, "other": h.other }))
            .collect();
        let global = l.global_block(cfg.pop_switch, env, now);
        let fams: Vec<u8> = [4u8, 6].into_iter().filter(|f| l.family_eligible(*f)).collect();
        let reason = global.unwrap_or(if fams.is_empty() { "single-pop" } else { "ok" });
        let switches24h = l.switches.iter().filter(|s| now.saturating_sub(s.2) < DAY_MS).count();
        let excluded: Vec<Value> = st
            .pools
            .p
            .keys()
            .filter(|n| Cdn::is_nearest(n))
            .map(|n| json!({ "provider": n, "reason": "nearest-provider" }))
            .collect();
        let audit = json!({
            "enabled": cfg.pop_audit, "pending": reach.pending, "confirmed": l.audit.confirmed, "mismatch": l.audit.mismatch,
            "probes24h": l.audit.probes_24h(now), "lastMismatchAt": ms_or_null(l.audit.mismatch_at),
            "chainPopUnreliable": l.audit.unreliable(now),
        });
        let fuse = l.fuse.until(now);
        drop(st);
        let mut o = Map::new();
        o.insert("reach".into(), reach.json(wan_epoch, stale));
        o.insert("popHealth".into(), Value::Array(health));
        o.insert(
            "popSwitch".into(),
            json!({ "enabled": cfg.pop_switch, "eligible": reason == "ok", "reason": reason, "switches24h": switches24h,
                    "eligibleFamilies": fams, "holds": holds, "excluded": excluded }),
        );
        o.insert("popAudit".into(), audit);
        if fuse > 0 {
            o.insert("slowerFuseUntil".into(), json!(fuse));
        }
        Value::Object(o)
    }

    /// 這條線到得了哪些台灣機房（E3 的 `reach`，同 [`Cdn::observe_json`] 裡的那一份）
    pub fn reach_json(&self) -> Value {
        let chained = self.line_env().chained;
        let st = self.state();
        st.line.reach.json(st.line.wan_epoch, st.line.stale || chained)
    }

    /// E2 用的計數與最近時間（見 [`ObserveCounters`]）
    pub fn observe_counters(&self) -> ObserveCounters {
        let now = now_ms();
        let st = self.state();
        let l = &st.line;
        ObserveCounters {
            verify_ok: st.stats.verify_ok,
            verify_fail: st.stats.verify_fail,
            pop_confirmed: l.audit.confirmed,
            pop_mismatch: l.audit.mismatch,
            pop_mismatch_at: secs(l.audit.mismatch_at),
            pop_probes: l.audit.probes,
            pop_switches: l.pop_switches,
            pop_switch_at: secs(l.pop_switch_at),
            pop_flapping: l.pop_flapping,
            pop_flapping_at: secs(l.pop_flapping_at),
            slower_fallback: l.slower_n,
            slower_fallback_at: secs(l.slower_at),
            slower_fuse_until: secs(l.fuse.until(now)),
        }
    }

    /// 串接中的機房抽查（E4）：這個 IP 是節點池裡上游宣稱機房（`upPop`）還沒確認的節點、而且還有抽查名額時，
    /// 回那家 CDN 的名稱；呼叫端用同一個抽查名額對它做一次機房探測，結果交給 [`Cdn::note_local_pop`]。
    ///
    /// 名額：10 分鐘 1 個、24 小時 24 個、每個節點一次（`cdn.lite`：30 分鐘 1 個、8 個）。
    /// `cdn.popAudit` 關、CDN 關、系統時間沒對時、記憶體壓力不是 `Normal` 時一律不抽查。
    /// 回 `Some` 就算用掉一個名額（探測失敗也不還）
    pub fn pop_audit_wanted(&self, ip: IpAddr) -> Option<&'static str> {
        if !self.cfg.enabled || !self.cfg.pop_audit || !kuroshio_net::clock::synced() || !self.line_env().memory_normal {
            return None;
        }
        let ip = unmap(ip);
        let family = if ip.is_ipv6() { 6 } else { 4 };
        let now = now_ms();
        let mut st = self.state();
        let st = &mut *st;
        let name = st
            .pools
            .p
            .iter()
            .find(|(_, d)| d.pool(family).iter().any(|x| x.ip == ip && x.up_pop().is_some()))
            .map(|(n, _)| *n)?;
        if !st.line.audit.take_slot(ip, now, self.cfg.lite) {
            return None;
        }
        providers::get(name).map(|p| p.name)
    }

    /// 本機量到某個節點的機房（E4）：只處理上游宣稱機房（`upPop`）還沒確認的節點——
    /// 一樣就確認；不一樣但還是台灣機房（最近節點型：任何機房）就改用本機量到的；不是台灣機房就照既有的流程標成壞節點。
    /// 不一樣不算上游不可信（不動串接抽查的可疑計數），只計數並在多數不一致時暫停 E5 的機房切換
    pub fn note_local_pop(&self, provider: &str, ip: IpAddr, pop: &str) {
        if pop.is_empty() {
            return;
        }
        let ip = unmap(ip);
        let family = if ip.is_ipv6() { 6 } else { 4 };
        let nearest = Cdn::is_nearest(provider);
        let now = now_ms();
        self.with_state(|st| {
            let Some(d) = st.pools.p.get_mut(provider) else { return };
            let Some(x) = d.pool_mut(family).iter_mut().find(|x| x.ip == ip) else {
                return;
            };
            let Some(up) = x.take_up_pop() else { return };
            let check = compare_pop(&up, pop, nearest);
            if check == PopCheck::Moved {
                x.pop = Some(util::intern(pop));
            }
            st.pools.reach_dirty = true;
            if check == PopCheck::NotTw {
                st.pools.mark_bad(provider, ip, &format!("POP={pop}"));
            }
            st.line.audit.note(check != PopCheck::Same, now);
            if check != PopCheck::Same {
                info!(
                    "{} 節點 {ip}：上游給的機房是 {up}，這台量到的是 {pop}，改用這台量到的（上游可能有多條對外線路）",
                    providers::label(provider)
                );
            }
        });
    }

    /// 同 [`Cdn::add_friend_nodes`]，但每家、每個家族一次最多 `per_batch` 個（E10：確定是別的 ISP 群組的好友降成四分之一）。
    /// 只會變少、不會變多：超過 [`FRIEND_MAX_NODES`] 的照 [`FRIEND_MAX_NODES`] 算；候選名單的總上限不變。
    /// 回傳新增幾個。
    pub fn add_friend_nodes_capped<'a>(&self, nodes: impl IntoIterator<Item = (&'a str, IpAddr)>, per_batch: usize) -> usize {
        self.add_friend_nodes_upto(nodes, per_batch.min(FRIEND_MAX_NODES))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::Num;

    fn node(ip: &str, pop: &str, ms: f64) -> PoolNode {
        let mut n = PoolNode::new(ip.parse().unwrap());
        n.pop = Some(util::intern(pop));
        n.ms = Num::V(ms);
        n
    }

    #[test]
    fn tpe_and_tsa_are_one_city() {
        assert_eq!(city_of("TPE"), "台北");
        assert_eq!(city_of("tsa51"), "台北");
        assert_eq!(city_of("KHH"), "高雄");
        assert_eq!(city_of("RMQ"), city_of("TXG"));
        assert_eq!(city_of("TNN"), "台南");
        assert_eq!(city_of("NRT"), "");
        // TPE＋TSA 是同一個城市：再多節點也不是「兩個機房」
        let f = fam_reach(vec![
            Acc {
                pop: "TPE".into(),
                nodes: 5,
                nets: vec![1, 2, 3],
                provs: vec!["cloudflare"],
                ms: vec![],
            },
            Acc {
                pop: "TSA".into(),
                nodes: 5,
                nets: vec![4, 5],
                provs: vec!["cloudflare"],
                ms: vec![],
            },
        ]);
        assert!(!f.multi);
        assert_eq!(f.pops.len(), 2, "代碼照樣列在資料裡");
        assert_eq!(reach_text(4, &f), "這條線目前只到得了台北機房");
    }

    #[test]
    fn reach_sentence_single_multi_none() {
        let none = FamReach::default();
        assert_eq!(reach_text(4, &none), "這條線目前量不到台灣機房（節點池還沒建立，或節點都連不上）");
        assert_eq!(
            reach_text(6, &none),
            "這條線的 IPv6 目前量不到台灣機房（節點池還沒建立，或節點都連不上）"
        );
        let one = fam_reach(vec![Acc {
            pop: "TPE".into(),
            nodes: 3,
            nets: vec![1, 2],
            provs: vec![],
            ms: vec![],
        }]);
        assert_eq!(reach_text(6, &one), "這條線的 IPv6 目前只到得了台北機房");
        let two = fam_reach(vec![
            Acc {
                pop: "KHH".into(),
                nodes: 2,
                nets: vec![7, 8],
                provs: vec![],
                ms: vec![],
            },
            Acc {
                pop: "TPE".into(),
                nodes: 9,
                nets: vec![1, 2],
                provs: vec![],
                ms: vec![],
            },
        ]);
        assert_eq!(reach_text(4, &two), "這條線目前到得了台北、高雄機房", "依節點數多到少");
        assert!(two.multi);
    }

    #[test]
    fn multi_needs_two_nodes_in_two_prefixes_per_city() {
        let acc = |pop: &str, nodes: u32, nets: Vec<u128>| Acc {
            pop: pop.into(),
            nodes,
            nets,
            provs: vec![],
            ms: vec![],
        };
        // 高雄只有 1 個節點：不算到得了（可以切換的程度）
        assert!(!fam_reach(vec![acc("TPE", 9, vec![1, 2]), acc("KHH", 1, vec![3])]).multi);
        // 高雄 2 個節點但在同一個網段
        assert!(!fam_reach(vec![acc("TPE", 9, vec![1, 2]), acc("KHH", 2, vec![3, 3])]).multi);
        assert!(fam_reach(vec![acc("TPE", 9, vec![1, 2]), acc("KHH", 2, vec![3, 4])]).multi);
        // 台中兩個代碼合起來算一個城市
        assert!(fam_reach(vec![acc("TPE", 2, vec![1, 2]), acc("RMQ", 1, vec![5]), acc("TXG", 1, vec![6])]).multi);
    }

    #[test]
    fn reach_counts_nodes_prefixes_per_pop_and_family() {
        let mut pools = Pools::empty(Arc::new(crate::config::CdnConfig::from_value(&json!({}))));
        let cf = pools::ProviderPools {
            pool4: vec![
                node("192.0.2.1", "TPE", 4.0),
                node("192.0.2.2", "TPE", 5.0),
                node("198.51.100.1", "TPE", 3.0),
                node("198.51.100.9", "KHH", 9.0),
            ],
            pool6: vec![node("2001:db8:1::1", "TPE", 2.0), node("2001:db8:1::2", "TPE", 2.0)],
            ..Default::default()
        };
        let cfr = pools::ProviderPools {
            pool4: vec![node("192.0.2.200", "TPE", 6.0)],
            ..Default::default()
        };
        pools.p.insert("cloudflare", cf);
        pools.p.insert("cloudfront", cfr);
        let r = compute_reach(&pools, 1);
        assert_eq!(r.v4.pops.len(), 2);
        let tpe = &r.v4.pops[0];
        assert_eq!(
            (tpe.pop.as_str(), tpe.city, tpe.nodes, tpe.prefixes, tpe.providers),
            ("TPE", "台北", 4, 2, 2)
        );
        assert_eq!(tpe.median_ms, Some(4.5));
        assert_eq!((r.v4.pops[1].pop.as_str(), r.v4.pops[1].nodes), ("KHH", 1));
        assert!(!r.v4.multi, "高雄只有一個節點");
        assert_eq!(r.v6.pops.len(), 1);
        assert_eq!((r.v6.pops[0].nodes, r.v6.pops[0].prefixes), (2, 1), "IPv6 用 /48");
        let j = r.json(3, false);
        assert_eq!(j["wanEpoch"], 3);
        assert_eq!(j["v4"]["pops"][0]["medianMs"], 4.5);
        assert_eq!(j["v6"]["text"], "這條線的 IPv6 目前只到得了台北機房");
    }

    #[test]
    fn reach_ignores_bad_seed_and_unconfirmed() {
        let mut pools = Pools::empty(Arc::new(crate::config::CdnConfig::from_value(&json!({}))));
        let mut up = node("192.0.2.3", "KHH", 3.0);
        up.set_up_pop("KHH");
        let mut up_bad = node("192.0.2.4", "KHH", 3.0);
        up_bad.set_up_pop("KHH");
        let mut cf = pools::ProviderPools {
            pool4: vec![
                node("192.0.2.1", "TPE", 4.0),
                node("192.0.2.2", "seed", 0.0),
                up,
                up_bad,
                node("198.51.100.1", "HKG", 30.0),
                node("198.51.100.2", "TPE", 4.0),
            ],
            ..Default::default()
        };
        cf.bad.insert(
            "198.51.100.2".parse().unwrap(),
            pools::Bad {
                at: 0,
                reason: "x".into(),
                quality: false,
            },
        );
        cf.bad.insert(
            "192.0.2.4".parse().unwrap(),
            pools::Bad {
                at: 0,
                reason: "x".into(),
                quality: false,
            },
        );
        pools.p.insert("cloudflare", cf);
        let r = compute_reach(&pools, 1);
        assert_eq!(r.v4.pops.len(), 1);
        assert_eq!((r.v4.pops[0].pop.as_str(), r.v4.pops[0].nodes), ("TPE", 1));
        assert_eq!(
            (r.unconfirmed, r.pending),
            (1, 2),
            "上游宣稱的另外計；壞的不算還沒確認、但還在等抽查"
        );
    }

    #[test]
    fn compare_and_mark_incoming() {
        assert_eq!(compare_pop("TPE", "tpe51", false), PopCheck::Same);
        assert_eq!(compare_pop("TPE", "KHH", false), PopCheck::Moved);
        assert_eq!(compare_pop("TPE", "HKG", false), PopCheck::NotTw);
        assert_eq!(compare_pop("NRT", "HKG", true), PopCheck::Moved, "最近節點型：哪個機房都能用");
        // 上游帶來的 upPop 一律先拿掉
        let mut n = node("192.0.2.1", "TPE", 1.0);
        n.set_up_pop("XXX");
        mark_incoming(&mut n, None);
        assert_eq!(n.up_pop(), Some("TPE"));
        // 這台原本就有、機房一樣：不放
        let mut n = node("192.0.2.1", "TPE", 1.0);
        mark_incoming(&mut n, Some(&node("192.0.2.1", "TPE", 3.0)));
        assert_eq!(n.up_pop(), None);
        assert!(n.extra.is_empty());
        // 這台原本就有、本機量到的不一樣：以本機為準
        let mut n = node("192.0.2.1", "TPE", 1.0);
        mark_incoming(&mut n, Some(&node("192.0.2.1", "KHH", 3.0)));
        assert_eq!((n.up_pop(), n.pop_str()), (None, "KHH"));
        // 這台原本的也還沒確認、或是種子：照上游的、等量
        let mut own = node("192.0.2.1", "KHH", 3.0);
        own.set_up_pop("KHH");
        let mut n = node("192.0.2.1", "TPE", 1.0);
        mark_incoming(&mut n, Some(&own));
        assert_eq!(n.up_pop(), Some("TPE"));
        let mut n = node("192.0.2.1", "TPE", 1.0);
        mark_incoming(&mut n, Some(&node("192.0.2.1", "seed", 0.0)));
        assert_eq!(n.up_pop(), Some("TPE"));
        // 上游的種子不記
        let mut n = node("192.0.2.1", "seed", 0.0);
        mark_incoming(&mut n, None);
        assert_eq!(n.up_pop(), None);
    }

    #[test]
    fn audit_slots_are_capped_and_lite_reduces() {
        let ip = |i: u32| IpAddr::V4(std::net::Ipv4Addr::from(0xC000_0200 + i));
        let mut a = Audit::default();
        let t0 = 10 * DAY_MS;
        assert!(a.take_slot(ip(1), t0, false));
        assert!(!a.take_slot(ip(1), t0 + HOUR_MS, false), "每個節點一次");
        assert!(!a.take_slot(ip(2), t0 + AUDIT_GAP_MS - 1, false), "10 分鐘 1 個");
        let mut n = 1;
        let mut t = t0;
        for i in 2..138 {
            t += AUDIT_GAP_MS;
            if a.take_slot(ip(i), t, false) {
                n += 1;
            }
        }
        assert_eq!(n, AUDIT_DAY_MAX, "24 小時最多 24 個");
        assert_eq!(a.probes_24h(t), AUDIT_DAY_MAX);
        // 一天之後名額回來
        assert!(a.take_slot(ip(500), t0 + DAY_MS + AUDIT_GAP_MS, false));
        // 小機器減量：30 分鐘 1 個、一天 8 個
        let mut a = Audit::default();
        let mut n = 0;
        let mut t = t0;
        // 23 小時內（同一個 24 小時窗）
        for i in 0..138 {
            t += AUDIT_GAP_MS;
            if a.take_slot(ip(i), t, true) {
                n += 1;
            }
        }
        assert_eq!(n, AUDIT_DAY_MAX_LITE);
        let mut a = Audit::default();
        assert!(a.take_slot(ip(1), t0, true));
        assert!(!a.take_slot(ip(2), t0 + AUDIT_GAP_MS, true));
        assert!(a.take_slot(ip(2), t0 + AUDIT_GAP_LITE_MS, true));
    }

    #[test]
    fn pop_mismatch_majority_sets_unreliable_and_recovers_after_24h() {
        let mut a = Audit::default();
        let t0 = 10 * DAY_MS;
        // 3 個不一致、多數：還不到 4 個
        for _ in 0..3 {
            a.note(true, t0);
        }
        assert!(!a.unreliable(t0));
        a.note(true, t0 + 1);
        assert!(a.unreliable(t0 + 1), "4 個、一半以上");
        // 24 小時內有新的不一致就往後延
        a.note(true, t0 + 12 * HOUR_MS);
        assert!(a.unreliable(t0 + 30 * HOUR_MS));
        assert!(!a.unreliable(t0 + 12 * HOUR_MS + DAY_MS), "24 小時沒有新的不一致：自己解除");
        // 不到一半不算
        let mut a = Audit::default();
        for _ in 0..10 {
            a.note(false, t0);
        }
        for _ in 0..4 {
            a.note(true, t0);
        }
        assert!(!a.unreliable(t0));
        assert_eq!((a.confirmed, a.mismatch), (10, 4));
    }

    fn agg(pop: &str, nodes: u32, bad: u32, ms: Option<f64>, prefixes: u32) -> PopHealth {
        PopHealth {
            provider: "cloudflare",
            family: 4,
            pop: pop.into(),
            nodes,
            bad,
            fail_rate: bad as f64 / nodes.max(1) as f64,
            median_ms: ms,
            usable_prefixes: prefixes,
            bad_streak: 0,
            clean_streak: 0,
        }
    }

    fn rounds(l: &mut Line, n: usize, t: &mut u64, a: impl Fn() -> Vec<PopHealth>, block: Option<&'static str>) -> Option<String> {
        let mut r = None;
        for _ in 0..n {
            *t += 30 * 60_000;
            r = l.pop_round("cloudflare", 4, a(), block, *t);
        }
        r
    }

    #[test]
    fn pop_health_aggregates_by_old_pop() {
        let n = |pop: &str, ok: bool, ip: &str, ms: f64| RoundNode {
            pop: pop.into(),
            ok,
            ms,
            ip: ip.parse().unwrap(),
        };
        let a = aggregate(
            "cloudflare",
            4,
            &[
                n("TPE", true, "192.0.2.1", 4.0),
                n("TPE", true, "198.51.100.1", 6.0),
                // 壞掉的節點（這一輪量不到機房）算在原本的機房
                n("TPE", false, "198.51.100.2", f64::INFINITY),
                n("KHH", false, "192.0.2.9", f64::INFINITY),
                n("seed", true, "192.0.2.10", 1.0),
            ],
        );
        assert_eq!(a.len(), 2);
        let tpe = a.iter().find(|x| x.pop == "TPE").unwrap();
        assert_eq!((tpe.nodes, tpe.bad, tpe.usable_prefixes, tpe.median_ms), (3, 1, 2, Some(5.0)));
        assert!((tpe.fail_rate - 1.0 / 3.0).abs() < 1e-9);
        assert!(tpe.degraded(), "失敗率 33%、3 個節點");
        let khh = a.iter().find(|x| x.pop == "KHH").unwrap();
        assert_eq!((khh.nodes, khh.bad, khh.median_ms), (1, 1, None));
        assert!(!khh.degraded(), "1 個節點壞掉不算機房變差（樣本太少）");
    }

    #[test]
    fn hold_rules_pure() {
        let bad_tpe = || vec![agg("TPE", 5, 2, Some(4.0), 3), agg("KHH", 3, 0, Some(12.0), 2)];
        let mut l = Line::default();
        let mut t = 10 * DAY_MS;
        assert_eq!(rounds(&mut l, 2, &mut t, bad_tpe, None), None, "兩輪還不夠");
        assert_eq!(rounds(&mut l, 1, &mut t, bad_tpe, None).as_deref(), Some("TPE"), "連續 3 輪");
        assert_eq!(l.pop_switches, 1);
        // 不提早結束：TPE 變好也照樣暫緩
        let ok = || vec![agg("TPE", 5, 0, Some(4.0), 3), agg("KHH", 3, 0, Some(12.0), 2)];
        assert_eq!(rounds(&mut l, 2, &mut t, ok, None).as_deref(), Some("TPE"));
        // 另一個機房太遠（多 20 毫秒以上）：不切
        let far = || vec![agg("TPE", 5, 2, Some(4.0), 3), agg("KHH", 3, 0, Some(30.0), 2)];
        let mut l2 = Line::default();
        assert_eq!(rounds(&mut l2, 5, &mut t, far, None), None);
        // 被擋（不符合資格）：只彙總
        let mut l3 = Line::default();
        assert_eq!(rounds(&mut l3, 5, &mut t, bad_tpe, Some("single-pop")), None);
        assert_eq!(l3.health.len(), 2);
        assert_eq!(l3.health[0].bad_streak, 5, "彙總照記");
    }

    #[test]
    fn slower_threshold_and_fuse() {
        // 3.5.0 F9：台灣 × 0.7 > 原本 ＋ 10 毫秒
        assert!(!slower_than(110.0, 67.0), "77 對 77：不算");
        assert!(slower_than(110.0, 66.9));
        assert!(!slower_than(100.0, 60.0), "台灣比較慢 40 毫秒，但加權後 70 對 70：不算（偏向台灣）");
        let mut f = SlowerFuse::default();
        let t0 = 10 * DAY_MS;
        for _ in 0..20 {
            assert!(!f.note(false, t0));
        }
        for i in 0..9 {
            assert!(!f.note(true, t0 + i), "還不到 10 次");
        }
        assert!(f.note(true, t0 + 10), "10 次、超過 30%");
        assert!(f.active(t0 + FUSE_MS - 1) && !f.active(t0 + 10 + FUSE_MS));
        assert_eq!(f.window(t0 + 2 * HOUR_MS), (0, 0), "一小時之前的不算");
    }
}
