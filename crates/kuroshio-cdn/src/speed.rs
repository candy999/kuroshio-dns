//! 節點測速的相對評分（3.5.0，規格 11 B1）：全部是純函式，節點池工作與離線重播共用。
//!
//! 以前（3.4.x）：
//! - 「慢」＝低於絕對的 1 MB/s：慢的線路（例如 2 Mbps）上每個節點都被罰，等於沒有區別。
//! - 「幾乎一樣」＝最快與最慢差 5% 以內：快的線路上 8 MiB 不到 0.2 秒就收完，量到的速度雜訊很大
//!   （Windows 實測 Cloudflare 各節點差 27%），瓶頸減量不啟動，每個節點都收滿 8 MiB。
//! - 排序直接比速度：61.2 與 60.8 MB/s 只是雜訊，卻排在延遲之前決定名次。
//!
//! 現在：
//! - 誤差範圍 [`tolerance`] 依傳輸時間決定（越短越大）。
//! - 「慢」跟同一家其他節點比（[`speed_ref`]、[`is_slow`]），另有絕對下限 [`SPEED_FLOOR`]（真的壞掉的）。
//! - 排序先分級再比（[`speed_class`]）：差在誤差範圍內的同一級，同一級之間由延遲決定。
//!
//! 測速的流量不變或更少：每個節點最多還是一次下載，瓶頸減量啟動的機會變多。

use kuroshio_net::probe::SpeedSample;
use std::cmp::Ordering;

/// 誤差範圍的係數（3.5.0 F16，規格 11 的 Q6 定案）：`clamp(0.05 + 0.035 ÷ √秒, 0.06, 0.18)`。
/// 依據 W3、D7 的實測（不含 TTFB 的速度）：0.13 秒差到 9%、1.5 秒 4%、3.8 秒 4～5%，每一段都留 1.5 倍以上。
/// 3.4.x 看到的「差 27%」是把 TTFB 算進速度造成的（3.5.0 的 `download_sample()` 收到標頭之後才開始算）
pub const TOL_BASE: f64 = 0.05;
pub const TOL_PER_SQRT_SEC: f64 = 0.035;
pub const TOL_MIN: f64 = 0.06;
pub const TOL_MAX: f64 = 0.18;
/// 「慢」：低於這一家參考速度（中位數）的幾成
pub const SLOW_RATIO: f64 = 0.5;
/// 絕對下限（MB/s）：低於它不管別人多慢都算慢（真的壞掉的）
pub const SPEED_FLOOR: f64 = 0.1;
/// 量到速度的節點不到這麼多個時，不做相對的判斷（沒有東西可以比）
pub const REF_MIN_NODES: usize = 3;
/// 舊規則的門檻（MB/s）：舊的 `pools.json`（節點沒有 `slow`）與 `pool.relativeSpeed: false` 沿用
pub const LEGACY_SLOW_MBPS: f64 = 1.0;
/// 快測（只收 1 MiB）能確認的上限（MB/s）：1 MiB 大半在 TCP 慢啟動階段，量到的速度比完整測低，
/// 不能直接跟參考速度的一半比；只能確認「不低於 min(參考 × 0.5, 這個值)」。
/// 3.5.0 F16 起只在沒有「前 1 MiB」參考（[`quick_ref`]）時的退路裡用
pub const QUICK_CAP_MBPS: f64 = 1.0;

/// 「幾乎一樣」的誤差範圍（比例）：傳輸時間越短越大。
/// 0.13 秒 → 約 0.147、0.5 秒 → 約 0.099、1.5 秒 → 約 0.079、3.8 秒 → 約 0.068
pub fn tolerance(secs: f64) -> f64 {
    if !secs.is_finite() || secs <= 0.0 {
        return TOL_MAX;
    }
    (TOL_BASE + TOL_PER_SQRT_SEC / secs.sqrt()).clamp(TOL_MIN, TOL_MAX)
}

/// 前幾個節點的速度幾乎一樣：量到的是瓶頸（這台的線路、或 CDN 每條連線的限速），回中位數。
/// 「幾乎一樣」＝最快與最慢的差在這幾個樣本裡最大的誤差範圍以內。
/// 不再要求 1 MB/s 以上：慢的線路上也是瓶頸；只排除量不到（0）與絕對下限以下的
pub fn same_speed(v: &[SpeedSample]) -> Option<f64> {
    if v.is_empty() || v.iter().any(|s| !s.mbps.is_finite() || s.mbps < SPEED_FLOOR) {
        return None;
    }
    let max = v.iter().map(|s| s.mbps).fold(f64::MIN, f64::max);
    let min = v.iter().map(|s| s.mbps).fold(f64::MAX, f64::min);
    let tol = v.iter().map(|s| tolerance(s.secs)).fold(0.0, f64::max);
    if (max - min) / max > tol {
        return None;
    }
    Some(median(v.iter().map(|s| s.mbps).collect()))
}

/// 3.4.x 的判斷：都在 1 MB/s 以上、最快與最慢差 5% 以內（`pool.relativeSpeed: false` 與離線重播用）
pub fn same_speed_legacy(v: &[f64]) -> Option<f64> {
    if v.is_empty() || v.iter().any(|s| !s.is_finite() || *s < LEGACY_SLOW_MBPS) {
        return None;
    }
    let max = v.iter().copied().fold(f64::MIN, f64::max);
    let min = v.iter().copied().fold(f64::MAX, f64::min);
    if (max - min) / max > 0.05 {
        return None;
    }
    Some(median(v.to_vec()))
}

fn median(mut s: Vec<f64>) -> f64 {
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    s[s.len() / 2]
}

/// 這一家的參考速度：量到速度（> 0）的節點的中位數；不到 [`REF_MIN_NODES`] 個回 None（不做相對的判斷）
pub fn speed_ref(speeds: impl IntoIterator<Item = f64>) -> Option<f64> {
    let v: Vec<f64> = speeds.into_iter().filter(|s| s.is_finite() && *s > 0.0).collect();
    (v.len() >= REF_MIN_NODES).then(|| median(v))
}

/// 這個節點慢不慢：連樂觀的估計（加上它自己的誤差範圍）都不到參考速度的一半，或低於絕對下限。
/// 整家都慢（線路塞車）時參考速度也低，一個都不會標——那不是節點的問題。
/// `mbps` 是 0（量不到）不算慢：沒有證據
pub fn is_slow(mbps: f64, secs: f64, reference: Option<f64>) -> bool {
    if !mbps.is_finite() || mbps <= 0.0 {
        return false;
    }
    if mbps < SPEED_FLOOR {
        return true;
    }
    match reference {
        Some(r) => mbps * (1.0 + tolerance(secs)) < r * SLOW_RATIO,
        None => false,
    }
}

/// 快測（1 MiB）的門檻（退路：沒有 [`quick_ref`] 時）：速度不低於它才算「確認不慢」
pub fn quick_floor(reference: f64, secs: f64) -> f64 {
    (reference * SLOW_RATIO).min(QUICK_CAP_MBPS) * (1.0 - tolerance(secs))
}

/// 快測的參考速度（3.5.0 F16）：完整測的樣本「收到第 1 MiB」時的速度（同一條連線順便記的 `head_secs`）的中位數。
/// 同類相比：快測量的也是前 1 MiB（大半在 TCP 慢啟動，每一家 CDN 開頭的快慢不一樣）。
/// 量到 `head_secs` 的樣本不到 [`REF_MIN_NODES`] 個（假的網路、檔案不到 1 MiB、舊資料）回 None：照 [`quick_floor`] 的退路
pub fn quick_ref(samples: &[SpeedSample]) -> Option<f64> {
    let v: Vec<f64> = samples
        .iter()
        .filter(|s| s.head_secs > 0.0 && s.head_secs.is_finite())
        .map(|s| (kuroshio_net::probe::HEAD_BYTES as f64 / 1_048_576.0 / s.head_secs * 100.0).round() / 100.0)
        .collect();
    (v.len() >= REF_MIN_NODES).then(|| median(v))
}

/// 快測的門檻（3.5.0 F16）：`quick_ref × 0.5 × (1 − tolerance(快測的秒數))`
pub fn quick_floor_ref(quick_ref: f64, secs: f64) -> f64 {
    quick_ref * SLOW_RATIO * (1.0 - tolerance(secs))
}

/// 沒量到速度的節點排在量到的後面、慢的前面
pub const CLASS_UNMEASURED: u8 = 253;
/// 慢的節點排最後
pub const CLASS_SLOW: u8 = 254;

/// 速度的級別（0 最好）：跟這一家最快的差在誤差範圍內是第 0 級，每再慢一個誤差範圍多一級。
/// 級別相同的節點速度「分不出來」，由延遲決定名次
pub fn speed_class(mbps: Option<f64>, slow: bool, best: f64, tol: f64) -> u8 {
    if slow {
        return CLASS_SLOW;
    }
    let Some(s) = mbps.filter(|s| s.is_finite() && *s > 0.0) else {
        return CLASS_UNMEASURED;
    };
    if !(best.is_finite() && best > 0.0) || s >= best {
        return 0;
    }
    let step = -(1.0 - tol.clamp(TOL_MIN, TOL_MAX)).ln();
    (((best / s).ln() / step).floor() as u32).min(250) as u8
}

/// 排序用的一個節點（節點池工作與離線重播共用）
#[derive(Debug, Clone, PartialEq)]
pub struct Ranked {
    pub loss: f64,
    pub ms: f64,
    /// MB/s；None 或 0 = 沒量到
    pub mbps: Option<f64>,
    /// 傳輸時間（秒；沒有就當成最短，誤差範圍最大）
    pub secs: f64,
    pub slow: bool,
}

fn cmp_f(a: f64, b: f64) -> Ordering {
    a.partial_cmp(&b).unwrap_or(Ordering::Equal)
}

/// 3.4.x 的排序：丟包 → 速度（大的在前，直接比數字）→ 延遲
pub fn cmp_legacy(a: &Ranked, b: &Ranked) -> Ordering {
    cmp_f(a.loss, b.loss)
        .then(cmp_f(b.mbps.unwrap_or(0.0), a.mbps.unwrap_or(0.0)))
        .then(cmp_f(a.ms, b.ms))
}

/// 這一批節點的（最快的速度，分級用的誤差範圍＝量到的樣本裡最大的）
pub fn class_basis(v: &[Ranked]) -> (f64, f64) {
    let measured = || v.iter().filter(|x| !x.slow && x.mbps.is_some_and(|s| s > 0.0));
    let best = measured().filter_map(|x| x.mbps).fold(0.0, f64::max);
    let tol = measured().map(|x| tolerance(x.secs)).fold(TOL_MIN, f64::max);
    (best, tol)
}

/// 3.5.0 的排序：丟包 → 速度的級別 → 延遲
pub fn cmp_relative(a: &Ranked, b: &Ranked, basis: (f64, f64)) -> Ordering {
    let c = |x: &Ranked| speed_class(x.mbps, x.slow, basis.0, basis.1);
    cmp_f(a.loss, b.loss).then(c(a).cmp(&c(b))).then(cmp_f(a.ms, b.ms))
}

/// 排好的順序（索引）。`relative = false` 是 3.4.x 的排序
pub fn order(v: &[Ranked], relative: bool) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..v.len()).collect();
    if relative {
        let basis = class_basis(v);
        idx.sort_by(|&a, &b| cmp_relative(&v[a], &v[b], basis));
    } else {
        idx.sort_by(|&a, &b| cmp_legacy(&v[a], &v[b]));
    }
    idx
}
