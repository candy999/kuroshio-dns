//! 通訊類網域（3.5.0，規格 11 B6）：推播與通訊服務的網域不被清單誤擋、快到期就預取、記憶體吃緊時優先留在快取、
//! 不做跨 CDN 探索（長連線重連的代價高，漏接通知比多一個連線嚴重）。
//!
//! 3.5.0 只內建有官方文件寫明主機名稱的兩組（Apple 推播、Firebase 雲端訊息）。其他通訊服務（LINE、WhatsApp…）
//! 等台灣實測之後再加。使用者可以用 `resolver.keepNames` 自己加（最多 64 個後綴）。
//!
//! 比對只在已經是慢路徑的地方呼叫（過濾器判定要擋之後、快取快到期時、記憶體控制淘汰時），
//! 每次是幾十個後綴的字串比較、不配置。
//!
//! 3.5.0 F11（規格 11 第 6 節）：內建一定通過的服務再加五類（時間同步、連線偵測、憑證撤銷、系統與安全更新、地震速報），
//! 每一類一組固定的旗標（[`Flags`]：不被清單擋、記憶體吃緊時先留、快到期就預取、不改寫 CDN 答案）。
//! 誰優先：使用者的自訂規則（擋或放行）＞ 內建表 ＞ 訂閱清單；`filter.protectComm` 關掉時新加的五類一律不比對。
//!
//! [`is_comm`] 維持 B6 的意思（推播與使用者自己加的），CDN 的「推播不跨 CDN」照舊用它；新加的五類用 [`flags_of`]／[`no_rewrite`]。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{OnceLock, RwLock};

/// 哪一類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommKind {
    /// Apple 推播（APNs）
    Apns,
    /// Firebase 雲端訊息（FCM）
    Fcm,
    /// 使用者自己加的（`resolver.keepNames`）
    User,
    /// 時間同步（NTP；3.5.0 F11）
    Ntp,
    /// 連線偵測（裝置判斷「有沒有網路」的固定網址；3.5.0 F11）
    NetCheck,
    /// 憑證撤銷（OCSP／CRL；3.5.0 F11）
    Revocation,
    /// 系統與安全更新（3.5.0 F11）：只保證不被清單誤擋，CDN 照常改寫
    Update,
    /// 地震速報（3.5.0 F11）
    Quake,
}

/// 一類服務的固定旗標（3.5.0 F11）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    /// 訂閱清單要擋時放行（自訂規則照樣優先）
    pub spare: bool,
    /// 記憶體吃緊時優先留在快取
    pub hold: bool,
    /// 快到期就預取（同時最多 16 個的名額只給推播、地震速報、使用者自己加的）
    pub prefetch: bool,
    /// 不改寫 CDN 答案（也不做跨 CDN、ECS 探測、不排驗證）
    pub no_rewrite: bool,
}

impl CommKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CommKind::Apns => "apns",
            CommKind::Fcm => "fcm",
            CommKind::User => "user",
            CommKind::Ntp => "ntp",
            CommKind::NetCheck => "netcheck",
            CommKind::Revocation => "revocation",
            CommKind::Update => "update",
            CommKind::Quake => "quake",
        }
    }

    /// 這一類的旗標（規格 11 F11 的表）
    pub const fn flags(self) -> Flags {
        let (spare, hold, prefetch, no_rewrite) = match self {
            // 推播（B6 既有）與使用者自己加的：不擋、先留、預取；CDN 照常改寫
            CommKind::Apns | CommKind::Fcm | CommKind::User => (true, true, true, false),
            CommKind::Ntp | CommKind::NetCheck => (true, true, false, true),
            CommKind::Revocation => (true, false, false, true),
            CommKind::Update => (true, false, false, false),
            CommKind::Quake => (true, true, true, true),
        };
        Flags {
            spare,
            hold,
            prefetch,
            no_rewrite,
        }
    }

    /// 3.5.0 F11 新加的五類（`filter.protectComm` 關掉時不比對；推播與使用者自己加的照 B6）
    pub const fn is_essential(self) -> bool {
        !matches!(self, CommKind::Apns | CommKind::Fcm | CommKind::User)
    }

    /// 全部的類別（統計用的順序）
    pub const ALL: [CommKind; 8] = [
        CommKind::Apns,
        CommKind::Fcm,
        CommKind::User,
        CommKind::Ntp,
        CommKind::NetCheck,
        CommKind::Revocation,
        CommKind::Update,
        CommKind::Quake,
    ];

    /// 在 [`CommKind::ALL`] 裡的位置（每一類一個計數器時用）
    pub const fn index(self) -> usize {
        match self {
            CommKind::Apns => 0,
            CommKind::Fcm => 1,
            CommKind::User => 2,
            CommKind::Ntp => 3,
            CommKind::NetCheck => 4,
            CommKind::Revocation => 5,
            CommKind::Update => 6,
            CommKind::Quake => 7,
        }
    }

    /// `/api/filter/check` 的 `rule`：推播與使用者自己加的照舊是 `builtin-comm`，新加的五類是 `builtin-<類別>`
    pub fn rule(self) -> String {
        if self.is_essential() {
            format!("builtin-{}", self.as_str())
        } else {
            "builtin-comm".to_string()
        }
    }

    /// 日誌與說明用的中文名稱
    pub fn label(self) -> &'static str {
        match self {
            CommKind::Apns | CommKind::Fcm => "推播",
            CommKind::User => "自己加的通訊類",
            CommKind::Ntp => "時間同步",
            CommKind::NetCheck => "連線偵測",
            CommKind::Revocation => "憑證撤銷",
            CommKind::Update => "系統與安全更新",
            CommKind::Quake => "地震速報",
        }
    }
}

/// 內建表的上限（3.5.0 F11 從 64 放寬到 128）
pub const BUILTIN_MAX: usize = 128;

/// 內建的後綴表（最多 [`BUILTIN_MAX`] 筆；等於它或是它的子網域）。這是編譯進去的資料，放真實網域；
/// 測試與文件範例一律用 `example.com`。不確定的不列（規格 11 F11 的「待補」）
pub const COMM_SUFFIXES: &[(&str, CommKind)] = &[
    // Apple Push Notification service（Apple 的開發者文件列出的主機）
    ("push.apple.com", CommKind::Apns),
    // Firebase Cloud Messaging（Google 的文件列出的主機）
    ("fcm.googleapis.com", CommKind::Fcm),
    ("fcmtoken.googleapis.com", CommKind::Fcm),
    ("mtalk.google.com", CommKind::Fcm),
    // ---- 3.5.0 F11：時間同步（NTP 走 UDP 123；驗證台灣節點用 HTTPS，通過不代表那個 IP 有 NTP：不改寫）
    ("pool.ntp.org", CommKind::Ntp),
    ("time.apple.com", CommKind::Ntp),
    ("time.asia.apple.com", CommKind::Ntp),
    ("time-ios.apple.com", CommKind::Ntp),
    ("time-macos.apple.com", CommKind::Ntp),
    ("time.windows.com", CommKind::Ntp),
    ("time.google.com", CommKind::Ntp),
    ("time1.google.com", CommKind::Ntp),
    ("time2.google.com", CommKind::Ntp),
    ("time3.google.com", CommKind::Ntp),
    ("time4.google.com", CommKind::Ntp),
    ("time.android.com", CommKind::Ntp),
    ("time.cloudflare.com", CommKind::Ntp),
    ("time.nist.gov", CommKind::Ntp),
    ("ntp.ubuntu.com", CommKind::Ntp),
    // 國家時間與頻率標準實驗室
    ("stdtime.gov.tw", CommKind::Ntp),
    // ---- 連線偵測（固定網址、固定內容；被擋或答案不一樣，手機會顯示沒有網路）
    ("captive.apple.com", CommKind::NetCheck),
    ("connectivitycheck.gstatic.com", CommKind::NetCheck),
    ("connectivitycheck.android.com", CommKind::NetCheck),
    ("clients3.google.com", CommKind::NetCheck),
    ("msftconnecttest.com", CommKind::NetCheck),
    ("msftncsi.com", CommKind::NetCheck),
    ("connectivity-check.ubuntu.com", CommKind::NetCheck),
    ("nmcheck.gnome.org", CommKind::NetCheck),
    ("network-test.debian.org", CommKind::NetCheck),
    ("detectportal.firefox.com", CommKind::NetCheck),
    // ---- 憑證撤銷（OCSP／CRL：純 HTTP、回應很小、有簽章，換節點沒有好處）
    ("lencr.org", CommKind::Revocation),
    ("pki.goog", CommKind::Revocation),
    ("ocsp.digicert.com", CommKind::Revocation),
    ("crl3.digicert.com", CommKind::Revocation),
    ("crl4.digicert.com", CommKind::Revocation),
    ("ocsp.sectigo.com", CommKind::Revocation),
    ("crl.sectigo.com", CommKind::Revocation),
    ("ocsp.usertrust.com", CommKind::Revocation),
    ("crl.usertrust.com", CommKind::Revocation),
    ("ocsp.comodoca.com", CommKind::Revocation),
    ("crl.comodoca.com", CommKind::Revocation),
    ("ocsp.globalsign.com", CommKind::Revocation),
    ("ocsp2.globalsign.com", CommKind::Revocation),
    ("crl.globalsign.com", CommKind::Revocation),
    ("ocsp.apple.com", CommKind::Revocation),
    ("ocsp2.apple.com", CommKind::Revocation),
    ("crl.apple.com", CommKind::Revocation),
    ("valid.apple.com", CommKind::Revocation),
    ("ocsp.msocsp.com", CommKind::Revocation),
    ("oneocsp.microsoft.com", CommKind::Revocation),
    ("crl.microsoft.com", CommKind::Revocation),
    ("amazontrust.com", CommKind::Revocation),
    ("ocsp.entrust.net", CommKind::Revocation),
    ("crl.entrust.net", CommKind::Revocation),
    ("ocsp.godaddy.com", CommKind::Revocation),
    ("crl.godaddy.com", CommKind::Revocation),
    ("ocsp.identrust.com", CommKind::Revocation),
    ("crl.identrust.com", CommKind::Revocation),
    // ---- 系統與安全更新（只保證不被清單誤擋；大檔從台灣節點拿最有感，CDN 照常改寫）
    ("windowsupdate.com", CommKind::Update),
    ("update.microsoft.com", CommKind::Update),
    ("delivery.mp.microsoft.com", CommKind::Update),
    ("definitionupdates.microsoft.com", CommKind::Update),
    ("mesu.apple.com", CommKind::Update),
    ("gdmf.apple.com", CommKind::Update),
    ("swscan.apple.com", CommKind::Update),
    ("swcdn.apple.com", CommKind::Update),
    ("swdist.apple.com", CommKind::Update),
    ("updates.cdn-apple.com", CommKind::Update),
    ("dl.google.com", CommKind::Update),
    ("update.googleapis.com", CommKind::Update),
    ("safebrowsing.googleapis.com", CommKind::Update),
    ("aus5.mozilla.org", CommKind::Update),
    ("archive.ubuntu.com", CommKind::Update),
    ("security.ubuntu.com", CommKind::Update),
    ("deb.debian.org", CommKind::Update),
    ("security.debian.org", CommKind::Update),
    ("downloads.openwrt.org", CommKind::Update),
    // ---- 地震速報（人身安全；判斷錯誤的最壞情況必須是「跟沒有黑潮一樣」：不改寫）
    // 中央氣象署（cwb.gov.tw 是舊網域，仍在使用）、國家災害防救科技中心（民生示警）
    ("cwa.gov.tw", CommKind::Quake),
    ("cwb.gov.tw", CommKind::Quake),
    ("ncdr.nat.gov.tw", CommKind::Quake),
];

/// 內建表每一類幾個後綴（`/api/status` 的 `comm.kinds`；使用者自己加的不算在這裡）
pub fn builtin_kinds() -> Vec<(&'static str, usize)> {
    CommKind::ALL
        .iter()
        .filter(|k| **k != CommKind::User)
        .map(|k| (k.as_str(), COMM_SUFFIXES.iter().filter(|(_, x)| x == k).count()))
        .collect()
}

/// 使用者自己加的後綴最多幾個
pub const USER_MAX: usize = 64;

static USER: RwLock<Vec<String>> = RwLock::new(Vec::new());

/// 3.5.0 F11 新加的五類要不要比對（`filter.protectComm`，載入設定時設；預設開）
static ESSENTIAL: AtomicBool = AtomicBool::new(true);

/// 套用 `filter.protectComm`（重新載入設定時呼叫）：關掉時新加的五類一律不比對（推播與使用者自己加的照 B6）
pub fn set_enabled(on: bool) {
    ESSENTIAL.store(on, Ordering::Relaxed);
}

/// 新加的五類現在有沒有在比對
pub fn enabled() -> bool {
    ESSENTIAL.load(Ordering::Relaxed)
}

/// 套用 `resolver.keepNames`（重新載入設定時呼叫）：正規化成小寫、去掉頭尾的點，最多 64 個；回傳實際採用幾個
pub fn set_user(names: &[String]) -> usize {
    let mut v: Vec<String> = names
        .iter()
        .map(|n| n.trim().trim_matches('.').to_ascii_lowercase())
        .filter(|n| !n.is_empty() && n.contains('.'))
        .collect();
    v.sort();
    v.dedup();
    v.truncate(USER_MAX);
    let n = v.len();
    *USER.write().unwrap() = v;
    n
}

/// 使用者加了幾個
pub fn user_count() -> usize {
    USER.read().unwrap().len()
}

/// `name` 等於 `suffix` 或是它的子網域（不分大小寫、可以帶結尾的點）
fn under(name: &str, suffix: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.len() < suffix.len() {
        return false;
    }
    let cut = name.len() - suffix.len();
    name[cut..].eq_ignore_ascii_case(suffix) && (cut == 0 || name.as_bytes()[cut - 1] == b'.')
}

/// 這個網域是不是通訊類或內建服務（是哪一類）。內建表先比，再比測試注入的、使用者自己加的
pub fn kind_of(name: &str) -> Option<CommKind> {
    let essential = enabled();
    if let Some((_, k)) = COMM_SUFFIXES
        .iter()
        .find(|(s, k)| (essential || !k.is_essential()) && under(name, s))
    {
        return Some(*k);
    }
    if TEST_ON.load(Ordering::Relaxed) {
        let t = TEST.read().unwrap();
        if let Some((_, k)) = t.iter().find(|(s, k)| (essential || !k.is_essential()) && under(name, s)) {
            return Some(*k);
        }
    }
    let u = USER.read().unwrap();
    u.iter().any(|s| under(name, s)).then_some(CommKind::User)
}

/// B6 的「通訊類」：推播與使用者自己加的（3.5.0 F11 新加的五類不算）。CDN 的「推播不跨 CDN」、
/// 舊的呼叫端照舊用它；新的呼叫端看 [`flags_of`]
pub fn is_comm(name: &str) -> bool {
    kind_of(name).is_some_and(|k| !k.is_essential())
}

/// 測試用的內建服務表（`*.example.com`）：測試不寫真的網域，用這個注入。正式執行時是空的、
/// 只多一次原子讀取（[`no_rewrite`] 也一樣，不碰 `RwLock`）
static TEST: RwLock<Vec<(String, CommKind)>> = RwLock::new(Vec::new());
static TEST_ON: AtomicBool = AtomicBool::new(false);

/// 測試共用的內建服務表（每一類一個 `*.essential.example.com`）。同一個測試行程裡的測試都注入這一份，不會互相蓋掉
#[doc(hidden)]
pub const TEST_ENTRIES: &[(&str, CommKind)] = &[
    ("ntp.essential.example.com", CommKind::Ntp),
    ("netcheck.essential.example.com", CommKind::NetCheck),
    ("ocsp.essential.example.com", CommKind::Revocation),
    ("update.essential.example.com", CommKind::Update),
    ("quake.essential.example.com", CommKind::Quake),
];

/// 測試用：注入內建服務的後綴（覆蓋上一次注入的；空的＝拿掉）。正式程式不要呼叫
#[doc(hidden)]
pub fn set_test_entries(v: &[(&str, CommKind)]) {
    let mut t = TEST.write().unwrap();
    *t = v.iter().map(|(s, k)| (s.to_ascii_lowercase(), *k)).collect();
    TEST_ON.store(!t.is_empty(), Ordering::Relaxed);
}

/// 依最後兩段（`apple.com`、`gov.tw`）分組、排好序的「不改寫」後綴：CDN 的查詢路徑上先二分搜尋那一組，
/// 平均只比對幾個，不配置、沒有鎖（第一次用時建一次）
struct NoRewriteGroup {
    key: &'static str,
    list: Vec<&'static str>,
}

fn no_rewrite_groups() -> &'static [NoRewriteGroup] {
    static G: OnceLock<Vec<NoRewriteGroup>> = OnceLock::new();
    G.get_or_init(|| {
        let mut g: Vec<NoRewriteGroup> = Vec::new();
        for (s, k) in COMM_SUFFIXES.iter().filter(|(_, k)| k.flags().no_rewrite) {
            let key = tail2(s);
            match g.iter_mut().find(|x| x.key == key) {
                Some(x) => x.list.push(s),
                None => g.push(NoRewriteGroup { key, list: vec![s] }),
            }
            debug_assert!(k.is_essential());
        }
        g.sort_by(|a, b| a.key.cmp(b.key));
        g
    })
}

/// 最後兩段（`a.b.example.com` → `example.com`；只有一段就是整個）
fn tail2(name: &str) -> &str {
    let mut dots = name.rmatch_indices('.');
    dots.next();
    match dots.next() {
        Some((i, _)) => &name[i + 1..],
        None => name,
    }
}

/// 不分大小寫的比較（不配置）
fn cmp_ci(a: &str, b: &str) -> std::cmp::Ordering {
    a.bytes()
        .map(|c| c.to_ascii_lowercase())
        .cmp(b.bytes().map(|c| c.to_ascii_lowercase()))
}

/// 這個網域的旗標（不是內建服務也不是使用者加的：全部 false）。3.5.0 F11
pub fn flags_of(name: &str) -> Flags {
    kind_of(name).map(CommKind::flags).unwrap_or_default()
}

/// 這個網域是不是「不改寫 CDN 答案」的內建服務（3.5.0 F11）。只比對內建表裡 `no_rewrite` 的那幾類，
/// 不看使用者加的後綴（不碰 `RwLock`）；CDN 的查詢路徑上呼叫，不配置、沒有鎖。
/// 依最後兩段分組：先二分搜尋那一組（約 30 組），再比那一組裡的幾個後綴
pub fn no_rewrite(name: &str) -> bool {
    if !enabled() {
        return false;
    }
    let n = name.strip_suffix('.').unwrap_or(name);
    let g = no_rewrite_groups();
    if let Ok(i) = g.binary_search_by(|x| cmp_ci(x.key, tail2(n))) {
        if g[i].list.iter().any(|s| under(n, s)) {
            return true;
        }
    }
    TEST_ON.load(Ordering::Relaxed) && TEST.read().unwrap().iter().any(|(s, k)| k.flags().no_rewrite && under(n, s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_matching() {
        assert!(under("a.push.apple.com", "push.apple.com"));
        assert!(under("PUSH.APPLE.COM.", "push.apple.com"));
        assert!(!under("xpush.apple.com", "push.apple.com"), "要在標籤邊界");
        assert!(!under("apple.com", "push.apple.com"));
        assert_eq!(kind_of("1-courier.push.apple.com"), Some(CommKind::Apns));
        assert_eq!(kind_of("mtalk.google.com"), Some(CommKind::Fcm));
        assert_eq!(kind_of("www.example.com"), None);
    }

    /// 3.5.0 F11：每一類的旗標照規格的表；推播與使用者自己加的跟 B6 一樣（不擋、先留、預取、照常改寫）
    #[test]
    fn flags_follow_spec_table() {
        let f = |k: CommKind| {
            let x = k.flags();
            (x.spare, x.hold, x.prefetch, x.no_rewrite)
        };
        assert_eq!(f(CommKind::Apns), (true, true, true, false));
        assert_eq!(f(CommKind::Fcm), (true, true, true, false));
        assert_eq!(f(CommKind::User), (true, true, true, false));
        assert_eq!(f(CommKind::Ntp), (true, true, false, true));
        assert_eq!(f(CommKind::NetCheck), (true, true, false, true));
        assert_eq!(f(CommKind::Revocation), (true, false, false, true));
        assert_eq!(f(CommKind::Update), (true, false, false, false));
        assert_eq!(f(CommKind::Quake), (true, true, true, true));
        // 推播的旗標跟現在的 is_comm 一樣（B6 的行為不變）
        assert_eq!(flags_of("1-courier.push.apple.com"), CommKind::Apns.flags());
        assert_eq!(flags_of("www.example.com"), Flags::default());
        // 推播照常改寫 CDN 答案（B6 不變）
        assert!(!no_rewrite("1-courier.push.apple.com"));
        assert!(!no_rewrite("www.example.com"));
    }

    /// `set_enabled()`／`set_test_entries()` 是整個行程共用的：改它們的測試排隊
    static GLOBAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// 3.5.0 F11：內建表本身的格式：小寫、沒有重複、沒有互相包含、不超過 128 筆、至少兩段；推播排最前面
    #[test]
    fn builtin_table_is_well_formed() {
        assert!(COMM_SUFFIXES.len() <= BUILTIN_MAX, "{}", COMM_SUFFIXES.len());
        assert_eq!(COMM_SUFFIXES[0].1, CommKind::Apns, "推播排最前面（其他測試用第一筆）");
        for (i, (a, _)) in COMM_SUFFIXES.iter().enumerate() {
            assert_eq!(*a, a.to_ascii_lowercase(), "小寫：{a}");
            assert!(a.contains('.') && !a.starts_with('.') && !a.ends_with('.'), "{a}");
            assert!(a.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'), "{a}");
            for (j, (b, _)) in COMM_SUFFIXES.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "重複：{a}");
                    assert!(!under(a, b), "{a} 被 {b} 包含");
                }
            }
        }
        // 每一類都有；統計的數字跟表一致
        let kinds = builtin_kinds();
        assert_eq!(kinds.iter().map(|x| x.1).sum::<usize>(), COMM_SUFFIXES.len());
        assert!(kinds.iter().all(|x| x.1 > 0), "{kinds:?}");
        assert!(!kinds.iter().any(|x| x.0 == "user"));
    }

    /// 3.5.0 F11：不改寫的分組比對跟逐筆比對的結果一樣（表裡每一筆、子網域、大小寫、結尾的點、相似但不同的網域）
    #[test]
    fn no_rewrite_groups_match_linear_scan() {
        let _g = GLOBAL.lock().unwrap();
        for (s, k) in COMM_SUFFIXES {
            let want = k.flags().no_rewrite;
            for n in [s.to_string(), format!("a.b.{s}"), format!("X.{}.", s.to_ascii_uppercase())] {
                assert_eq!(no_rewrite(&n), want, "{n}");
            }
            // 標籤邊界：前面黏字不算
            assert!(!no_rewrite(&format!("x{s}")), "{s}");
        }
        assert!(!no_rewrite("www.example.com"));
        assert!(!no_rewrite("com"));
        assert!(!no_rewrite(""));
        assert_eq!(tail2("a.b.example.com"), "example.com");
        assert_eq!(tail2("example.com"), "example.com");
        assert_eq!(tail2("com"), "com");
    }

    /// 3.5.0 F11：注入的測試表（`*.example.com`）走同一套旗標；`filter.protectComm` 關掉（`set_enabled(false)`）時
    /// 新加的五類不比對，推播照 B6
    #[test]
    fn protect_comm_off_restores_list_blocking_and_rewrite() {
        let _g = GLOBAL.lock().unwrap();
        set_test_entries(TEST_ENTRIES);
        assert_eq!(kind_of("a.ntp.essential.example.com"), Some(CommKind::Ntp));
        assert!(flags_of("a.ntp.essential.example.com").spare);
        assert!(no_rewrite("a.ntp.essential.example.com"));
        assert!(!no_rewrite("a.update.essential.example.com"), "系統更新照常改寫");
        assert!(flags_of("a.quake.essential.example.com").prefetch);
        assert!(!is_comm("a.ntp.essential.example.com"), "is_comm 維持 B6 的意思");
        assert_eq!(CommKind::Ntp.rule(), "builtin-ntp");
        assert_eq!(CommKind::Fcm.rule(), "builtin-comm");
        set_enabled(false);
        assert_eq!(kind_of("a.ntp.essential.example.com"), None);
        assert_eq!(flags_of("a.quake.essential.example.com"), Flags::default());
        assert!(!no_rewrite("a.ntp.essential.example.com"));
        assert_eq!(kind_of(&format!("a.{}", COMM_SUFFIXES[0].0)), Some(CommKind::Apns), "推播照 B6");
        for (s, k) in COMM_SUFFIXES.iter().filter(|(_, k)| k.is_essential()) {
            assert_eq!(kind_of(s), None, "{k:?}");
            assert!(!no_rewrite(s));
        }
        set_enabled(true);
        assert!(no_rewrite("a.ntp.essential.example.com"));
        set_test_entries(&[]);
        assert_eq!(kind_of("a.ntp.essential.example.com"), None);
    }

    /// 3.5.0 F11：使用者自己加的後綴（`resolver.keepNames`）只有不擋＋快取優先，不影響 CDN 改寫
    #[test]
    fn keep_names_do_not_affect_cdn_rewrite() {
        let _g = GLOBAL.lock().unwrap();
        set_user(&["mine.keep.example.com".into()]);
        assert_eq!(kind_of("a.mine.keep.example.com"), Some(CommKind::User));
        let f = flags_of("a.mine.keep.example.com");
        assert!(f.spare && f.hold && f.prefetch);
        assert!(!no_rewrite("a.mine.keep.example.com"), "CDN 那條路不比對使用者加的");
        set_user(&[]);
    }

    #[test]
    fn keep_names_capped_at_64() {
        let _g = GLOBAL.lock().unwrap();
        let names: Vec<String> = (0..100).map(|i| format!("n{i}.example.com")).collect();
        assert_eq!(set_user(&names), USER_MAX);
        assert_eq!(
            set_user(&["  Push.Example.Com. ".into(), "push.example.com".into(), "nodot".into()]),
            1
        );
        assert_eq!(kind_of("a.push.example.com"), Some(CommKind::User));
        set_user(&[]);
        assert_eq!(kind_of("a.push.example.com"), None);
    }
}
