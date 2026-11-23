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
//! 規格 11 第 6.2 節骨架：五類的後綴表先是空的、[`flags_of`]／[`no_rewrite`] 還沒有地方讀，乙批（表、過濾、快取）與甲批（CDN）接上。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

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
}

/// 內建的後綴表（最多 64 筆）
pub const COMM_SUFFIXES: &[(&str, CommKind)] = &[
    // Apple Push Notification service（Apple 的開發者文件列出的主機）
    ("push.apple.com", CommKind::Apns),
    // Firebase Cloud Messaging（Google 的文件列出的主機）
    ("fcm.googleapis.com", CommKind::Fcm),
    ("fcmtoken.googleapis.com", CommKind::Fcm),
    ("mtalk.google.com", CommKind::Fcm),
];

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

/// 這個網域是不是通訊類（是哪一類）
pub fn kind_of(name: &str) -> Option<CommKind> {
    let essential = enabled();
    if let Some((_, k)) = COMM_SUFFIXES
        .iter()
        .find(|(s, k)| (essential || !k.is_essential()) && under(name, s))
    {
        return Some(*k);
    }
    let u = USER.read().unwrap();
    u.iter().any(|s| under(name, s)).then_some(CommKind::User)
}

pub fn is_comm(name: &str) -> bool {
    kind_of(name).is_some()
}

/// 這個網域的旗標（不是內建服務也不是使用者加的：全部 false）。3.5.0 F11
pub fn flags_of(name: &str) -> Flags {
    kind_of(name).map(CommKind::flags).unwrap_or_default()
}

/// 這個網域是不是「不改寫 CDN 答案」的內建服務（3.5.0 F11）。只比對內建表裡 `no_rewrite` 的那幾類，
/// 不看使用者加的後綴（不碰 `RwLock`）；CDN 的查詢路徑上呼叫，不配置、沒有鎖
pub fn no_rewrite(name: &str) -> bool {
    enabled() && COMM_SUFFIXES.iter().any(|(s, k)| k.flags().no_rewrite && under(name, s))
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

    #[test]
    fn keep_names_capped_at_64() {
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
