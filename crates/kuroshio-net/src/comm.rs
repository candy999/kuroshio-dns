//! 通訊類網域（3.5.0，規格 11 B6）：推播與通訊服務的網域不被清單誤擋、快到期就預取、記憶體吃緊時優先留在快取、
//! 不做跨 CDN 探索（長連線重連的代價高，漏接通知比多一個連線嚴重）。
//!
//! 3.5.0 只內建有官方文件寫明主機名稱的兩組（Apple 推播、Firebase 雲端訊息）。其他通訊服務（LINE、WhatsApp…）
//! 等台灣實測之後再加。使用者可以用 `resolver.keepNames` 自己加（最多 64 個後綴）。
//!
//! 比對只在已經是慢路徑的地方呼叫（過濾器判定要擋之後、快取快到期時、記憶體控制淘汰時），
//! 每次是幾十個後綴的字串比較、不配置。

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
}

impl CommKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CommKind::Apns => "apns",
            CommKind::Fcm => "fcm",
            CommKind::User => "user",
        }
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
    if let Some((_, k)) = COMM_SUFFIXES.iter().find(|(s, _)| under(name, s)) {
        return Some(*k);
    }
    let u = USER.read().unwrap();
    u.iter().any(|s| under(name, s)).then_some(CommKind::User)
}

pub fn is_comm(name: &str) -> bool {
    kind_of(name).is_some()
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
