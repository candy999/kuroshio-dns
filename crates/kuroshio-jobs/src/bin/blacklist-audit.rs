//! 永久黑名單體檢：用每日評測同一個標準重新驗證每一筆，只留下「確定劫持」的
//!
//! 每一筆：再問一次那台 DNS 當初被判汙染的網域（沒記網域的用幾個常被汙染的網域），然後
//! - 回 0.0.0.0 / 私有位址 / 封鎖：確定竄改 → 保留
//! - 連到回答的 IP 用網域檢查憑證：
//!   - 先確認基準：公共 DNS（1.1.1.1、8.8.8.8）的正常回答要能通過憑證檢查，這個網域才能用憑證判斷；
//!     不能的（例如只有 HTTP 的 ctldl.windowsupdate.com）→ 無法驗證
//!   - 憑證不符 → 確定劫持 → 保留（註記證據）
//!   - 憑證有效 → 規則誤殺 → 移除
//!   - 連不上 → 無法驗證 → 移除（交給每日評測用新規則在本地重新判斷，累計 3 天才會再列入）
//! - DNS 本身不回應 → 移除（同上）
//!
//! 需要真的網路（會連到各網站的 443），在 GitHub Actions 跑：
//!   cargo run --release -p kuroshio-jobs --bin blacklist-audit -- data/benchmark/blacklist.txt out/
//! 輸出 out/blacklist.txt（新名單）與 out/report.json、out/report.md（每一筆的結果）

use kuroshio_jobs::benchmark::probe::{query, NetProber, Outcome, Prober, SiteCheck};
use kuroshio_net::upstream::Upstream;
use serde_json::json;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// 沒記網域的舊紀錄：用這些常被汙染的網域檢查（DNS 汙染常把它們指到別家的 IP；每一個都要通過才算誤殺）
const FALLBACK_DOMAINS: [&str; 4] = ["www.google.com", "www.youtube.com", "twitter.com", "www.wikipedia.org"];
const CONC: usize = 24;
/// 基準：用這些公共 DNS 的回答確認網域本身能不能用憑證判斷（例如只有 HTTP 的網域不能）
const REFERENCE: [&str; 2] = ["udp://1.1.1.1", "udp://8.8.8.8"];

type Baselines = Arc<tokio::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::OnceCell<bool>>>>>;

/// 這個網域的正常回答能不能通過憑證檢查（同一個網域只算一次）
async fn baseline(p: &NetProber, cache: &Baselines, domain: &str) -> bool {
    let cell = cache.lock().await.entry(domain.to_string()).or_default().clone();
    *cell
        .get_or_init(|| async {
            for r in REFERENCE {
                let Ok(up) = Upstream::parse(r) else { continue };
                if let Outcome::Ok(ips) = query(p, &up, domain, Duration::from_secs(4), 2).await.outcome {
                    for ip in ips.iter().take(2) {
                        if p.verify_site(IpAddr::V4(*ip), domain.to_string(), Duration::from_secs(6)).await.0 == SiteCheck::Valid {
                            return true;
                        }
                    }
                }
            }
            false
        })
        .await
}

#[derive(Clone)]
struct Entry {
    id: String,
    domain: Option<String>,
    comment: String,
}

fn parse(text: &str) -> Vec<Entry> {
    text.lines()
        .map(|l| l.trim_start_matches('\u{feff}').trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let (id, comment) = match l.split_once('#') {
                Some((a, b)) => (a.trim(), b.trim()),
                None => (l, ""),
            };
            let domain = comment
                .split_once("汙染：")
                .and_then(|(_, r)| r.split_whitespace().next())
                .map(|d| d.trim_end_matches('（').to_string());
            (!id.is_empty()).then(|| Entry {
                id: id.to_string(),
                domain,
                comment: comment.to_string(),
            })
        })
        .collect()
}

/// 一筆的結論：(類別, 是否保留, 說明)
async fn audit(p: Arc<NetProber>, base: Baselines, e: Entry) -> (&'static str, bool, String) {
    let id = if e.id.contains("://") {
        e.id.clone()
    } else {
        format!("udp://{}", e.id)
    };
    let Ok(up) = Upstream::parse(&id) else {
        return ("格式錯誤", false, "無法解析".into());
    };
    let domains: Vec<String> = match &e.domain {
        Some(d) => vec![d.clone()],
        None => FALLBACK_DOMAINS.iter().map(|s| s.to_string()).collect(),
    };
    // 每個網域都要看：任何一個確定竄改 → 保留；全部都回答而且憑證有效 → 誤殺；其他 → 無法驗證
    let mut notes = Vec::new();
    let (mut valid, mut answered) = (0usize, 0usize);
    for d in &domains {
        let r = query(&*p, &up, d, Duration::from_secs(4), 2).await;
        match r.outcome {
            Outcome::Error(err) => notes.push(format!("{d}：DNS 沒回應（{err}）")),
            Outcome::Blocked(b) => return ("竄改（封鎖）", true, format!("{d}：{b}")),
            Outcome::Ok(ips) => {
                answered += 1;
                if !baseline(&p, &base, d).await {
                    notes.push(format!("{d}：網域本身無法用憑證判斷（公共 DNS 的正常回答也不符，例如只有 HTTP）"));
                    continue;
                }
                let mut verdicts = Vec::new();
                for ip in ips.iter().take(2) {
                    let (c, why) = p.verify_site(IpAddr::V4(*ip), d.clone(), Duration::from_secs(6)).await;
                    verdicts.push((c, format!("{d}：{ip} {}（{why}）", c.name())));
                }
                if let Some((_, v)) = verdicts.iter().find(|v| v.0 == SiteCheck::Valid) {
                    valid += 1;
                    notes.push(v.clone());
                } else if let Some((_, v)) = verdicts.into_iter().find(|v| v.0 == SiteCheck::Invalid) {
                    return ("確定劫持（憑證不符）", true, v);
                } else {
                    notes.push(format!("{d}：無法驗證"));
                }
            }
        }
    }
    if answered == domains.len() && valid == domains.len() {
        ("誤殺（憑證有效）", false, notes.join("；"))
    } else if answered == 0 {
        ("DNS 沒回應", false, notes.join("；"))
    } else {
        ("無法驗證", false, notes.join("；"))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let input = PathBuf::from(args.get(1).map(String::as_str).unwrap_or("data/benchmark/blacklist.txt"));
    let out = PathBuf::from(args.get(2).map(String::as_str).unwrap_or("blacklist-audit"));
    std::fs::create_dir_all(&out)?;
    let entries = parse(&std::fs::read_to_string(&input)?);
    eprintln!("體檢 {} 筆", entries.len());
    let p = Arc::new(NetProber);
    let base: Baselines = Default::default();
    let sem = Arc::new(tokio::sync::Semaphore::new(CONC));
    let mut set = tokio::task::JoinSet::new();
    for (i, e) in entries.iter().cloned().enumerate() {
        let (p, sem, base) = (p.clone(), sem.clone(), base.clone());
        set.spawn(async move {
            let _g = sem.acquire().await;
            (i, audit(p, base, e).await)
        });
    }
    let mut results: Vec<Option<(&'static str, bool, String)>> = vec![None; entries.len()];
    let mut done = 0;
    while let Some(Ok((i, r))) = set.join_next().await {
        results[i] = Some(r);
        done += 1;
        if done % 50 == 0 {
            eprintln!("  {done} / {}", entries.len());
        }
    }
    let today = chrono_like_today();
    let mut kept = vec![
        "# 永久黑名單：確定劫持或竄改的 DNS，每日評測不再測試".to_string(),
        "# 每一筆都實際驗證過：回答的 IP 用網域檢查憑證不符，或回封鎖位址。要恢復某台就刪掉那一行".to_string(),
        format!("# {today} 體檢：誤殺、無法驗證、沒回應的已移除（交給每日評測在本地重新驗證）"),
    ];
    let mut rows = Vec::new();
    let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
    for (e, r) in entries.iter().zip(results) {
        let (cat, keep, why) = r.unwrap_or(("體檢失敗", false, String::new()));
        *counts.entry(cat).or_default() += 1;
        if keep {
            kept.push(format!("{}  # {} ｜{today} 體檢：{cat}，{why}", e.id, e.comment));
        }
        rows.push(json!({ "id": e.id, "domain": e.domain, "old": e.comment, "result": cat, "keep": keep, "detail": why }));
    }
    std::fs::write(out.join("blacklist.txt"), kept.join("\n") + "\n")?;
    let report = json!({ "date": today, "total": entries.len(), "counts": counts, "entries": rows });
    std::fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report)?)?;
    let mut md = format!(
        "# 永久黑名單體檢（{today}）\n\n共 {} 筆\n\n| 結果 | 筆數 |\n|---|---|\n",
        entries.len()
    );
    for (k, v) in &counts {
        md.push_str(&format!("| {k} | {v} |\n"));
    }
    md.push_str("\n| DNS | 原本的判定 | 體檢結果 | 說明 |\n|---|---|---|---|\n");
    for r in report["entries"].as_array().into_iter().flatten() {
        let s = |k: &str| r[k].as_str().unwrap_or("").replace('|', "/");
        md.push_str(&format!("| {} | {} | {} | {} |\n", s("id"), s("old"), s("result"), s("detail")));
    }
    std::fs::write(out.join("report.md"), md)?;
    eprintln!("{}", serde_json::to_string(&counts)?);
    Ok(())
}

/// 台北日期（UTC+8）
fn chrono_like_today() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    kuroshio_jobs::time::local_date_str(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_entries() {
        let e = parse("\u{feff}# head\n1.2.3.4  # 2026-10-02 汙染 → Facebook AS32934\nhttps://x.example/dns-query  # 2026-10-04 汙染：missav.ws → Foo（憑證不符 X）\n\n");
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].domain, None);
        assert_eq!(e[1].id, "https://x.example/dns-query");
        assert_eq!(e[1].domain.as_deref(), Some("missav.ws"));
    }
}
