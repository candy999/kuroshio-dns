//! ECS 突破（對齊 2.x `lib/cdn/ecs.js`）：對 DNS 分流型 CDN（Akamai 等），帶「台灣用戶子網路」去問支援 ECS 的解析器，
//! 找出比預設更近的節點。很多 CDN 會因成本把某些台灣網段導去香港 / 日本，換成其他台灣網段常能拿到台灣節點。
//!
//! 子網路順序（規格 06 第 3.1 節）：外層指定的優先網段（例如自己 ISP 的 /24）→ 偵測到的 WAN 網段 → 設定的台灣網段；
//! 優先網段以外的依「成功找到更近節點的次數」排序。

use crate::cdn::Cdn;
use crate::db::Ecs;
use crate::net::parse_subnet;
use crate::util::{self, intern, now_ms, Num, HOUR_MS};
use kuroshio_net::probe::HttpsOpts;
use kuroshio_proto::logic::ips_of;
use kuroshio_proto::message::rtype;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

fn fmt(v: f64) -> Num {
    if v.is_infinite() {
        Num::Inf
    } else {
        Num::V(util::round(v, 1))
    }
}

fn fmt_s(v: f64) -> String {
    if v.is_infinite() {
        "∞".into()
    } else {
        util::round(v, 1).to_string()
    }
}

impl Cdn {
    /// 目前的子網路順序
    pub fn ecs_subnets(&self) -> Vec<String> {
        let st = self.state();
        let mut rest: Vec<String> = st.ecs_subnets.iter().filter(|s| !st.ecs_preferred.contains(s)).cloned().collect();
        rest.sort_by_key(|s| std::cmp::Reverse(st.ecs_wins.get(s).copied().unwrap_or(0)));
        let mut out = st.ecs_preferred.clone();
        out.extend(rest);
        out
    }

    /// 加一個子網路到最前面（偵測到的 WAN 網段，同 2.x 的 `addSubnet`）
    pub fn ecs_add_subnet(&self, s: &str) {
        if s.is_empty() || parse_subnet(s).is_none() {
            return;
        }
        let mut st = self.state();
        if !st.ecs_subnets.iter().any(|x| x == s) {
            st.ecs_subnets.insert(0, s.to_string());
        }
    }

    /// 優先使用的子網路（例如自己 ISP 的網段；外層依 WAN IP / ASN 決定）
    pub fn ecs_set_preferred(&self, list: Vec<String>) {
        let mut st = self.state();
        st.ecs_preferred = list.into_iter().filter(|s| parse_subnet(s).is_some()).take(8).collect();
    }

    /// 帶 ECS 查詢（`subnet` 為 None 時不帶）；依序試每台解析器，第一個 NOERROR 的結果
    pub async fn resolve_with_ecs(&self, name: &str, qtype: u16, subnet: Option<&str>) -> Vec<IpAddr> {
        let ecs = subnet.and_then(parse_subnet);
        for r in &self.cfg.ecs.resolvers {
            match self.net.dns(r, name, qtype, ecs, Duration::from_millis(2000)).await {
                Ok(m) if m.rcode == 0 => {
                    return ips_of(&m, qtype)
                        .into_iter()
                        .filter(|ip| if qtype == rtype::A { ip.is_ipv4() } else { ip.is_ipv6() })
                        .collect();
                }
                _ => continue,
            }
        }
        vec![]
    }

    /// ECS 突破（同 2.x `EcsBreaker.probe`）
    pub async fn ecs_probe(self: &Arc<Self>, name: &str, orig4: &[IpAddr], orig6: &[IpAddr]) {
        let ttl = (self.cfg.ecs.result_hours * HOUR_MS as f64) as u64;
        let set = |e: Ecs| self.with_state(|st| st.db.set_ecs(name, e));
        let mut sets: Vec<(String, Vec<IpAddr>, f64)> = Vec::new();
        for subnet in self.ecs_subnets() {
            let ips = self.resolve_with_ecs(name, rtype::A, Some(&subnet)).await;
            if !ips.is_empty() {
                sets.push((subnet, ips, f64::INFINITY));
            }
        }
        if sets.is_empty() {
            set(Ecs {
                verdict: Some(intern("none")),
                reason: Some("ECS 查無結果".into()),
                until: Some(now_ms() + ttl),
                ..Default::default()
            });
            return;
        }
        let mut all: Vec<IpAddr> = orig4.to_vec();
        for (_, ips, _) in &sets {
            for ip in ips {
                if !all.contains(ip) {
                    all.push(*ip);
                }
            }
        }
        let ranked = self.net.rank(&all).await;
        let ms: HashMap<IpAddr, f64> = ranked
            .into_iter()
            .map(|(ip, l)| (ip, if l.ok { l.ms } else { f64::INFINITY }))
            .collect();
        let best = |ips: &[IpAddr]| {
            ips.iter()
                .map(|ip| ms.get(ip).copied().unwrap_or(f64::INFINITY))
                .fold(f64::INFINITY, f64::min)
        };
        let orig_best = if orig4.is_empty() { f64::INFINITY } else { best(orig4) };
        for s in sets.iter_mut() {
            s.2 = best(&s.1);
        }
        sets.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
        let (subnet, ips4, top) = sets.swap_remove(0);
        let gain = orig_best - top;
        let ok_gain = gain >= self.cfg.ecs.min_gain_ms && (orig_best.is_infinite() || gain / orig_best >= self.cfg.ecs.min_gain_ratio);
        if !top.is_finite() || !ok_gain {
            set(Ecs {
                verdict: Some(intern("none")),
                reason: Some(format!("無明顯改善 (原 {}ms / ECS {}ms)", fmt_s(orig_best), fmt_s(top))),
                subnet: Some(intern(&subnet)),
                until: Some(now_ms() + ttl),
                ..Default::default()
            });
            return;
        }
        // 驗證：憑證要對、狀態不能是 5xx。最快的那個不通過就整個判失敗（同 2.x）；
        // 其餘要回給用戶端的 IP 也逐一驗證，沒通過的不列入（以前只驗第一個，其餘 3 個與 IPv6 直接照回）
        let mut ips: Vec<IpAddr> = ips4
            .into_iter()
            .filter(|ip| ms.get(ip).map(|m| m.is_finite()).unwrap_or(false))
            .collect();
        ips.sort_by(|a, b| ms[a].partial_cmp(&ms[b]).unwrap_or(std::cmp::Ordering::Equal));
        ips.truncate(4);
        let check = |ip: IpAddr| async move {
            let v = self
                .net
                .https_probe(
                    ip,
                    name,
                    "/",
                    HttpsOpts {
                        timeout: Duration::from_millis(5000),
                        ..Default::default()
                    },
                )
                .await;
            if v.ok && v.status < 500 {
                Ok(())
            } else if v.ok {
                Err(format!("HTTP {}", v.status))
            } else {
                Err(v.error.clone().unwrap_or_default())
            }
        };
        if let Err(reason) = check(ips[0]).await {
            set(Ecs {
                verdict: Some(intern("fail")),
                reason: Some(reason),
                subnet: Some(intern(&subnet)),
                until: Some(now_ms() + ttl),
                ..Default::default()
            });
            return;
        }
        let mut good = vec![ips[0]];
        for &ip in &ips[1..] {
            if check(ip).await.is_ok() {
                good.push(ip);
            }
        }
        let ips = good;
        // IPv6：同一子網路再問一次 AAAA（取得的是 CDN 自己給台灣用戶的 v6），一樣要驗證過才回
        let mut ips6 = Vec::new();
        if !orig6.is_empty() && self.net.v6_usable() != Some(false) {
            let c6 = self.resolve_with_ecs(name, rtype::AAAA, Some(&subnet)).await;
            if !c6.is_empty() {
                let cand: Vec<IpAddr> = self
                    .net
                    .rank(&c6)
                    .await
                    .into_iter()
                    .filter(|x| x.1.ok)
                    .take(2)
                    .map(|x| x.0)
                    .collect();
                for ip in cand {
                    if check(ip).await.is_ok() {
                        ips6.push(ip);
                    }
                }
            }
        }
        let first = ips[0];
        set(Ecs {
            verdict: Some(intern("ok")),
            subnet: Some(intern(&subnet)),
            ips4: Some(ips),
            ips6: Some(ips6),
            gain_ms: Num::of(util::round(gain, 1)),
            orig_ms: fmt(orig_best),
            ecs_ms: Num::of(util::round(top, 1)),
            until: Some(now_ms() + ttl),
            ..Default::default()
        });
        self.with_state(|st| *st.ecs_wins.entry(subnet.clone()).or_default() += 1);
        info!(
            "✔ {name} 透過 {subnet} 找到更近節點 {first}（{}ms → {}ms）",
            fmt_s(orig_best),
            util::round(top, 1)
        );
    }
}
