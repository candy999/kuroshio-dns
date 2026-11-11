//! 解析器的模糊測試（固定種子的亂數，每次跑的內容都一樣）：
//! 不管收到什麼位元組，解析都不能 panic、不能繞圈、不能照封包自己宣告的數量配置記憶體；
//! 解析成功的訊息重新編碼後要能解析回一模一樣的內容。

use kuroshio_proto::message::{opt_code, rtype, Message, Opt, RData, Record, EDNS_DO};
use kuroshio_proto::{logic, Error};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// 每個對外的入口都跑一次：任何輸入都不能 panic
fn poke(b: &[u8]) -> Option<Message> {
    let _ = kuroshio_proto::header(b);
    let _ = kuroshio_proto::question(b);
    let _ = kuroshio_proto::answers(b);
    let _ = kuroshio_proto::matches(b, b);
    let _ = kuroshio_proto::edns_udp_size(b);
    let limit = kuroshio_proto::udp_limit(b);
    assert!((512..=1232).contains(&limit));
    let e = kuroshio_proto::error_response(b, 2);
    assert!(e.len() >= 12);
    let t = kuroshio_proto::truncated_response(b, b);
    assert!(t.len() >= 12 && t[2] & 0x02 != 0);
    let m = Message::parse(b).ok()?;
    let _ = logic::classify(&m, 1);
    let _ = logic::min_ttl(&m, 60);
    let _ = logic::negative_ttl(&m);
    let _ = logic::terminal_name(&m, "a.test");
    let _ = logic::cname_targets(&m);
    let _ = logic::wants_padding(&m);
    Some(m)
}

/// 所有名稱轉小寫：壓縮指標會指到「第一次出現」的那個名稱，只有大小寫不同的名稱解析回來會變成它的大小寫
fn lower(m: &Message) -> Message {
    let mut m = m.clone();
    let l = |s: &mut String| s.make_ascii_lowercase();
    m.questions.iter_mut().for_each(|q| l(&mut q.name));
    for r in m.answers.iter_mut().chain(&mut m.authorities).chain(&mut m.additionals) {
        l(&mut r.name);
        match &mut r.data {
            RData::Name(n) | RData::Mx(_, n) | RData::Srv { target: n, .. } => l(n),
            RData::Soa { mname, rname, .. } => {
                l(mname);
                l(rname);
            }
            _ => {}
        }
    }
    m
}

/// 解析成功的訊息：重新編碼 → 再解析，內容要一樣；補齊後的長度是區塊的倍數
fn roundtrip(m: &Message) {
    let wire = m.encode();
    let back = Message::parse(&wire).unwrap_or_else(|e| panic!("重新編碼後解析失敗（{e}）：{m:?}"));
    assert_eq!(lower(&back), lower(m), "重新編碼後內容不同");
    if m.opt.is_some() && wire.len() < 60_000 {
        let padded = m.encode_padded(468);
        assert_eq!(padded.len() % 468, 0);
        let p = Message::parse(&padded).expect("補齊後仍然是合法的訊息");
        assert_eq!((p.answers.len(), p.id, p.rcode), (m.answers.len(), m.id, m.rcode));
    }
}

fn rec(name: &str, rtype: u16, data: RData) -> Record {
    Record {
        name: name.into(),
        rtype,
        class: 1,
        ttl: 300,
        data,
    }
}

/// 各種記錄類型都有的合法訊息，當作變異的起點
fn corpus() -> Vec<Vec<u8>> {
    let mut q = Message::parse(&kuroshio_proto::build_query(0x1234, "www.example.com", rtype::A)).unwrap();
    q.opt = Some(Opt {
        udp_size: 1232,
        flags: EDNS_DO,
        options: vec![(opt_code::PADDING, vec![0; 7]), (opt_code::COOKIE, vec![1, 2, 3, 4, 5, 6, 7, 8])],
        ..Default::default()
    });
    let mut r = Message::response_to(&q, 0);
    r.answers = vec![
        rec("www.example.com", rtype::CNAME, RData::Name("edge.cdn.example.net".into())),
        Record::a("edge.cdn.example.net", 60, Ipv4Addr::new(192, 0, 2, 1)),
        Record::aaaa("edge.cdn.example.net", 60, "2001:db8::1".parse().unwrap()),
        rec("example.net", rtype::MX, RData::Mx(10, "mail.example.net".into())),
        rec(
            "_sip._tcp.example.net",
            rtype::SRV,
            RData::Srv {
                priority: 1,
                weight: 2,
                port: 5060,
                target: "sip.example.net".into(),
            },
        ),
        rec("example.net", rtype::TXT, RData::Raw(b"\x05hello\x05world".to_vec())),
        rec("4.3.2.1.in-addr.arpa", rtype::PTR, RData::Name("host.example.net".into())),
    ];
    r.authorities = vec![rec(
        "example.net",
        rtype::SOA,
        RData::Soa {
            mname: "ns1.example.net".into(),
            rname: "hostmaster.example.net".into(),
            serial: 2026111101,
            refresh: 7200,
            retry: 900,
            expire: 1209600,
            minimum: 300,
        },
    )];
    r.additionals = vec![Record::a("ns1.example.net", 3600, Ipv4Addr::new(192, 0, 2, 53))];
    logic::add_ede(&mut r, logic::ede::STALE_ANSWER, "舊資料");
    let nx = Message::response_to(&q, 3);
    let plain = kuroshio_proto::build_query(7, "a.b.c.d.e.example.org", rtype::AAAA);
    vec![q.encode(), r.encode(), r.encode_padded(128), nx.encode(), plain]
}

#[test]
fn random_bytes_never_panic() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..30_000 {
        let n = rng.below(300);
        let mut b: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        // 一半的樣本把標頭的記錄數壓小，讓解析走得進記錄內容，而不是在第一個名稱就失敗
        if n >= 12 && rng.below(2) == 0 {
            for i in [4, 6, 8, 10] {
                b[i] = 0;
                b[i + 1] &= 0x03;
            }
        }
        if let Some(m) = poke(&b) {
            roundtrip(&m);
        }
    }
}

#[test]
fn truncated_messages_never_panic() {
    for wire in corpus() {
        assert!(poke(&wire).is_some(), "原本的訊息是合法的");
        for cut in 0..wire.len() {
            // 從任何位置截斷：不是合法訊息，就是（剛好切在記錄邊界、記錄數卻沒改）解析失敗
            if let Some(m) = poke(&wire[..cut]) {
                roundtrip(&m);
            }
        }
    }
}

#[test]
fn mutated_messages_never_panic_and_roundtrip() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let corpus = corpus();
    let mut parsed = 0;
    for i in 0..60_000 {
        let mut b = corpus[i % corpus.len()].clone();
        match rng.below(4) {
            // 改幾個位元組
            0 | 1 => {
                for _ in 0..1 + rng.below(4) {
                    let at = rng.below(b.len());
                    b[at] = rng.next() as u8;
                }
            }
            // 把某個位元組改成壓縮指標（最容易出問題的地方）
            2 => {
                let at = rng.below(b.len() - 1);
                b[at] = 0xc0 | (rng.next() as u8 & 0x3f);
                b[at + 1] = rng.next() as u8;
            }
            // 插入或刪掉一段
            _ => {
                let at = rng.below(b.len());
                if rng.below(2) == 0 {
                    let n = 1 + rng.below(8);
                    let extra: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                    b.splice(at..at, extra);
                } else {
                    let end = (at + 1 + rng.below(8)).min(b.len());
                    b.drain(at..end);
                }
            }
        }
        if let Some(m) = poke(&b) {
            parsed += 1;
            roundtrip(&m);
        }
    }
    assert!(parsed > 1000, "變異後仍然合法的樣本太少（{parsed}），測不到重新編碼");
}

fn header(qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
    let mut b = vec![0, 1, 0x81, 0x80];
    for n in [qd, an, ns, ar] {
        b.extend_from_slice(&n.to_be_bytes());
    }
    b
}

#[test]
fn pointer_loops_are_rejected() {
    // 指標指向自己
    let mut b = header(1, 0, 0, 0);
    b.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
    assert_eq!(Message::parse(&b), Err(Error::BadName));
    // 兩個指標互指
    let mut b = header(1, 0, 0, 0);
    b.extend_from_slice(&[0xc0, 14, 0xc0, 12, 0, 1, 0, 1]);
    assert_eq!(Message::parse(&b), Err(Error::BadName));
    // 標籤後面的指標指回標籤開頭：名稱會無限變長 → 超過 255 bytes 就拒絕
    let mut b = header(1, 0, 0, 0);
    b.extend_from_slice(&[1, b'a', 0xc0, 12, 0, 1, 0, 1]);
    assert_eq!(Message::parse(&b), Err(Error::BadName));
    // 指標指到封包外面
    let mut b = header(1, 0, 0, 0);
    b.extend_from_slice(&[0xc0, 200, 0, 1, 0, 1]);
    assert_eq!(Message::parse(&b), Err(Error::TooShort));
    // 往後指的指標（指到還沒讀到的地方）可以解析，但同樣受步數與長度限制
    let mut b = header(1, 0, 0, 0);
    b.extend_from_slice(&[0xc0, 18, 0, 1, 0, 1, 3, b'f', b'w', b'd', 0]);
    assert_eq!(Message::parse(&b).unwrap().questions[0].name, "fwd");
}

#[test]
fn pointer_chains_take_bounded_time() {
    // 幾千筆記錄，每一筆的名稱都指向前一筆的名稱（一長串指標）：
    // 每個名稱最多跳 64 次就放棄，整個封包的解析時間不會跟「記錄數 × 鏈長」成正比
    let n = 5000u16;
    let mut b = header(1, n, 0, 0);
    b.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
    let mut prev = 12u16;
    for _ in 0..n {
        let at = b.len() as u16;
        b.extend_from_slice(&(0xc000 | prev).to_be_bytes());
        b.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        prev = at.min(0x3fff);
    }
    let t0 = Instant::now();
    let r = Message::parse(&b);
    assert!(t0.elapsed() < Duration::from_secs(2), "解析花了 {:?}", t0.elapsed());
    assert_eq!(r, Err(Error::BadName), "指標鏈超過 64 層就拒絕");
    // 64 層以內的鏈是合法的
    let mut b = header(1, 60, 0, 0);
    b.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
    let mut prev = 12u16;
    for _ in 0..60 {
        let at = b.len() as u16;
        b.extend_from_slice(&(0xc000 | prev).to_be_bytes());
        b.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        prev = at;
    }
    let m = Message::parse(&b).unwrap();
    assert!(m.answers.iter().all(|a| a.name == "a"));
}

#[test]
fn lying_counts_fail_fast_without_allocating() {
    // 標頭說每個區段都有 65535 筆，實際上什麼都沒有
    let b = header(0, 65535, 65535, 65535);
    assert_eq!(Message::parse(&b), Err(Error::TooShort));
    let b = header(65535, 0, 0, 0);
    assert_eq!(Message::parse(&b), Err(Error::TooShort));
    // RDLENGTH 說 RDATA 比封包還長
    let mut b = header(0, 1, 0, 0);
    b.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 60, 0xff, 0xff, 1, 2, 3, 4]);
    assert_eq!(Message::parse(&b), Err(Error::TooShort));
    assert_eq!(kuroshio_proto::answers(&b), Err(Error::TooShort));
    // OPT 的選項長度超出 RDATA
    let mut b = header(0, 0, 0, 1);
    b.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 6, 0, 12, 0, 9, 0, 0]);
    assert_eq!(Message::parse(&b), Err(Error::TooShort));
}

#[test]
fn rdata_names_must_stay_inside_rdlength() {
    // CNAME 的 RDLENGTH 是 0，名稱其實寫在後面（下一筆記錄的位置）：不能接受
    let mut b = header(0, 1, 0, 0);
    b.extend_from_slice(&[1, b'a', 0, 0, 5, 0, 1, 0, 0, 0, 60, 0, 0]);
    b.extend_from_slice(&[3, b'b', b'a', b'd', 0]);
    assert_eq!(Message::parse(&b), Err(Error::TooShort));
    // SOA 的固定欄位超出 RDLENGTH
    let mut b = header(0, 1, 0, 0);
    b.extend_from_slice(&[1, b'a', 0, 0, 6, 0, 1, 0, 0, 0, 60, 0, 2, 0, 0]);
    b.extend_from_slice(&[0; 20]);
    assert_eq!(Message::parse(&b), Err(Error::TooShort));
    // 指標指到前面的名稱是合法的（指標本身在 RDATA 範圍內）
    let mut b = header(1, 1, 0, 0);
    b.extend_from_slice(&[1, b'a', 0, 0, 5, 0, 1]);
    b.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12]);
    assert_eq!(Message::parse(&b).unwrap().answers[0].target(), Some("a"));
}

#[test]
fn name_length_limits() {
    let q = |labels: &[usize]| {
        let mut b = header(1, 0, 0, 0);
        for &n in labels {
            b.push(n as u8);
            b.extend(std::iter::repeat_n(b'x', n));
        }
        b.extend_from_slice(&[0, 0, 1, 0, 1]);
        b
    };
    // 標籤最長 63；64 以上的長度位元組是保留的格式
    assert!(Message::parse(&q(&[63])).is_ok());
    let mut bad = q(&[63]);
    bad[12] = 64;
    assert_eq!(Message::parse(&bad), Err(Error::BadName));
    // 名稱在封包裡最長 255 bytes（含每個標籤的長度位元組與結尾的 0）：63+63+63+61 剛好 255
    let max = q(&[63, 63, 63, 61]);
    let m = Message::parse(&max).unwrap();
    assert_eq!(m.questions[0].name.len(), 253);
    assert_eq!(m.encode(), max, "最長的名稱可以原樣編碼回去");
    assert_eq!(Message::parse(&q(&[63, 63, 63, 62])), Err(Error::BadName));
    // 很多個短標籤也一樣算總長度
    assert!(Message::parse(&q(&[1; 127])).is_ok());
    assert_eq!(Message::parse(&q(&[1; 128])), Err(Error::BadName));
}

#[test]
fn compression_keeps_distinct_names_distinct() {
    // 標籤裡面有「.」的名稱（a\.b 是一個標籤）跟一般的 a.b（兩個標籤）字面上很像，
    // 壓縮時不能把其中一個指到另一個
    let q = Message::parse(&kuroshio_proto::build_query(1, "x.test", 1)).unwrap();
    let mut m = Message::response_to(&q, 0);
    for name in ["a\\046b.example", "a.b.example", "b.example", "A.B.EXAMPLE", "a\\046b.example"] {
        m.answers.push(Record::a(name, 60, Ipv4Addr::new(192, 0, 2, 1)));
    }
    let wire = m.encode();
    let back = Message::parse(&wire).unwrap();
    let names: Vec<&str> = back.answers.iter().map(|a| a.name.as_str()).collect();
    // 第 4 筆只有大小寫不同：壓縮成指標，解析回來是第一次出現時的大小寫（DNS 名稱不分大小寫）
    assert_eq!(
        names,
        ["a\\046b.example", "a.b.example", "b.example", "a.b.example", "a\\046b.example"]
    );
    // 重複的名稱有壓縮到：example 只出現一次
    assert_eq!(wire.windows(7).filter(|w| w.eq_ignore_ascii_case(b"example")).count(), 1);
}

#[test]
fn random_messages_roundtrip() {
    // 隨機組出來的訊息（名稱共用後綴、各種記錄類型）：編碼 → 解析要完全一樣
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    let labels = [
        "a",
        "b",
        "www",
        "cdn",
        "example",
        "net",
        "com",
        "x\\046y",
        "sp\\032ace",
        "tw",
        "long-label-0123456789",
    ];
    let name = |rng: &mut Rng| -> String {
        let n = rng.below(5);
        (0..n).map(|_| labels[rng.below(labels.len())]).collect::<Vec<_>>().join(".")
    };
    for _ in 0..3000 {
        let qname = name(&mut rng);
        let mut q = Message::parse(&kuroshio_proto::build_query(rng.next() as u16, &qname, 1)).unwrap();
        if rng.below(2) == 0 {
            q.opt = Some(Opt {
                udp_size: 1232,
                ..Default::default()
            });
        }
        let mut m = Message::response_to(&q, rng.below(6) as u16);
        for _ in 0..rng.below(12) {
            let owner = name(&mut rng);
            let r = match rng.below(7) {
                0 => Record::a(&owner, 60, Ipv4Addr::from(rng.next() as u32)),
                1 => rec(&owner, rtype::CNAME, RData::Name(name(&mut rng))),
                2 => rec(&owner, rtype::DNAME, RData::Name(name(&mut rng))),
                3 => rec(&owner, rtype::MX, RData::Mx(rng.next() as u16, name(&mut rng))),
                4 => rec(
                    &owner,
                    rtype::SRV,
                    RData::Srv {
                        priority: 1,
                        weight: 2,
                        port: 3,
                        target: name(&mut rng),
                    },
                ),
                5 => rec(
                    &owner,
                    rtype::SOA,
                    RData::Soa {
                        mname: name(&mut rng),
                        rname: name(&mut rng),
                        serial: rng.next() as u32,
                        refresh: 1,
                        retry: 2,
                        expire: 3,
                        minimum: 4,
                    },
                ),
                _ => rec(&owner, rtype::TXT, RData::Raw(vec![3, b'a', b'b', b'c'])),
            };
            match rng.below(3) {
                0 => m.answers.push(r),
                1 => m.authorities.push(r),
                _ => m.additionals.push(r),
            }
        }
        roundtrip(&m);
    }
}
