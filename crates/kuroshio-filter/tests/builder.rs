//! 建置器：串流切塊、預算、去重與分類、複雜規則上限、記憶體估計。

use kuroshio_filter::{Action, BuildError, BuildOptions, Category, Filter, FilterBuilder, ListSpec, MatchKind, SourceStatus, TierKind};

const A: u16 = 1;
const AAAA: u16 = 28;

fn build(opts: BuildOptions, custom: &str, lists: &[(&str, Category, &str)]) -> Filter {
    let mut b = FilterBuilder::new(opts);
    if !custom.is_empty() {
        b.add_custom(custom.as_bytes());
    }
    for (name, cat, text) in lists {
        b.add_list(ListSpec::new(*name, *cat), text.as_bytes()).unwrap();
    }
    b.finish()
}

fn decisions(f: &Filter, names: &[&str]) -> Vec<String> {
    names
        .iter()
        .map(|n| match f.check(n, A) {
            None => format!("{n}: none"),
            Some(v) => format!("{n}: {:?} {:?} {:?} {}", v.action, v.tier, v.category, v.rule()),
        })
        .collect()
}

const LIST: &str = "! 標題\r\n||ads.example^\r\n0.0.0.0 hosts.example\r\n例子.台灣\r\n||例子.台灣^\r\n@@||ok.ads.example^\r\n||w*.wild.example^\r\n/^re[0-9]\\.example$/\r\nplain.example";

#[test]
fn chunk_split_streaming_matches_whole() {
    let names = [
        "ads.example",
        "x.ads.example",
        "ok.ads.example",
        "hosts.example",
        "a.hosts.example",
        "w1.wild.example",
        "re5.example",
        "plain.example",
        "q.plain.example",
        "none.example",
    ];
    let whole = build(BuildOptions::default(), "", &[("l", Category::Ads, LIST)]);
    let want = decisions(&whole, &names);
    assert_eq!(want[0], "ads.example: Block Lists Ads ||ads.example^");
    // 每一種切塊大小（含 1 byte：會切開 \r\n 與中文字的 UTF-8）
    for size in 1..=17 {
        let mut b = FilterBuilder::new(BuildOptions::default());
        let mut w = b.list(ListSpec::new("l", Category::Ads)).unwrap();
        for ch in LIST.as_bytes().chunks(size) {
            w.feed(ch);
        }
        w.end();
        let f = b.finish();
        assert_eq!(decisions(&f, &names), want, "切塊大小 {size}");
        assert_eq!(f.stats(), whole.stats(), "切塊大小 {size}");
    }
}

#[test]
fn writer_dropped_without_end_still_finishes() {
    let mut b = FilterBuilder::new(BuildOptions::default());
    {
        let mut w = b.list(ListSpec::new("l", Category::Ads)).unwrap();
        w.feed(b"||a.example^\n||b.exam");
        w.feed(b"ple^");
    }
    let f = b.finish();
    assert!(f.check("b.example", A).unwrap().is_block());
    assert_eq!(f.stats().sources[0].lines, 2);
}

#[test]
fn budget_enforcement() {
    let opts = BuildOptions {
        max_domains: 5,
        ..BuildOptions::default()
    };
    let mut b = FilterBuilder::new(opts);
    // 自訂規則永遠載入（但佔額度）
    b.add_custom(b"||c1.example^\n||c2.example^\n");
    b.add_list(ListSpec::new("小", Category::Ads), b"||a1.example^\n||a2.example^\n")
        .unwrap();
    // 這份會超過（剩 1）→ 整份不載入，連它的複雜規則也退回
    let big = b
        .add_list(
            ListSpec::new("大", Category::Malware),
            b"||m1.example^\n||m2.example^\n||m*.wild^\n||m3.example^\n",
        )
        .unwrap();
    assert_eq!(big.status, SourceStatus::OverBudget { rules: 3, remaining: 1 });
    // 後面較小的清單仍然可以載入
    b.add_list(ListSpec::new("剛好", Category::Telemetry), b"||t1.example^\n").unwrap();
    // 停用的清單不載入
    b.add_list(
        ListSpec {
            name: "停用".into(),
            category: Category::Ads,
            enabled: false,
        },
        b"||off.example^\n",
    )
    .unwrap();
    // 超過額度的自訂規則仍然載入
    b.add_custom(b"||c3.example^\n");
    let f = b.finish();
    for n in ["c1.example", "c2.example", "c3.example", "a1.example", "a2.example", "t1.example"] {
        assert!(f.check(n, A).is_some_and(|v| v.is_block()), "{n}");
    }
    for n in ["m1.example", "m2.example", "m3.example", "mx.wild", "off.example"] {
        assert!(f.check(n, A).is_none(), "{n}");
    }
    let st = f.stats();
    assert_eq!(st.budget_used, 6);
    assert_eq!(st.complex, 0);
    assert_eq!(st.over_budget().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["大"]);
    assert_eq!(st.sources[4].status, SourceStatus::Disabled);
    assert_eq!(st.lists, 3);
}

#[test]
fn dedup_and_category_ranking() {
    let f = build(
        BuildOptions::default(),
        "",
        &[
            ("廣告", Category::Ads, "||dup.example^\n||ads.example^\n0.0.0.0 tele.example\n"),
            ("惡意", Category::Malware, "||dup.example^\n"),
            (
                "遙測",
                Category::Telemetry,
                "1.2.3.4 tele.example\n10.9.9.9 hidden.example\n||dup.example^\n",
            ),
        ],
    );
    let v = f.check("dup.example", A).unwrap();
    assert_eq!((v.category, v.list), (Category::Malware, Some(1)));
    assert_eq!(f.stats().sources[1].name, "惡意");
    assert_eq!(f.check("tele.example", A).unwrap().category, Category::Telemetry);
    assert!(f.check("hidden.example", A).unwrap().is_block());
    let st = f.stats();
    // 同 node 版 selftest：dup、ads、tele、hidden 四條
    assert_eq!(st.lists, 4);
    assert_eq!(st.duplicates, 3);
    assert_eq!(
        (
            st.by_category.get(Category::Ads),
            st.by_category.get(Category::Telemetry),
            st.by_category.get(Category::Malware)
        ),
        (1, 2, 1)
    );
    assert_eq!(st.domains, 4);
}

#[test]
fn custom_tier_wins_and_sections() {
    let custom = "||plain.example^\n! @begin 遙測\n||tele2.example^\n! @end\n# @begin malware\n||bad.example^\n# @end\n@@||dup.example^\n";
    let f = build(
        BuildOptions::default(),
        custom,
        &[("惡意", Category::Malware, "||dup.example^\n||x.plain.example^$important\n")],
    );
    assert_eq!(f.check("plain.example", A).unwrap().category, Category::Custom);
    assert_eq!(f.check("tele2.example", A).unwrap().category, Category::Telemetry);
    assert_eq!(f.check("bad.example", A).unwrap().category, Category::Malware);
    let v = f.check("dup.example", A).unwrap();
    assert_eq!((v.action, v.tier, v.list), (Action::Allow, TierKind::Custom, None));
    assert_eq!(v.rule(), "@@||dup.example^");
    // 清單層的 $important 仍然輸給自訂層
    let v = f.check("x.plain.example", A).unwrap();
    assert_eq!(
        (v.tier, v.kind, v.domain.as_deref()),
        (TierKind::Custom, MatchKind::Suffix, Some("plain.example"))
    );
    assert_eq!(f.stats().custom_by_category.get(Category::Malware), 1);
}

#[test]
fn verdict_fields() {
    let f = build(
        BuildOptions::default(),
        "",
        &[(
            "l",
            Category::Ads,
            "0.0.0.0 Exact.Example.\n||sfx.example^$important\n||w*.wild^\n||six.example^$dnstype=AAAA\n",
        )],
    );
    let v = f.check("EXACT.example.", A).unwrap();
    assert_eq!(
        (v.kind, v.domain.as_deref(), v.rule().as_ref()),
        (MatchKind::Exact, Some("exact.example"), "|exact.example^")
    );
    let v = f.check("a.b.sfx.example", A).unwrap();
    assert_eq!((v.important, v.rule().as_ref()), (true, "||sfx.example^$important"));
    let v = f.check("w9.wild", A).unwrap();
    assert_eq!(
        (v.kind, v.domain.as_deref(), v.rule().as_ref()),
        (MatchKind::Pattern, None, "||w*.wild^")
    );
    assert!(f.check("six.example", A).is_none());
    assert_eq!(f.check("six.example", AAAA).unwrap().rule(), "||six.example^$dnstype=AAAA");
}

#[test]
fn complex_cap() {
    let opts = BuildOptions {
        max_complex: 2,
        ..BuildOptions::default()
    };
    let mut b = FilterBuilder::new(opts);
    // 自訂規則不受上限限制（但會佔額度）
    b.add_custom(b"||c*.example^\n");
    let st = b
        .add_list(
            ListSpec::new("l", Category::Ads),
            b"||a*.example^\n||b*.example^\n/^re\\./\n||plain.example^\n",
        )
        .unwrap();
    assert_eq!((st.complex_rules, st.complex_dropped), (3, 2));
    let f = b.finish();
    assert!(f.check("c1.example", A).is_some());
    assert!(f.check("a1.example", A).is_some());
    assert!(f.check("b1.example", A).is_none());
    assert!(f.check("re.x", A).is_none());
    assert!(f.check("plain.example", A).is_some());
    assert_eq!((f.stats().complex, f.stats().complex_dropped), (2, 2));
}

#[test]
fn unsupported_regex_is_counted() {
    let mut b = FilterBuilder::new(BuildOptions::default());
    let st = b
        .add_list(ListSpec::new("l", Category::Ads), b"/(a)\\1/\n||x.example^$third-party\n/bad(/\n")
        .unwrap();
    assert_eq!((st.unsupported, st.regex_unsupported), (2, 1));
    let f = b.finish();
    assert_eq!((f.stats().skipped, f.stats().regex_unsupported), (2, 1));
}

#[test]
fn badfilter_across_lists() {
    let f = build(
        BuildOptions::default(),
        "",
        &[
            ("a", Category::Ads, "||bad.example^\n||keep.example^\n||w*.bad^\n"),
            (
                "b",
                Category::Malware,
                "||bad.example^$badfilter\n||w*.bad^$badfilter\n||BAD.example^\n",
            ),
        ],
    );
    // 文字完全相同的被取消；大小寫不同的（另一條規則）保留
    let v = f.check("bad.example", A).unwrap();
    assert_eq!(v.category, Category::Malware);
    assert!(f.check("w1.bad", A).is_none());
    assert!(f.check("keep.example", A).is_some());
    assert_eq!(f.stats().badfilter_removed, 2);
}

#[test]
fn cname_chain() {
    let f = build(
        BuildOptions::default(),
        "@@||ok.example^\n",
        &[("惡意", Category::Malware, "||evil.example^\n")],
    );
    let v = f.check_cname("cdn.example", ["a.example", "x.EVIL.example."], A).unwrap();
    assert_eq!((v.category, v.rule().as_ref()), (Category::Malware, "||evil.example^"));
    assert!(f.check_cname("ok.example", ["evil.example"], A).is_none());
    assert!(f.check_cname("cdn.example", ["a.example"], A).is_none());
}

#[test]
fn too_many_lists() {
    let mut b = FilterBuilder::new(BuildOptions::default());
    for i in 0..64 {
        b.add_list(
            ListSpec::new(format!("l{i}"), Category::Ads),
            format!("||d{i}.example^\n").as_bytes(),
        )
        .unwrap();
    }
    assert_eq!(b.list(ListSpec::new("x", Category::Ads)).err(), Some(BuildError::TooManyLists));
    let f = b.finish();
    assert_eq!(f.check("d63.example", A).unwrap().list, Some(63));
}

#[test]
fn memory_estimate() {
    let empty = Filter::empty();
    let base = empty.memory_bytes();
    assert!(base < 1024, "{base}");
    let mut text = String::new();
    for i in 0..100_000 {
        text.push_str(&format!("||d{i}.example.com^\n"));
    }
    let f = build(BuildOptions::default(), "", &[("l", Category::Ads, &text)]);
    assert_eq!(f.domain_count(), 100_000);
    let m = f.memory_bytes();
    // 每筆 8 bytes 鍵 + 1 byte meta
    assert!((900_000..1_000_000).contains(&m), "{m}");
    // 複雜規則與自訂規則保留文字，會多算
    let g = build(
        BuildOptions::default(),
        "||c.example^\n",
        &[("l", Category::Ads, &text), ("w", Category::Ads, "||a*.example^\n/^x+$/\n")],
    );
    assert!(g.memory_bytes() > m + 100, "{}", g.memory_bytes());
}
