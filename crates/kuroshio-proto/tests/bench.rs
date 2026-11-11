//! 效能量測（預設不跑）：`cargo test -p kuroshio-proto --test bench -- --ignored --nocapture`
//!
//! 除錯組建的時間沒有參考價值，要看時間請加 `CARGO_PROFILE_TEST_OPT_LEVEL=2`；配置次數跟最佳化等級無關。

use kuroshio_proto::message::{opt_code, rtype, Message, Opt, RData, Record};
use std::alloc::{GlobalAlloc, Layout, System};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

struct Counting;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.realloc(p, l, n)
    }
}

#[global_allocator]
static A: Counting = Counting;

fn response() -> Message {
    let mut q = Message::parse(&kuroshio_proto::build_query(0x1234, "www.video.example.com", 1)).unwrap();
    q.opt = Some(Opt {
        udp_size: 1232,
        options: vec![(opt_code::PADDING, vec![])],
        ..Default::default()
    });
    let mut r = Message::response_to(&q, 0);
    r.answers.push(Record {
        name: "www.video.example.com".into(),
        rtype: rtype::CNAME,
        class: 1,
        ttl: 300,
        data: RData::Name("edge.cdn.example.net".into()),
    });
    for i in 0..4 {
        r.answers
            .push(Record::a("edge.cdn.example.net", 300, Ipv4Addr::new(192, 0, 2, 10 + i)));
    }
    r
}

fn run(label: &str, n: usize, mut f: impl FnMut()) {
    for _ in 0..n / 10 {
        f();
    }
    let a0 = ALLOCS.load(Ordering::Relaxed);
    let t0 = Instant::now();
    for _ in 0..n {
        f();
    }
    let ns = t0.elapsed().as_nanos() as f64 / n as f64;
    let allocs = (ALLOCS.load(Ordering::Relaxed) - a0) as f64 / n as f64;
    println!("BENCH {label:<34} {ns:>9.0} ns/op {allocs:>7.1} allocs/op");
}

#[test]
#[ignore]
fn bench_parse_encode() {
    let r = response();
    let wire = r.encode();
    let n = 300_000;
    run("Message::parse (CNAME + 4 A)", n, || {
        std::hint::black_box(Message::parse(std::hint::black_box(&wire)).unwrap());
    });
    run("Message::encode (CNAME + 4 A)", n, || {
        std::hint::black_box(std::hint::black_box(&r).encode());
    });
    run("pad(468) + encode", n, || {
        let mut m = r.clone();
        kuroshio_proto::logic::pad(&mut m, 468);
        std::hint::black_box(m.encode());
    });
}
