//! 黑潮 DNS 背景工作（規格 02：`kuroshio-jobs`，對應 2.x 的 `lib/scheduler.js`、`jobs/*`、`lib/seed.js`）
//!
//! - `scheduler`：排程器。工作在核心裡以 tokio task 執行（2.x 是子程序），同一時間只跑一個。
//!   其他 crate（例如 `kuroshio-cdn` 的 cdn-ranges / cdn-scan / cdn-pool）的工作也註冊進同一個排程器。
//! - `benchmark`：每日上游評測，結果寫 `state/upstreams.json`（格式同 2.x，伺服器照讀）。
//! - `seed`：第一次啟動時帶入種子資料。
//!
//! 32 位元 MIPS 沒有 64 位元原子操作，這個 crate 不用 `AtomicU64` / `AtomicI64`。
//!
//! 整合方式（核心）：
//! ```ignore
//! kuroshio_jobs::apply_seeds(&state_dir, &seed_dir);                 // 啟動時、建立上游管理之前
//! let mut o = kuroshio_jobs::Options::new(&state_dir, &base_dir);
//! o.should_defer = Some(Arc::new(|| app::pressure() != Pressure::Normal));
//! o.lock_dir = Some("/tmp/kuroshio/locks".into());
//! o.on_state_change = Some(Arc::new(move || { let (n, b) = sched2.snapshot(); persister.lock().unwrap().stage(n, b); }));
//! let saved = persister.lock().unwrap().load(kuroshio_jobs::JOBS_STATE_FILE);
//! let sched = Scheduler::new(cfg.clone(), saved.as_deref(), o);
//! sched.register("dns-benchmark", Benchmark::new(BenchPaths::from_config(&cfg, &state_dir, &base_dir)));
//! sched.register("cdn-pool", |ctx: JobCtx| async move { /* kuroshio-cdn 的工作 */ Ok(()) });
//! sched.start();
//! // /api/jobs → sched.status()；/api/jobs/run → sched.request(name, "手動 (管理介面)")
//! // 評測寫完 upstreams.json 後，上游管理的 reload_auto() 會依修改時間重新載入
//! ```

pub mod benchmark;
pub mod geo;
pub mod lock;
pub mod scheduler;
pub mod seed;
pub mod time;
pub mod util;

pub use benchmark::{BenchPaths, Benchmark};
pub use scheduler::{resolve_path, Job, JobCtx, Options, Scheduler, JOBS_STATE_FILE};
pub use seed::{apply_seeds, apply_seeds_with, SeedSpec, SEEDS};
pub use time::{Clock, ManualClock, SystemClock};
