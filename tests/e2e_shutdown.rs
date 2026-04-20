//! In-process coverage of `app::serve`'s graceful-shutdown path.
//!
//! `serve()` drains on SIGTERM/SIGINT. Because `serve()` installs a
//! Tokio SIGTERM handler (via `signal::unix::signal`), raising SIGTERM
//! at *this* process is caught by that handler and triggers graceful
//! shutdown — it does NOT kill the test process. So we can drive the
//! whole bind → serve → graceful-drain → drain_background_tasks →
//! emit_server_shutdown chain in-process and assert `serve()` returns
//! `Ok(())` cleanly.
//!
//! Its own test binary: SIGTERM is process-global, and `serve()`
//! installs process-global tracing/metrics state that can init only
//! once per process.

use std::net::TcpListener;
use std::time::{Duration, Instant};

use clap::Parser as _;

#[test]
fn serve_drains_gracefully_on_sigterm() {
    #[derive(clap::Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: artifacts::app::ServeArgs,
    }

    let data_dir = tempfile::tempdir().unwrap();
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let bind = format!("127.0.0.1:{port}");
    let base_url = format!("http://{bind}");

    // Take the SQLite-backed webhook registry arm (with a durable
    // DeliveryOutbox + delivery-worker + prune task) so the drain has
    // those handles to cancel — covers the SQLite webhook wiring that
    // the in-memory-arm e2e doesn't. Safe to set process env here: this
    // is the only test in this binary.
    std::env::set_var("ARTIFACTS_WEBHOOK_DB", data_dir.path().join("webhooks.db"));

    // Defaults for retention/gc spawn the background tasks, so the
    // drain actually has handles to cancel + join. Zero drain delay +
    // short timeout keep the test quick.
    let args = Wrapper::parse_from([
        "artifacts",
        "--data-dir",
        data_dir.path().to_str().unwrap(),
        "--bind",
        &bind,
        "--public-base-url",
        &base_url,
        "--admin-token",
        "shutdown-admin",
        // Non-zero drain delay exercises the "mark draining, sleep so
        // the orchestrator can pull from rotation" branch of the
        // shutdown signal (the e2e_tls test covers the zero-delay path).
        "--shutdown-drain-delay-secs",
        "1",
        "--shutdown-timeout-secs",
        "5",
    ])
    .args;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    // Spawn serve() directly so the JoinHandle yields its Result.
    let handle = rt.spawn(artifacts::app::serve(args));

    // Wait until the listener is up (and thus the SIGTERM handler the
    // graceful-shutdown future installs is registered).
    let deadline = Instant::now() + Duration::from_secs(10);
    let health = format!("{base_url}/v1/health");
    let mut ready = false;
    while Instant::now() < deadline {
        if let Ok(r) = ureq::get(&health)
            .timeout(Duration::from_millis(200))
            .call()
        {
            if r.status() == 200 {
                ready = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ready, "server did not become ready");
    // Small extra margin so the graceful-shutdown future is being polled.
    std::thread::sleep(Duration::from_millis(200));

    // Raise SIGTERM at ourselves — caught by serve()'s handler.
    // SAFETY: raise() with a valid signal number is async-signal-safe
    // and has no preconditions; the handler installed by serve()
    // turns this into a graceful-shutdown trigger.
    let rc = unsafe { libc::raise(libc::SIGTERM) };
    assert_eq!(rc, 0, "raise(SIGTERM) failed");

    // serve() should now drain and return Ok(()) within the timeout.
    let outcome =
        rt.block_on(async { tokio::time::timeout(Duration::from_secs(15), handle).await });
    let joined = outcome.expect("serve() did not return after SIGTERM within 15s");
    let served = joined.expect("serve() task panicked");
    served.expect("serve() returned an error instead of clean shutdown");
}
