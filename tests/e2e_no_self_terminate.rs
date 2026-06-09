//! Regression guard for the non-TLS graceful-shutdown timeout.
//!
//! `serve()` imposes a drain deadline on shutdown, but the clock must
//! start only when the shutdown *signal* arrives — not at boot. A
//! previous version wrapped the whole serve future in
//! `timeout(shutdown_timeout, serve)`; since the future only resolves
//! on a signal, the timer fired `shutdown_timeout_secs` after startup
//! and the server exited on its own with no signal ever sent — a
//! default deployment would self-terminate ~30s after boot.
//!
//! This test boots with a 1s `--shutdown-timeout-secs`, waits well
//! past it with no signal, and asserts the server is still serving.
//! Under the bug this fails (connection refused). Own test binary —
//! process-global SIGTERM + once-per-process init.

use std::net::TcpListener;
use std::time::{Duration, Instant};

use clap::Parser as _;

#[test]
fn serve_does_not_self_terminate_after_shutdown_timeout() {
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

    let args = Wrapper::parse_from([
        "artifacts",
        "--data-dir",
        data_dir.path().to_str().unwrap(),
        "--bind",
        &bind,
        "--public-base-url",
        &base_url,
        "--admin-token",
        "no-self-terminate-admin",
        "--shutdown-drain-delay-secs",
        "0",
        // Small but non-zero: exercises the drain-timeout branch. The
        // server must NOT exit when this elapses absent a signal.
        "--shutdown-timeout-secs",
        "1",
    ])
    .args;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let handle = rt.spawn(artifacts::app::serve(args));

    let health = format!("{base_url}/v1/health");
    let ready_by = Instant::now() + Duration::from_secs(10);
    let mut ready = false;
    while Instant::now() < ready_by {
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

    // Wait well past the 1s shutdown timeout with NO signal sent. The
    // serve task must still be running and the listener still serving.
    std::thread::sleep(Duration::from_millis(1800));
    assert!(
        !handle.is_finished(),
        "serve() task exited on its own ~shutdown_timeout after boot — self-termination regression"
    );
    let resp = ureq::get(&health)
        .timeout(Duration::from_millis(500))
        .call()
        .expect("server should still answer /health long after shutdown_timeout elapsed");
    assert_eq!(resp.status(), 200, "server still healthy past the timeout");

    // Now a real signal drives a graceful shutdown that DOES return.
    // SAFETY: raise() with a valid signal is async-signal-safe; serve()'s
    // handler turns SIGTERM into a graceful shutdown.
    assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0, "raise failed");
    let outcome =
        rt.block_on(async { tokio::time::timeout(Duration::from_secs(15), handle).await });
    outcome
        .expect("serve() did not return after SIGTERM")
        .expect("serve() task panicked")
        .expect("serve() returned an error");
}
