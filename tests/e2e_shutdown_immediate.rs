//! Covers `serve()`'s zero-`shutdown_timeout` branch: when the timeout
//! is 0, the listener `await`s without the `tokio::time::timeout`
//! wrapper and `drain_background_tasks` takes its no-deadline path.
//! (`e2e_shutdown` / `e2e_tls` cover the non-zero-timeout branch.)
//! Own test binary — process-global SIGTERM + once-per-process init.

use std::net::TcpListener;
use std::time::{Duration, Instant};

use clap::Parser as _;

#[test]
fn serve_drains_with_zero_shutdown_timeout() {
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
        "immediate-admin",
        "--shutdown-drain-delay-secs",
        "0",
        // 0 = no graceful-shutdown deadline → the un-timed serve().await
        // branch and the no-deadline drain.
        "--shutdown-timeout-secs",
        "0",
    ])
    .args;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let handle = rt.spawn(artifacts::app::serve(args));

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
    std::thread::sleep(Duration::from_millis(200));

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
