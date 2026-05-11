//! In-process coverage of `app::serve`'s TLS bind path + its
//! axum-server shutdown listener.
//!
//! Generates a throwaway self-signed cert with `openssl`, boots
//! `serve()` with `--tls-cert/--tls-key` (the `axum_server::bind_rustls`
//! branch + `spawn_shutdown_listener`), then raises SIGTERM to drive the
//! TLS graceful-shutdown + drain path. We don't need an HTTPS client —
//! entering the TLS branch and draining it is the coverage target.
//!
//! Own test binary: SIGTERM + serve()'s process-global init.

use std::net::TcpListener;
use std::process::Command;
use std::time::Duration;

use clap::Parser as _;

#[test]
fn serve_tls_branch_binds_and_drains() {
    // Skip cleanly if openssl isn't available rather than failing.
    if Command::new("openssl").arg("version").output().is_err() {
        eprintln!("openssl not available; skipping TLS coverage test");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let gen = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .expect("spawn openssl");
    assert!(
        gen.status.success(),
        "openssl cert generation failed: {}",
        String::from_utf8_lossy(&gen.stderr)
    );

    #[derive(clap::Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: artifacts::app::ServeArgs,
    }

    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let bind = format!("127.0.0.1:{port}");

    let args = Wrapper::parse_from([
        "artifacts",
        "--data-dir",
        dir.path().to_str().unwrap(),
        "--bind",
        &bind,
        "--public-base-url",
        &format!("https://{bind}"),
        "--admin-token",
        "tls-admin",
        "--tls-cert",
        cert.to_str().unwrap(),
        "--tls-key",
        key.to_str().unwrap(),
        "--shutdown-drain-delay-secs",
        "0",
        "--shutdown-timeout-secs",
        "5",
    ])
    .args;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let handle = rt.spawn(artifacts::app::serve(args));

    // The TLS branch installs its shutdown listener (and the SIGTERM
    // handler) synchronously before bind_rustls().serve() awaits, so a
    // short sleep is enough for the handler to be live.
    std::thread::sleep(Duration::from_millis(1500));

    // SAFETY: raise() with a valid signal is async-signal-safe; serve()'s
    // shutdown listener turns SIGTERM into a graceful TLS shutdown.
    let rc = unsafe { libc::raise(libc::SIGTERM) };
    assert_eq!(rc, 0, "raise(SIGTERM) failed");

    let outcome =
        rt.block_on(async { tokio::time::timeout(Duration::from_secs(15), handle).await });
    let joined = outcome.expect("TLS serve() did not return after SIGTERM within 15s");
    let served = joined.expect("TLS serve() task panicked");
    served.expect("TLS serve() returned an error instead of clean shutdown");
}
