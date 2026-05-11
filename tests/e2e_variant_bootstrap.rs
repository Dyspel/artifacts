//! In-process coverage of `app::serve` bootstrap branches the main
//! e2e doesn't take, in a dedicated test binary (so the process-global
//! tracing/metrics init runs once and cleanly):
//!
//!   - admin token AUTO-GENERATED (no `--admin-token`),
//!   - JWT secret loaded from `<data-dir>/jwt-key.bin` (no
//!     `--jwt-secret`, env-pinned path off),
//!   - periodic GC sweep ENABLED (`--gc-interval-secs` > 0 spawns the
//!     sweep task — the main e2e disables it).
//!
//! These run during startup, so simply booting + a couple of requests
//! exercises them. Authenticated calls use a JWT signed with the
//! file-loaded secret (the generated admin token is printed to stderr
//! and not recoverable in-process, which is fine — JWT auth is
//! independent).

use std::net::TcpListener;
use std::time::{Duration, Instant};

use clap::Parser as _;
use jsonwebtoken::{encode, EncodingKey, Header};

#[test]
fn serve_bootstraps_with_generated_admin_and_file_jwt_and_gc_enabled() {
    #[derive(clap::Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: artifacts::app::ServeArgs,
    }

    let data_dir = tempfile::tempdir().unwrap();
    // Pre-seed the JWT key file so serve() loads the secret from disk
    // (env-unpinned path). Must exist before serve() reads it.
    let jwt_secret = "variant-file-jwt-secret";
    std::fs::write(data_dir.path().join("jwt-key.bin"), jwt_secret).unwrap();

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
        // No --admin-token  → generated + printed to stderr.
        // No --jwt-secret   → loaded from <data-dir>/jwt-key.bin.
        // Periodic GC sweep ENABLED so the spawn branch is taken.
        "--gc-interval-secs",
        "3600",
        "--shutdown-drain-delay-secs",
        "0",
    ])
    .args;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let handle = rt.spawn(async move {
        if let Err(e) = artifacts::app::serve(args).await {
            eprintln!("variant serve() error: {e:#}");
        }
    });

    // Wait for readiness.
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
    assert!(ready, "variant server did not become ready");

    // A JWT signed with the file-loaded secret authorizes (proves the
    // jwt-key.bin load path took effect).
    #[derive(serde::Serialize)]
    struct Claims<'a> {
        #[serde(rename = "userId")]
        user_id: &'a str,
        exp: u64,
    }
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let jwt = encode(
        &Header::default(),
        &Claims {
            user_id: "variant-user",
            exp,
        },
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .unwrap();

    let create = ureq::post(&format!("{base_url}/v1/repos"))
        .set("Authorization", &format!("Bearer {jwt}"))
        .call();
    assert!(
        matches!(create, Ok(r) if r.status() == 200),
        "JWT from jwt-key.bin should authorize repo creation"
    );

    // A bogus JWT (wrong secret) is rejected — auth path is live.
    let bad = encode(
        &Header::default(),
        &Claims { user_id: "x", exp },
        &EncodingKey::from_secret(b"the-wrong-secret"),
    )
    .unwrap();
    let rejected = match ureq::get(&format!("{base_url}/v1/repos"))
        .set("Authorization", &format!("Bearer {bad}"))
        .call()
    {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(s, _)) => s,
        Err(e) => panic!("transport error: {e}"),
    };
    assert_eq!(rejected, 401, "wrong-secret JWT must be rejected");

    handle.abort();
    rt.block_on(async { tokio::time::sleep(Duration::from_millis(50)).await });
}
