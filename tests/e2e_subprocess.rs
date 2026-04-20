//! In-process coverage of the smart-HTTP **subprocess** path.
//!
//! `smart_http` has a native in-process v2 fast path and a fallback
//! that shells out to `git upload-pack`/`receive-pack`. The main e2e
//! exercises the native path; this one sets `ARTIFACTS_DISABLE_NATIVE=1`
//! so every clone/push/fetch goes through the subprocess dispatchers
//! (advertise + serve for both upload-pack and receive-pack).
//!
//! Own test binary: the env flag is process-global and `serve()` inits
//! process-global state once per process.

use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use clap::Parser as _;
use serde_json::Value;

#[test]
fn smart_http_subprocess_path_clone_push_fetch() {
    // Force the subprocess dispatchers before serve() reads the flag.
    std::env::set_var("ARTIFACTS_DISABLE_NATIVE", "1");

    #[derive(clap::Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: artifacts::app::ServeArgs,
    }

    let data_dir = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let admin = "subprocess-admin";

    let args = Wrapper::parse_from([
        "artifacts",
        "--data-dir",
        data_dir.path().to_str().unwrap(),
        "--bind",
        &bind,
        "--public-base-url",
        &base,
        "--admin-token",
        admin,
        "--gc-interval-secs",
        "0",
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
            eprintln!("subprocess-variant serve() error: {e:#}");
        }
    });

    // Readiness.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut ready = false;
    while Instant::now() < deadline {
        if let Ok(r) = ureq::get(&format!("{base}/v1/health"))
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

    // Create a repo and capture its credentialed remote.
    let created = ureq::post(&format!("{base}/v1/repos"))
        .set("Authorization", &format!("Bearer {admin}"))
        .call()
        .expect("create repo");
    let body: Value = created.into_json().unwrap();
    let remote = body["remote"].as_str().unwrap().to_string();

    let git = |repo: &Path, args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .current_dir(repo)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("spawn git");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let clone = |remote: &str, dest: &Path| {
        let out = Command::new("git")
            .args(["clone", "--quiet", remote, dest.to_str().unwrap()])
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("spawn git clone");
        assert!(
            out.status.success(),
            "clone failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };

    // Clone (empty) → commit → push → re-clone, all via subprocess
    // upload-pack/receive-pack.
    let a = work.path().join("a");
    clone(&remote, &a);
    git(&a, &["config", "user.email", "s@x"]);
    git(&a, &["config", "user.name", "s"]);
    std::fs::write(a.join("f.txt"), "hello subprocess\n").unwrap();
    git(&a, &["add", "."]);
    git(&a, &["commit", "--quiet", "-m", "init"]);
    git(&a, &["branch", "-M", "main"]);
    git(&a, &["push", "--quiet", "origin", "main"]);

    let b = work.path().join("b");
    clone(&remote, &b);
    assert_eq!(
        std::fs::read_to_string(b.join("f.txt")).unwrap(),
        "hello subprocess\n"
    );

    handle.abort();
    rt.block_on(async { tokio::time::sleep(Duration::from_millis(50)).await });
}
