//! End-to-end test for scripts/backup.sh + scripts/restore.sh.
//!
//! Flow:
//!   1. Spawn the server against a fresh data_dir.
//!   2. Create a repo + a read token, push a commit so the bare
//!      repo on disk has content.
//!   3. Stop the server.
//!   4. Run scripts/backup.sh data_dir → backup_dir.
//!   5. Wipe data_dir.
//!   6. Run scripts/restore.sh backup_dir → data_dir.
//!   7. Restart the server pointing at the same data_dir.
//!   8. Clone using the pre-restart token; assert the working tree
//!      matches the original push.
//!
//! Asserts:
//!   - SQLite stores survive (token still authorizes).
//!   - Bare repos survive (clone succeeds + content matches).
//!   - The whole backup/restore path is hermetic — nothing's lost.
//!
//! Uses the same `CARGO_BIN_EXE_artifacts` spawn pattern as
//! tests/integration_smoke.rs but with a deliberately tiny harness
//! (no shared module, no fancy assert layer) — this test is one
//! linear flow and benefits from being read top-to-bottom.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

#[test]
fn backup_restore_roundtrip() {
    // Skip silently when sqlite3 isn't on PATH (the host env can be
    // bare; backup.sh requires it).
    if Command::new("sqlite3").arg("--version").output().is_err() {
        eprintln!("skipping backup_restore_roundtrip: sqlite3 not on PATH");
        return;
    }

    let data_dir = tempfile::Builder::new()
        .prefix("artifacts-restore-data-")
        .tempdir()
        .expect("data_dir tempdir");
    let work_dir = tempfile::Builder::new()
        .prefix("artifacts-restore-work-")
        .tempdir()
        .expect("work_dir tempdir");
    let backup_dir = tempfile::Builder::new()
        .prefix("artifacts-restore-backup-")
        .tempdir()
        .expect("backup_dir tempdir");
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let admin_token = format!("restore-admin-{ts}");
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base_url = format!("http://{bind}");

    // 1. Start the server.
    let mut child = spawn_server(data_dir.path(), &admin_token, &bind, &base_url);
    wait_ready(&base_url);

    // 2. Create a repo via REST, then push content via git CLI.
    let create = http_post_admin(&base_url, &admin_token, "/v1/repos", &json!({}));
    let create_v: Value = serde_json::from_str(&create).unwrap();
    let repo_id = create_v["id"].as_str().unwrap().to_string();
    let owner_remote = create_v["remote"].as_str().unwrap().to_string();
    let work_clone = work_dir.path().join("work");
    git(&[
        "clone",
        "--quiet",
        &owner_remote,
        work_clone.to_str().unwrap(),
    ]);
    git_in(
        &work_clone,
        &["config", "user.email", "restore@artifacts.local"],
    );
    git_in(&work_clone, &["config", "user.name", "Restore Test"]);
    std::fs::write(work_clone.join("README.md"), "restore round-trip\n").unwrap();
    std::fs::create_dir_all(work_clone.join("src")).unwrap();
    std::fs::write(work_clone.join("src/lib.rs"), "fn lib() {}\n").unwrap();
    git_in(&work_clone, &["add", "."]);
    git_in(&work_clone, &["commit", "--quiet", "-m", "seed"]);
    git_in(&work_clone, &["branch", "-M", "main"]);
    git_in(&work_clone, &["push", "--quiet", "origin", "main"]);

    // 2b. Mint an extra read token; pre-restart authorization round-trip is
    // the whole point of backing up tokens.db, not just the bare repos.
    let mint = http_post_admin_path(
        &base_url,
        &admin_token,
        &format!("/v1/repos/{repo_id}/tokens"),
        &json!({"scope": "read"}),
    );
    let mint_v: Value = serde_json::from_str(&mint).unwrap();
    let read_remote = mint_v["remote"].as_str().unwrap().to_string();
    // Smoke: the token works before backup so we know we're testing
    // restore, not some pre-existing breakage.
    let pre_backup_clone = work_dir.path().join("pre-backup");
    git(&[
        "clone",
        "--quiet",
        &read_remote,
        pre_backup_clone.to_str().unwrap(),
    ]);
    assert!(pre_backup_clone.join("README.md").exists());

    // 3. Stop the server cleanly.
    let _ = child.kill();
    let _ = child.wait();
    // Wait for the port to free so the post-restore restart binds cleanly.
    let _ = wait_port_free(&base_url, Duration::from_secs(5));

    // 4. backup.sh data_dir → backup_dir.
    let backup_out = Command::new("bash")
        .arg(repo_script("backup.sh"))
        .arg(data_dir.path())
        .arg(backup_dir.path())
        .output()
        .expect("spawn backup.sh");
    if !backup_out.status.success() {
        panic!(
            "backup.sh failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&backup_out.stdout),
            String::from_utf8_lossy(&backup_out.stderr),
        );
    }
    assert!(
        backup_dir.path().join("repos.tar").exists(),
        "backup did not produce repos.tar"
    );
    assert!(
        backup_dir.path().join("tokens.db").exists(),
        "backup did not produce tokens.db"
    );

    // 5. Wipe data_dir.
    for entry in std::fs::read_dir(data_dir.path()).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            std::fs::remove_dir_all(&p).unwrap();
        } else {
            std::fs::remove_file(&p).unwrap();
        }
    }
    assert!(
        std::fs::read_dir(data_dir.path()).unwrap().next().is_none(),
        "data_dir not empty after wipe"
    );

    // 6. restore.sh backup_dir → data_dir.
    let restore_out = Command::new("bash")
        .arg(repo_script("restore.sh"))
        .arg(backup_dir.path())
        .arg(data_dir.path())
        .output()
        .expect("spawn restore.sh");
    if !restore_out.status.success() {
        panic!(
            "restore.sh failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&restore_out.stdout),
            String::from_utf8_lossy(&restore_out.stderr),
        );
    }
    assert!(
        data_dir.path().join("tokens.db").exists(),
        "restore did not put back tokens.db"
    );
    assert!(
        data_dir.path().join("repos").is_dir(),
        "restore did not put back repos/"
    );

    // 7. Restart the server against the restored data_dir.
    let mut child = spawn_server(data_dir.path(), &admin_token, &bind, &base_url);
    wait_ready(&base_url);

    // 8. The pre-restart read token should still clone, against the
    // restored repos + restored tokens.db.
    let post_clone = work_dir.path().join("post-restore");
    git(&[
        "clone",
        "--quiet",
        &read_remote,
        post_clone.to_str().unwrap(),
    ]);
    assert!(post_clone.join("README.md").exists());
    assert!(post_clone.join("src/lib.rs").exists());
    let readme = std::fs::read_to_string(post_clone.join("README.md")).unwrap();
    assert_eq!(readme, "restore round-trip\n", "restored README mismatch");

    // Teardown.
    let _ = child.kill();
    let _ = child.wait();
}

// ---------------------------------------------------------------------
// Tiny harness helpers — deliberately not shared with
// integration_smoke.rs because this test is one linear flow.
// ---------------------------------------------------------------------

fn spawn_server(data_dir: &Path, admin: &str, bind: &str, base_url: &str) -> Child {
    let bin = env!("CARGO_BIN_EXE_artifacts");
    let log = std::fs::File::create(data_dir.join("server.log")).expect("open log");
    let log_err = log.try_clone().expect("clone log");
    Command::new(bin)
        .env("ARTIFACTS_ADMIN_TOKEN", admin)
        .env("ARTIFACTS_SHUTDOWN_DRAIN_DELAY_SECS", "0")
        .arg("serve")
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--bind")
        .arg(bind)
        .arg("--public-base-url")
        .arg(base_url)
        .stdin(Stdio::null())
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn artifacts")
}

fn wait_ready(base_url: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(r) = ureq::get(&format!("{base_url}/v1/health"))
            .timeout(Duration::from_millis(200))
            .call()
        {
            if r.status() == 200 {
                return;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("server never became ready at {base_url}");
}

fn wait_port_free(base_url: &str, dur: Duration) -> Result<(), ()> {
    let deadline = Instant::now() + dur;
    while Instant::now() < deadline {
        if ureq::get(&format!("{base_url}/v1/health"))
            .timeout(Duration::from_millis(100))
            .call()
            .is_err()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(())
}

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn http_post_admin(base_url: &str, admin: &str, path: &str, body: &Value) -> String {
    http_post_admin_path(base_url, admin, path, body)
}

fn http_post_admin_path(base_url: &str, admin: &str, path: &str, body: &Value) -> String {
    let url = format!("{base_url}{path}");
    let resp = ureq::post(&url)
        .set("Authorization", &format!("Bearer {admin}"))
        .send_json(body.clone())
        .unwrap_or_else(|e| panic!("POST {path} failed: {e}"));
    assert_eq!(resp.status(), 200, "POST {path} unexpected status");
    resp.into_string().expect("read body")
}

fn git(args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("spawn git");
    if !out.status.success() {
        panic!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn git_in(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("spawn git");
    if !out.status.success() {
        panic!(
            "git -C {} {:?} failed: {}",
            repo.display(),
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn repo_script(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join(name)
}
