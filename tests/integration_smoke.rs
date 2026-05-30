//! End-to-end integration test for the Artifacts server.
//!
//! This is the Rust port of `tests/smoke.sh` — same scenarios, same
//! assertions, but each step is a Rust function instead of a shell
//! pipeline, so the failure mode is "test panic with a file:line" rather
//! than "bash trace + log dump". The CI gate (`.github/workflows/ci.yml`'s
//! `build-test` job) picks this up via `cargo test --all-targets`.
//! `tests/smoke.sh` remains as a thin shim for local-dev iteration.
//!
//! The test spawns the just-built `artifacts` binary as a child
//! process (the path comes from `CARGO_BIN_EXE_artifacts`, which cargo
//! sets for integration tests), waits for `/v1/health`, runs every
//! scenario sequentially against the same server (with one explicit
//! stop/start cycle for the restart-durability step + one more for the
//! drain-readiness step), and tears down via `Drop`.
//!
//! All scenarios live inside one `#[test]` fn — `smoke_end_to_end` —
//! so the cost of spinning the server up + the git CLI dance only pays
//! once, and the relative-ordering invariants between steps (alice's
//! repo from step 11 must be in her listing in step 16, etc.) carry
//! through naturally.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::{json, Value};
use tempfile::TempDir;

// ---------------------------------------------------------------------
// Spawned-server harness.
// ---------------------------------------------------------------------

struct TestServer {
    bind: String,
    base_url: String,
    admin_token: String,
    jwt_secret: String,
    data_dir: TempDir,
    log_path: PathBuf,
    child: Option<Child>,
}

impl TestServer {
    /// Spawn the server, wait for `/v1/health` to answer. The data_dir
    /// is a tempdir; the admin token and JWT secret are stable across
    /// the test so steps can compose without re-reading them.
    fn start() -> Self {
        let data_dir = tempfile::Builder::new()
            .prefix("artifacts-smoke-")
            .tempdir()
            .expect("tempdir");
        let port = pick_free_port();
        let bind = format!("127.0.0.1:{port}");
        let base_url = format!("http://{bind}");
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let admin_token = format!("smoke-admin-token-{ts}");
        let jwt_secret = format!("smoke-jwt-secret-{ts}");
        let log_path = data_dir.path().join("server.log");

        let mut server = TestServer {
            bind,
            base_url,
            admin_token,
            jwt_secret,
            data_dir,
            log_path,
            child: None,
        };
        server.spawn();
        server.wait_ready();
        server
    }

    /// Spawn the child process. Called from `start` and `restart`.
    fn spawn(&mut self) {
        assert!(
            self.child.is_none(),
            "TestServer::spawn called while a child is still running"
        );
        let bin = env!("CARGO_BIN_EXE_artifacts");
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .expect("open server log");
        let log_stderr = log_file
            .try_clone()
            .expect("clone server-log file handle for stderr");
        let child = Command::new(bin)
            // The smoke harness wants tight quotas + a small blob cap so the
            // quota/blob-cap steps don't burn through production-sized limits.
            // SHUTDOWN_DRAIN_DELAY_SECS=0 keeps each stop/restart cycle fast
            // (the drain-flip step opts back in to a 2-second delay so it
            // can observe the flip on its own dedicated server).
            .env("ARTIFACTS_ADMIN_TOKEN", &self.admin_token)
            .env("ARTIFACTS_JWT_SECRET", &self.jwt_secret)
            .env("ARTIFACTS_MAX_REPOS_PER_USER", "3")
            .env("ARTIFACTS_MAX_COMMIT_BLOB_BYTES", "1024")
            .env("ARTIFACTS_SHUTDOWN_DRAIN_DELAY_SECS", "0")
            .arg("serve")
            .arg("--data-dir")
            .arg(self.data_dir.path())
            .arg("--bind")
            .arg(&self.bind)
            .arg("--public-base-url")
            .arg(&self.base_url)
            .stdin(Stdio::null())
            .stdout(log_file)
            .stderr(log_stderr)
            .spawn()
            .expect("spawn artifacts");
        self.child = Some(child);
    }

    /// Block until `/v1/health` answers OK or 5 s elapses.
    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let url = format!("{}/v1/health", self.base_url);
        while Instant::now() < deadline {
            if let Ok(resp) = ureq::get(&url).timeout(Duration::from_millis(200)).call() {
                if resp.status() == 200 {
                    return;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        self.dump_log_and_panic("server did not become ready within 5s");
    }

    /// Kill the child (SIGKILL — used between scenarios where we
    /// don't care about drain timing).
    fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let _ = child.wait();
        // Wait until the port frees so a subsequent spawn doesn't
        // collide.
        let deadline = Instant::now() + Duration::from_secs(5);
        let url = format!("{}/v1/health", self.base_url);
        while Instant::now() < deadline {
            if ureq::get(&url)
                .timeout(Duration::from_millis(100))
                .call()
                .is_err()
            {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    /// Bracketed stop/start — exercises SQLite durability.
    fn restart(&mut self) {
        self.stop();
        self.spawn();
        self.wait_ready();
    }

    /// On failure, dump the server log so the panic message has the
    /// per-request structured logging the developer would otherwise
    /// only see by re-running locally.
    fn dump_log_and_panic(&self, why: &str) -> ! {
        eprintln!("\n=== TestServer panic: {why} ===");
        eprintln!("--- server log ({}) ---", self.log_path.display());
        if let Ok(s) = std::fs::read_to_string(&self.log_path) {
            eprintln!("{s}");
        }
        panic!("{why}");
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Best-effort teardown — never panic in Drop.
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Pick a port that's currently free. There's an unavoidable
/// time-of-check/time-of-use race between the close here and the
/// server's bind, but for a single-process test that bottoms out at
/// the localhost loopback it's effectively zero.
fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe socket");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

// ---------------------------------------------------------------------
// HTTP helpers.
// ---------------------------------------------------------------------

/// (status, body_string, lowercased-name headers).
type HttpReply = (u16, String, BTreeMap<String, String>);

fn collect_reply(resp: ureq::Response) -> HttpReply {
    let status = resp.status();
    let mut headers = BTreeMap::new();
    for name in resp.headers_names() {
        if let Some(v) = resp.header(&name) {
            headers.insert(name.to_lowercase(), v.to_string());
        }
    }
    let body = resp.into_string().unwrap_or_default();
    (status, body, headers)
}

fn send(req: ureq::Request) -> HttpReply {
    match req.call() {
        Ok(r) => collect_reply(r),
        Err(ureq::Error::Status(_, r)) => collect_reply(r),
        Err(e) => panic!("transport error: {e}"),
    }
}

fn send_json(req: ureq::Request, body: &Value) -> HttpReply {
    match req.send_json(body.clone()) {
        Ok(r) => collect_reply(r),
        Err(ureq::Error::Status(_, r)) => collect_reply(r),
        Err(e) => panic!("transport error: {e}"),
    }
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn parse_json(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("bad json: {e} body=`{body}`"))
}

fn json_str<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing or non-string `{key}` in {v}"))
}

fn assert_status(reply: &HttpReply, expected: u16, ctx: &str) {
    assert_eq!(
        reply.0, expected,
        "{ctx}: expected HTTP {expected}, got {}; body={}",
        reply.0, reply.1
    );
}

// ---------------------------------------------------------------------
// git CLI helpers.
// ---------------------------------------------------------------------

fn git_in(repo: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("spawn git")
}

fn git_in_must(repo: &Path, args: &[&str]) {
    let out = git_in(repo, args);
    if !out.status.success() {
        panic!(
            "git {:?} in {} failed: {}\nstdout: {}",
            args,
            repo.display(),
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout),
        );
    }
}

fn git_clone(remote: &str, dest: &Path) {
    let out = Command::new("git")
        .args(["clone", "--quiet", remote, dest.to_str().unwrap()])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("spawn git clone");
    if !out.status.success() {
        panic!(
            "git clone {} failed: {}",
            remote,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// True if clone succeeded.
fn git_clone_ok(remote: &str, dest: &Path) -> bool {
    Command::new("git")
        .args(["clone", "--quiet", remote, dest.to_str().unwrap()])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn git_config_user(repo: &Path) {
    git_in_must(repo, &["config", "user.email", "smoke@artifacts.local"]);
    git_in_must(repo, &["config", "user.name", "Smoke Test"]);
}

/// HS256-sign a JWT with `userId=<user>` and a 1h expiry, matching the
/// shape `sign_jwt` in the bash smoke produces.
fn sign_jwt(secret: &str, user: &str) -> String {
    #[derive(serde::Serialize)]
    struct Claims<'a> {
        #[serde(rename = "userId")]
        user_id: &'a str,
        exp: u64,
    }
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    encode(
        &Header::default(),
        &Claims { user_id: user, exp },
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("encode jwt")
}

// ---------------------------------------------------------------------
// Cross-step state.
// ---------------------------------------------------------------------

#[derive(Default)]
struct State {
    work_dir: Option<TempDir>,

    repo_id: String,
    remote_a: String,
    fork_id: String,
    fork_remote: String,

    rest_id: String,
    rest_remote: String,
    c1_sha: String,
    c2_sha: String,

    alice_jwt: String,
    bob_jwt: String,
    alice_repo: String,
    bob_repo: String,
}

impl State {
    fn work_path(&self, sub: &str) -> PathBuf {
        self.work_dir.as_ref().unwrap().path().join(sub)
    }
}

// ---------------------------------------------------------------------
// The test.
// ---------------------------------------------------------------------

#[test]
fn smoke_end_to_end() {
    let work_dir = tempfile::Builder::new()
        .prefix("artifacts-smoke-work-")
        .tempdir()
        .expect("work tempdir");
    let mut state = State {
        work_dir: Some(work_dir),
        ..State::default()
    };
    let mut server = TestServer::start();

    step01_create_empty_repo(&server, &mut state);
    step02_clone_empty_repo(&server, &mut state);
    step03_commit_and_push(&server, &mut state);
    step04_fork_writable(&server, &mut state);
    step05_clone_fork_verify(&server, &mut state);
    step06_readonly_fork_rejects_push(&server, &mut state);
    step07_mint_read_token(&server, &mut state);
    step08_rest_commits(&server, &mut state);
    step09_revoke_token(&server, &mut state);
    step10_tokens_persist_across_restart(&mut server, &mut state);
    step11_jwt_ownership(&server, &mut state);
    step12_per_user_quota(&server, &mut state);
    step13_blob_size_cap(&server, &mut state);
    step14_metrics_and_request_id(&server, &state);
    step15_merge(&server, &mut state);
    step16_user_scoped_listing(&server, &mut state);
    step17_per_repo_read_endpoints(&server, &mut state);
    step18_sse_events(&server, &mut state);
    step_admin_inspection(&server, &state);
    step_audit_log(&server, &state);
    step_admin_jwt_key_rotation(&server, &mut state);
    step_admin_token_rotation(&server, &state);
    step_drain_readiness(&mut server, &state);
}

// ---------------------------------------------------------------------
// Step bodies.
// ---------------------------------------------------------------------

fn step01_create_empty_repo(server: &TestServer, st: &mut State) {
    let reply = send(
        ureq::post(&format!("{}/v1/repos", server.base_url))
            .set("Authorization", &bearer(&server.admin_token)),
    );
    assert_status(&reply, 200, "step01 POST /v1/repos");
    let v = parse_json(&reply.1);
    st.repo_id = json_str(&v, "id").to_string();
    st.remote_a = json_str(&v, "remote").to_string();
    let token = json_str(&v, "token").to_string();
    assert!(!st.repo_id.is_empty() && !st.remote_a.is_empty() && !token.is_empty());
}

fn step02_clone_empty_repo(_server: &TestServer, st: &mut State) {
    git_clone(&st.remote_a, &st.work_path("a"));
}

fn step03_commit_and_push(_server: &TestServer, st: &mut State) {
    let clone_a = st.work_path("a");
    git_config_user(&clone_a);
    std::fs::write(clone_a.join("README.md"), "hello from artifacts\n").unwrap();
    std::fs::create_dir_all(clone_a.join("src")).unwrap();
    std::fs::write(
        clone_a.join("src/main.rs"),
        "fn main(){ println!(\"hi\"); }\n",
    )
    .unwrap();
    git_in_must(&clone_a, &["add", "."]);
    git_in_must(&clone_a, &["commit", "--quiet", "-m", "initial commit"]);
    git_in_must(&clone_a, &["branch", "-M", "main"]);
    git_in_must(&clone_a, &["push", "--quiet", "origin", "main"]);
}

fn step04_fork_writable(server: &TestServer, st: &mut State) {
    let reply = send_json(
        ureq::post(&format!(
            "{}/v1/repos/{}/forks",
            server.base_url, st.repo_id
        ))
        .set("Authorization", &bearer(&server.admin_token)),
        &json!({}),
    );
    assert_status(&reply, 200, "step04 POST /forks");
    let v = parse_json(&reply.1);
    st.fork_id = json_str(&v, "id").to_string();
    st.fork_remote = json_str(&v, "remote").to_string();
}

fn step05_clone_fork_verify(server: &TestServer, st: &mut State) {
    let clone_a = st.work_path("a");
    let clone_b = st.work_path("b");
    git_clone(&st.fork_remote, &clone_b);
    // Same content via alternates.
    let readme = std::fs::read_to_string(clone_b.join("README.md")).unwrap();
    assert_eq!(readme, "hello from artifacts\n", "fork README mismatch");
    // Working trees byte-match (ignoring .git).
    let a_files = list_files_excluding_git(&clone_a);
    let b_files = list_files_excluding_git(&clone_b);
    assert_eq!(
        a_files, b_files,
        "fork working tree differs from source clone"
    );
    // Fork's objects/ should only contain info/ and pack/ — no loose
    // fanout dirs, since everything comes via alternates.
    let fork_objects = server
        .data_dir
        .path()
        .join("repos")
        .join(format!("{}.git", st.fork_id))
        .join("objects");
    assert!(
        fork_objects.join("info/alternates").exists(),
        "alternates file missing under {}",
        fork_objects.display()
    );
    let mut dirs: Vec<String> = std::fs::read_dir(&fork_objects)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().ok().is_some_and(|t| t.is_dir()))
        .map(|e| e.file_name().into_string().unwrap())
        .collect();
    dirs.sort();
    assert_eq!(
        dirs,
        vec!["info".to_string(), "pack".to_string()],
        "fork objects dir has unexpected entries: {dirs:?}"
    );
}

fn step06_readonly_fork_rejects_push(server: &TestServer, st: &mut State) {
    let reply = send_json(
        ureq::post(&format!(
            "{}/v1/repos/{}/forks",
            server.base_url, st.repo_id
        ))
        .set("Authorization", &bearer(&server.admin_token)),
        &json!({"readOnly": true}),
    );
    assert_status(&reply, 200, "step06 mint RO fork");
    let v = parse_json(&reply.1);
    let ro_remote = json_str(&v, "remote").to_string();
    let clone_ro = st.work_path("ro");
    git_clone(&ro_remote, &clone_ro);
    git_config_user(&clone_ro);
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(clone_ro.join("README.md"))
        .unwrap();
    f.write_all(b"change\n").unwrap();
    drop(f);
    git_in_must(&clone_ro, &["add", "README.md"]);
    git_in_must(
        &clone_ro,
        &["commit", "--quiet", "-m", "attempt push to readonly"],
    );
    let push = git_in(&clone_ro, &["push", "--quiet", "origin", "main"]);
    assert!(
        !push.status.success(),
        "push to readOnly fork should have failed"
    );
}

fn step07_mint_read_token(server: &TestServer, st: &mut State) {
    let reply = send_json(
        ureq::post(&format!(
            "{}/v1/repos/{}/tokens",
            server.base_url, st.repo_id
        ))
        .set("Authorization", &bearer(&server.admin_token)),
        &json!({"scope": "read"}),
    );
    assert_status(&reply, 200, "step07 mint read token");
    let v = parse_json(&reply.1);
    let remote = json_str(&v, "remote").to_string();
    let clone_tok = st.work_path("tok");
    git_clone(&remote, &clone_tok);
    let readme = std::fs::read_to_string(clone_tok.join("README.md")).unwrap();
    assert_eq!(readme, "hello from artifacts\n");
}

fn step08_rest_commits(server: &TestServer, st: &mut State) {
    // Create a fresh repo dedicated to the REST-commits scenario.
    let reply = send(
        ureq::post(&format!("{}/v1/repos", server.base_url))
            .set("Authorization", &bearer(&server.admin_token)),
    );
    assert_status(&reply, 200, "step08 create rest repo");
    let v = parse_json(&reply.1);
    st.rest_id = json_str(&v, "id").to_string();
    st.rest_remote = json_str(&v, "remote").to_string();

    // c1 — orphan commit seeding README + src/a.txt.
    let c1 = send_json(
        ureq::post(&format!(
            "{}/v1/repos/{}/commits",
            server.base_url, st.rest_id
        ))
        .set("Authorization", &bearer(&server.admin_token)),
        &json!({
            "branch": "main",
            "parent": null,
            "message": "rest-initial",
            "changes": [
                {"op": "write", "path": "README.md", "content": "# rest-initial\n"},
                {"op": "write", "path": "src/a.txt", "content": "a"}
            ]
        }),
    );
    assert_status(&c1, 200, "step08 c1");
    let c1v = parse_json(&c1.1);
    st.c1_sha = json_str(&c1v, "commit").to_string();
    assert_eq!(st.c1_sha.len(), 40, "c1 sha length: {}", st.c1_sha);

    // c2 — delete src/a.txt, add src/b.txt with CAS parent=c1.
    let c2 = send_json(
        ureq::post(&format!(
            "{}/v1/repos/{}/commits",
            server.base_url, st.rest_id
        ))
        .set("Authorization", &bearer(&server.admin_token)),
        &json!({
            "branch": "main",
            "parent": st.c1_sha,
            "message": "rest-delete-and-add",
            "changes": [
                {"op": "delete", "path": "src/a.txt"},
                {"op": "write", "path": "src/b.txt", "content": "b"}
            ]
        }),
    );
    assert_status(&c2, 200, "step08 c2");
    let c2v = parse_json(&c2.1);
    st.c2_sha = json_str(&c2v, "commit").to_string();
    assert_eq!(st.c2_sha.len(), 40);

    // c3 — reuse stale parent=c1. Must 409 with ref_conflict.
    let c3 = send_json(
        ureq::post(&format!(
            "{}/v1/repos/{}/commits",
            server.base_url, st.rest_id
        ))
        .set("Authorization", &bearer(&server.admin_token)),
        &json!({
            "branch": "main",
            "parent": st.c1_sha,
            "message": "stale",
            "changes": [{"op": "write", "path": "x", "content": "x"}]
        }),
    );
    assert_status(&c3, 409, "step08 c3 stale-parent");
    let c3v = parse_json(&c3.1);
    let err = c3v.get("error").expect("error field");
    assert_eq!(
        err.get("code").and_then(Value::as_str),
        Some("ref_conflict")
    );
    assert_eq!(
        err.get("current").and_then(Value::as_str),
        Some(st.c2_sha.as_str())
    );

    // Clone and verify the c2 state matches: README + src/b.txt
    // present, src/a.txt absent.
    let rest_clone = st.work_path("rest");
    git_clone(&st.rest_remote, &rest_clone);
    assert!(rest_clone.join("README.md").exists(), "README missing");
    assert!(
        !rest_clone.join("src/a.txt").exists(),
        "src/a.txt should be deleted"
    );
    assert!(
        rest_clone.join("src/b.txt").exists(),
        "src/b.txt should be present"
    );
    let b = std::fs::read_to_string(rest_clone.join("src/b.txt")).unwrap();
    assert_eq!(b, "b");

    // Invalid path → 400, not 500.
    let bad = send_json(
        ureq::post(&format!(
            "{}/v1/repos/{}/commits",
            server.base_url, st.rest_id
        ))
        .set("Authorization", &bearer(&server.admin_token)),
        &json!({
            "branch": "main",
            "parent": st.c2_sha,
            "message": "bad path",
            "changes": [{"op": "write", "path": "../escape", "content": "x"}]
        }),
    );
    assert_status(&bad, 400, "step08 invalid path");
}

fn step09_revoke_token(server: &TestServer, st: &mut State) {
    let mint = send_json(
        ureq::post(&format!(
            "{}/v1/repos/{}/tokens",
            server.base_url, st.repo_id
        ))
        .set("Authorization", &bearer(&server.admin_token)),
        &json!({"scope": "read"}),
    );
    assert_status(&mint, 200, "step09 mint token");
    let mintv = parse_json(&mint.1);
    let token = json_str(&mintv, "token").to_string();
    let remote = json_str(&mintv, "remote").to_string();
    let clone1 = st.work_path("rev");
    git_clone(&remote, &clone1);
    // Revoke.
    let rv = send_json(
        ureq::post(&format!("{}/v1/tokens/revoke", server.base_url))
            .set("Authorization", &bearer(&server.admin_token)),
        &json!({"token": token}),
    );
    assert_status(&rv, 200, "step09 revoke");
    let rvv = parse_json(&rv.1);
    assert_eq!(rvv.get("revoked").and_then(Value::as_bool), Some(true));
    // Re-clone with revoked token — must fail.
    let clone2 = st.work_path("rev2");
    assert!(
        !git_clone_ok(&remote, &clone2),
        "clone with revoked token should fail"
    );
    // Double-revoke is idempotent (returns revoked=false).
    let rv2 = send_json(
        ureq::post(&format!("{}/v1/tokens/revoke", server.base_url))
            .set("Authorization", &bearer(&server.admin_token)),
        &json!({"token": token}),
    );
    assert_status(&rv2, 200, "step09 second revoke");
    let rv2v = parse_json(&rv2.1);
    assert_eq!(rv2v.get("revoked").and_then(Value::as_bool), Some(false));
}

fn step10_tokens_persist_across_restart(server: &mut TestServer, st: &mut State) {
    let mint = send_json(
        ureq::post(&format!(
            "{}/v1/repos/{}/tokens",
            server.base_url, st.repo_id
        ))
        .set("Authorization", &bearer(&server.admin_token)),
        &json!({"scope": "read"}),
    );
    assert_status(&mint, 200, "step10 mint token");
    let mintv = parse_json(&mint.1);
    let remote = json_str(&mintv, "remote").to_string();
    server.restart();
    let clone = st.work_path("persist");
    git_clone(&remote, &clone);
    assert!(
        clone.join("README.md").exists(),
        "post-restart clone missing README.md"
    );
}

fn step11_jwt_ownership(server: &TestServer, st: &mut State) {
    st.alice_jwt = sign_jwt(&server.jwt_secret, "alice");
    st.bob_jwt = sign_jwt(&server.jwt_secret, "bob");
    // Alice creates a repo via her JWT.
    let alice_create = send(
        ureq::post(&format!("{}/v1/repos", server.base_url))
            .set("Authorization", &bearer(&st.alice_jwt)),
    );
    assert_status(&alice_create, 200, "alice create");
    let v = parse_json(&alice_create.1);
    st.alice_repo = json_str(&v, "id").to_string();
    // Bob → mint token on alice's repo → 403.
    let bob_mint = send_json(
        ureq::post(&format!(
            "{}/v1/repos/{}/tokens",
            server.base_url, st.alice_repo
        ))
        .set("Authorization", &bearer(&st.bob_jwt)),
        &json!({"scope": "read"}),
    );
    assert_status(&bob_mint, 403, "bob → alice's tokens");
    // Bob → delete alice's repo → 403.
    let bob_del = send(
        ureq::delete(&format!("{}/v1/repos/{}", server.base_url, st.alice_repo))
            .set("Authorization", &bearer(&st.bob_jwt)),
    );
    assert_status(&bob_del, 403, "bob → DELETE alice's repo");
    // Alice → mint on her own → 200.
    let alice_mint = send_json(
        ureq::post(&format!(
            "{}/v1/repos/{}/tokens",
            server.base_url, st.alice_repo
        ))
        .set("Authorization", &bearer(&st.alice_jwt)),
        &json!({"scope": "read"}),
    );
    assert_status(&alice_mint, 200, "alice → her tokens");
    // Admin bypasses ownership → 200.
    let admin_mint = send_json(
        ureq::post(&format!(
            "{}/v1/repos/{}/tokens",
            server.base_url, st.alice_repo
        ))
        .set("Authorization", &bearer(&server.admin_token)),
        &json!({"scope": "read"}),
    );
    assert_status(&admin_mint, 200, "admin → alice's tokens");
    // Non-admin JWT cannot revoke → 403.
    let alice_revoke = send_json(
        ureq::post(&format!("{}/v1/tokens/revoke", server.base_url))
            .set("Authorization", &bearer(&st.alice_jwt)),
        &json!({"token": "whatever"}),
    );
    assert_status(&alice_revoke, 403, "alice → revoke");
}

fn step12_per_user_quota(server: &TestServer, st: &mut State) {
    // Alice already owns 1 (from step 11). Create 2 more, then expect 429.
    for i in 2..=3 {
        let r = send(
            ureq::post(&format!("{}/v1/repos", server.base_url))
                .set("Authorization", &bearer(&st.alice_jwt)),
        );
        assert_status(&r, 200, &format!("alice create #{i}"));
    }
    let over = send(
        ureq::post(&format!("{}/v1/repos", server.base_url))
            .set("Authorization", &bearer(&st.alice_jwt)),
    );
    assert_status(&over, 429, "alice over quota");
    let ov = parse_json(&over.1);
    let err = ov.get("error").expect("error field");
    assert_eq!(
        err.get("code").and_then(Value::as_str),
        Some("quota_exceeded")
    );
    // Bob has separate quota → his first repo succeeds. Capture id for step 13.
    let bob_create = send(
        ureq::post(&format!("{}/v1/repos", server.base_url))
            .set("Authorization", &bearer(&st.bob_jwt)),
    );
    assert_status(&bob_create, 200, "bob first repo");
    let bv = parse_json(&bob_create.1);
    st.bob_repo = json_str(&bv, "id").to_string();
    // Admin bypasses quota even after alice is over.
    let admin_create = send(
        ureq::post(&format!("{}/v1/repos", server.base_url))
            .set("Authorization", &bearer(&server.admin_token)),
    );
    assert_status(&admin_create, 200, "admin create bypasses quota");
}

fn step13_blob_size_cap(server: &TestServer, st: &mut State) {
    let big = "x".repeat(2000); // > 1024 cap
    let body = json!({
        "branch": "main",
        "parent": null,
        "message": "too big",
        "changes": [{"op": "write", "path": "big.txt", "content": big}]
    });
    let reply = send_json(
        ureq::post(&format!(
            "{}/v1/repos/{}/commits",
            server.base_url, st.bob_repo
        ))
        .set("Authorization", &bearer(&st.bob_jwt)),
        &body,
    );
    assert_status(&reply, 400, "oversized blob");
    assert!(
        reply.1.contains("over limit of"),
        "error body should mention the blob-size limit; got {}",
        reply.1
    );
    // Under-cap commit on same repo works.
    let small = send_json(
        ureq::post(&format!(
            "{}/v1/repos/{}/commits",
            server.base_url, st.bob_repo
        ))
        .set("Authorization", &bearer(&st.bob_jwt)),
        &json!({
            "branch": "main",
            "parent": null,
            "message": "ok",
            "changes": [{"op": "write", "path": "ok.txt", "content": "small"}]
        }),
    );
    assert_status(&small, 200, "under-cap commit");
}

fn step14_metrics_and_request_id(server: &TestServer, st: &State) {
    // /metrics (no auth) — Prometheus text format, route-template path labels.
    let metrics = send(ureq::get(&format!("{}/metrics", server.base_url)));
    assert_status(&metrics, 200, "/metrics");
    let body = &metrics.1;
    for needle in [
        "# TYPE artifacts_requests_total counter",
        "artifacts_build_info",
        "/v1/repos/:id/tokens",
        "artifacts_quota_exceeded_total",
    ] {
        assert!(
            body.contains(needle),
            "/metrics body missing `{needle}`; got:\n{body}"
        );
    }
    // repos-total gauge ≥ 1 — every smoke step that created a repo
    // is reflected here.
    let repos_total = extract_gauge(body, "artifacts_repos_total");
    assert!(
        repos_total >= 1.0,
        "artifacts_repos_total = {repos_total}, expected ≥ 1"
    );
    // audit-events-stored gauge ≥ 1.
    let audit_stored = extract_gauge(body, "artifacts_audit_events_stored_total");
    assert!(
        audit_stored >= 1.0,
        "artifacts_audit_events_stored_total = {audit_stored}, expected ≥ 1"
    );
    // Audit-event counter has labeled series for repo.create + token.mint
    // (counters reset at the step-10 restart so we can only assert on
    // post-restart events).
    for kind in ["repo.create", "token.mint"] {
        let needle = format!("artifacts_audit_events_total{{event=\"{kind}\"}}");
        assert!(body.contains(&needle), "/metrics missing `{needle}`");
    }
    // Readiness probe — every component reports ok.
    let ready = send(ureq::get(&format!("{}/v1/health/ready", server.base_url)));
    assert_status(&ready, 200, "/v1/health/ready");
    let rv = parse_json(&ready.1);
    assert_eq!(rv.get("ok").and_then(Value::as_bool), Some(true));
    let components = rv
        .get("components")
        .and_then(|c| c.as_object())
        .expect("components object");
    let mut names: Vec<_> = components.keys().cloned().collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "audit".to_string(),
            "ownership".to_string(),
            "tokens".to_string()
        ],
        "ready components set drifted: {names:?}"
    );
    for v in components.values() {
        assert_eq!(v.as_str(), Some("ok"));
    }
    // X-Request-Id round-trips when client supplies one.
    let echo = send(
        ureq::get(&format!("{}/v1/health", server.base_url)).set("X-Request-Id", "smoke-trace-xyz"),
    );
    assert_status(&echo, 200, "X-Request-Id echo");
    assert_eq!(
        echo.2.get("x-request-id").map(String::as_str),
        Some("smoke-trace-xyz")
    );
    // No supplied id → server generates a 32-char hex.
    let gen = send(ureq::get(&format!("{}/v1/health", server.base_url)));
    let gen_id = gen.2.get("x-request-id").expect("generated x-request-id");
    assert_eq!(gen_id.len(), 32, "generated X-Request-Id length: {gen_id}");
    let _ = st;
}

fn step15_merge(server: &TestServer, st: &mut State) {
    // Fresh repo for the merge scenarios.
    let create = send(
        ureq::post(&format!("{}/v1/repos", server.base_url))
            .set("Authorization", &bearer(&server.admin_token)),
    );
    assert_status(&create, 200, "merge repo create");
    let cv = parse_json(&create.1);
    let merge_id = json_str(&cv, "id").to_string();
    let merge_remote = json_str(&cv, "remote").to_string();
    // c1 (orphan): seed README + a.txt. Merge base.
    let c1 = send_json(
        ureq::post(&format!(
            "{}/v1/repos/{}/commits",
            server.base_url, merge_id
        ))
        .set("Authorization", &bearer(&server.admin_token)),
        &json!({
            "branch": "main",
            "parent": null,
            "message": "base",
            "changes": [
                {"op": "write", "path": "README.md", "content": "# base\n"},
                {"op": "write", "path": "a.txt", "content": "one\n"}
            ]
        }),
    );
    assert_status(&c1, 200, "merge c1");
    let m_c1 = json_str(&parse_json(&c1.1), "commit").to_string();
    // Clone and use the working copy as a branch-push source.
    let merge_work = st.work_path("merge_work");
    git_clone(&merge_remote, &merge_work);
    git_config_user(&merge_work);

    let push_branch = |branch: &str, path: &str, content: &str| -> String {
        git_in_must(&merge_work, &["checkout", "-q", "-B", branch, &m_c1]);
        std::fs::write(merge_work.join(path), content).unwrap();
        git_in_must(&merge_work, &["add", path]);
        let msg = format!("{branch}: {path}");
        git_in_must(&merge_work, &["commit", "-q", "-m", &msg]);
        git_in_must(&merge_work, &["push", "-q", "origin", branch]);
        let out = git_in(&merge_work, &["rev-parse", "HEAD"]);
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };

    // Fast-forward: feature adds b.txt on top of c1; merge feature → main.
    let ff_c = push_branch("feature", "b.txt", "b");
    let ff = send_json(
        ureq::post(&format!("{}/v1/repos/{}/merge", server.base_url, merge_id))
            .set("Authorization", &bearer(&server.admin_token)),
        &json!({"sourceBranch": "feature", "targetBranch": "main"}),
    );
    assert_status(&ff, 200, "ff merge");
    let ffv = parse_json(&ff.1);
    assert_eq!(json_str(&ffv, "commit"), ff_c);
    assert_eq!(ffv.get("fastForward").and_then(Value::as_bool), Some(true));

    // Three-way clean: advance main with d.txt on top of ff_c; create
    // side off ff_c that adds c.txt; merge side → main.
    git_in_must(&merge_work, &["checkout", "-q", "main"]);
    git_in_must(&merge_work, &["pull", "-q", "--ff-only", "origin", "main"]);
    std::fs::write(merge_work.join("d.txt"), "d").unwrap();
    git_in_must(&merge_work, &["add", "d.txt"]);
    git_in_must(&merge_work, &["commit", "-q", "-m", "main: add d"]);
    let m_c2 = String::from_utf8(git_in(&merge_work, &["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string();
    git_in_must(&merge_work, &["push", "-q", "origin", "main"]);
    let side_c = push_branch("side", "c.txt", "c");

    let tw = send_json(
        ureq::post(&format!("{}/v1/repos/{}/merge", server.base_url, merge_id))
            .set("Authorization", &bearer(&server.admin_token)),
        &json!({
            "sourceBranch": "side",
            "targetBranch": "main",
            "message": "merge side"
        }),
    );
    assert_status(&tw, 200, "three-way merge");
    let tw_v = parse_json(&tw.1);
    assert_eq!(
        tw_v.get("fastForward").and_then(Value::as_bool),
        Some(false)
    );
    let tw_head = json_str(&tw_v, "commit").to_string();
    assert!(
        tw_head != m_c2 && tw_head != side_c,
        "3-way head wrong: {tw_head}"
    );
    // Verify the merge commit has two parents and unified tree.
    let tw_clone = st.work_path("merge_tw");
    git_clone(&merge_remote, &tw_clone);
    let parents_out = git_in(&tw_clone, &["rev-list", "--parents", "-n", "1", "HEAD"]);
    let parents_line = String::from_utf8(parents_out.stdout).unwrap();
    let mut parts = parents_line.split_whitespace();
    let _ = parts.next();
    let p1 = parts.next().unwrap_or("").to_string();
    let p2 = parts.next().unwrap_or("").to_string();
    assert_eq!(p1, m_c2);
    assert_eq!(p2, side_c);
    assert!(tw_clone.join("c.txt").exists() && tw_clone.join("d.txt").exists());

    // Three-way conflict: both sides edit a.txt differently on top of c1.
    push_branch("conflict-left", "a.txt", "left\n");
    push_branch("conflict-right", "a.txt", "right\n");
    let cf = send_json(
        ureq::post(&format!("{}/v1/repos/{}/merge", server.base_url, merge_id))
            .set("Authorization", &bearer(&server.admin_token)),
        &json!({
            "sourceBranch": "conflict-right",
            "targetBranch": "conflict-left",
            "message": "should conflict"
        }),
    );
    assert_status(&cf, 409, "merge conflict");
    let cfv = parse_json(&cf.1);
    let err = cfv.get("error").expect("error field");
    assert_eq!(
        err.get("code").and_then(Value::as_str),
        Some("merge_conflict")
    );
    let conflicts = err
        .get("conflicts")
        .and_then(Value::as_array)
        .expect("conflicts list");
    let names: Vec<String> = conflicts
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    assert_eq!(names, vec!["a.txt".to_string()]);
    // ff-only refuses divergence.
    let ffo = send_json(
        ureq::post(&format!("{}/v1/repos/{}/merge", server.base_url, merge_id))
            .set("Authorization", &bearer(&server.admin_token)),
        &json!({
            "sourceBranch": "conflict-right",
            "targetBranch": "conflict-left",
            "strategy": "ff-only"
        }),
    );
    assert_status(&ffo, 400, "ff-only on diverged");
}

fn step16_user_scoped_listing(server: &TestServer, st: &mut State) {
    // Alice's listing — her repos only, X-Total-Count matches body length.
    let alice = send(
        ureq::get(&format!("{}/v1/repos", server.base_url))
            .set("Authorization", &bearer(&st.alice_jwt)),
    );
    assert_status(&alice, 200, "alice GET /v1/repos");
    let av: Vec<Value> = serde_json::from_str(&alice.1).expect("alice list array");
    let ids: Vec<String> = av
        .iter()
        .filter_map(|r| r.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    assert!(
        ids.contains(&st.alice_repo),
        "alice's list missing alice_repo"
    );
    assert!(!ids.contains(&st.bob_repo), "alice's list leaked bob_repo");
    let alice_total = alice.2.get("x-total-count").cloned().unwrap_or_default();
    assert_eq!(
        alice_total.parse::<usize>().unwrap_or(0),
        av.len(),
        "alice X-Total-Count vs body length"
    );
    // Admin sees more than alice does.
    let admin = send(
        ureq::get(&format!("{}/v1/repos", server.base_url))
            .set("Authorization", &bearer(&server.admin_token)),
    );
    assert_status(&admin, 200, "admin GET /v1/repos");
    let admv: Vec<Value> = serde_json::from_str(&admin.1).expect("admin list array");
    assert!(admv.len() > av.len(), "admin should see > alice's count");
    let admin_total = admin.2.get("x-total-count").cloned().unwrap_or_default();
    assert_eq!(
        admin_total.parse::<usize>().unwrap_or(0),
        admv.len(),
        "admin X-Total-Count vs body length"
    );
    // Pagination — ?limit=1 returns 1 row, X-Total-Count = unpaginated total.
    let p1 = send(
        ureq::get(&format!("{}/v1/repos?limit=1", server.base_url))
            .set("Authorization", &bearer(&server.admin_token)),
    );
    assert_status(&p1, 200, "GET /v1/repos?limit=1");
    let p1v: Vec<Value> = serde_json::from_str(&p1.1).unwrap();
    assert_eq!(p1v.len(), 1);
    assert_eq!(
        p1.2.get("x-total-count").cloned().unwrap_or_default(),
        admin_total
    );
}

fn step17_per_repo_read_endpoints(server: &TestServer, st: &mut State) {
    let auth = bearer(&server.admin_token);
    // Detail — id, headSha = c2_sha, ≥1 ref, commitCount ≥ 2, forkCount = 0.
    let det = send(
        ureq::get(&format!("{}/v1/repos/{}", server.base_url, st.rest_id))
            .set("Authorization", &auth),
    );
    assert_status(&det, 200, "detail");
    let dv = parse_json(&det.1);
    assert_eq!(
        dv.get("id").and_then(Value::as_str),
        Some(st.rest_id.as_str())
    );
    assert_eq!(
        dv.get("headSha").and_then(Value::as_str),
        Some(st.c2_sha.as_str())
    );
    assert!(
        dv.get("refs")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0)
            >= 1
    );
    assert!(dv.get("commitCount").and_then(Value::as_u64).unwrap_or(0) >= 2);
    assert_eq!(dv.get("forkCount").and_then(Value::as_u64), Some(0));
    // Detail on root repo: forkCount ≥ 2 (writable fork + RO fork from steps 4 + 6).
    let root_det = send(
        ureq::get(&format!("{}/v1/repos/{}", server.base_url, st.repo_id))
            .set("Authorization", &auth),
    );
    assert_status(&root_det, 200, "root detail");
    let rd = parse_json(&root_det.1);
    assert!(
        rd.get("forkCount").and_then(Value::as_u64).unwrap_or(0) >= 2,
        "root forkCount should be ≥ 2"
    );
    // Commits — newest-first, c2 has c1 as sole parent.
    let commits = send(
        ureq::get(&format!(
            "{}/v1/repos/{}/commits",
            server.base_url, st.rest_id
        ))
        .set("Authorization", &auth),
    );
    assert_status(&commits, 200, "commits");
    let cv: Vec<Value> = serde_json::from_str(&commits.1).expect("commits array");
    assert!(cv.len() >= 2);
    assert_eq!(
        cv[0].get("sha").and_then(Value::as_str),
        Some(st.c2_sha.as_str())
    );
    let parents: Vec<String> = cv[0]
        .get("parents")
        .and_then(Value::as_array)
        .expect("parents")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    assert_eq!(parents, vec![st.c1_sha.clone()]);
    // Refs — refs/heads/main = c2.
    let refs = send(
        ureq::get(&format!("{}/v1/repos/{}/refs", server.base_url, st.rest_id))
            .set("Authorization", &auth),
    );
    assert_status(&refs, 200, "refs");
    let rv: Vec<Value> = serde_json::from_str(&refs.1).unwrap();
    let main_sha = rv
        .iter()
        .find(|r| r.get("name").and_then(Value::as_str) == Some("refs/heads/main"))
        .and_then(|r| r.get("sha").and_then(Value::as_str))
        .expect("refs/heads/main");
    assert_eq!(main_sha, st.c2_sha);
    // Tree — README + src/ + src/b.txt; src/a.txt absent.
    let tree = send(
        ureq::get(&format!("{}/v1/repos/{}/tree", server.base_url, st.rest_id))
            .set("Authorization", &auth),
    );
    assert_status(&tree, 200, "tree");
    let tv: Vec<Value> = serde_json::from_str(&tree.1).expect("tree array");
    let has = |path: &str, kind: &str| -> bool {
        tv.iter().any(|e| {
            e.get("path").and_then(Value::as_str) == Some(path)
                && e.get("type").and_then(Value::as_str) == Some(kind)
        })
    };
    assert!(has("README.md", "file"));
    assert!(has("src/b.txt", "file"));
    assert!(has("src", "dir"));
    assert!(!tv
        .iter()
        .any(|e| e.get("path").and_then(Value::as_str) == Some("src/a.txt")));
    // Blob — README at HEAD contains "rest-initial".
    let blob = send(
        ureq::get(&format!(
            "{}/v1/repos/{}/blob?path=README.md",
            server.base_url, st.rest_id
        ))
        .set("Authorization", &auth),
    );
    assert_status(&blob, 200, "blob");
    assert!(blob.1.contains("rest-initial"));
    // ObjectStore hit counter must be ≥ 1 after the blob read.
    let metrics = send(ureq::get(&format!("{}/metrics", server.base_url)));
    assert_status(&metrics, 200, "/metrics after blob");
    let saw_hit = metrics.1.lines().any(|line| {
        line.starts_with("artifacts_object_reads_total{")
            && line.contains("backend=\"fs\"")
            && line.contains("outcome=\"hit\"")
            && {
                line.split_whitespace()
                    .last()
                    .and_then(|n| n.parse::<u64>().ok())
                    .unwrap_or(0)
                    >= 1
            }
    });
    assert!(
        saw_hit,
        "artifacts_object_reads_total{{backend=fs,outcome=hit}} not ≥ 1"
    );
    // Diff — c2 deletes src/a.txt + adds src/b.txt → two files, add + delete.
    let diff = send(
        ureq::get(&format!(
            "{}/v1/repos/{}/diff?commit={}",
            server.base_url, st.rest_id, st.c2_sha
        ))
        .set("Authorization", &auth),
    );
    assert_status(&diff, 200, "diff");
    let dv: Vec<Value> = serde_json::from_str(&diff.1).expect("diff array");
    assert!(dv.len() >= 2);
    let statuses: Vec<&str> = dv
        .iter()
        .filter_map(|f| f.get("status").and_then(Value::as_str))
        .collect();
    assert!(statuses.contains(&"deleted"));
    assert!(statuses.contains(&"added"));
    // Notes — write via git CLI, read via REST.
    let note_clone = st.work_path("note_setup");
    git_clone(&st.rest_remote, &note_clone);
    git_in_must(
        &note_clone,
        &[
            "notes",
            "--ref=refs/notes/agent",
            "add",
            "-m",
            r#"{"version":1,"sessionId":"smoke","model":"test","turns":[]}"#,
            &st.c2_sha,
        ],
    );
    git_in_must(
        &note_clone,
        &["push", "--quiet", &st.rest_remote, "refs/notes/agent"],
    );
    let note = send(
        ureq::get(&format!(
            "{}/v1/repos/{}/notes?ref=refs/notes/agent&commit={}",
            server.base_url, st.rest_id, st.c2_sha
        ))
        .set("Authorization", &auth),
    );
    assert_status(&note, 200, "note fetch");
    let nv = parse_json(&note.1);
    let txt = json_str(&nv, "text");
    assert!(
        txt.contains(r#""sessionId":"smoke""#),
        "note text wrong: {txt}"
    );
    // Missing note → 404 (c1 has no note on agent ref).
    let miss = send(
        ureq::get(&format!(
            "{}/v1/repos/{}/notes?ref=refs/notes/agent&commit={}",
            server.base_url, st.rest_id, st.c1_sha
        ))
        .set("Authorization", &auth),
    );
    assert_status(&miss, 404, "missing note");
}

fn step18_sse_events(server: &TestServer, st: &mut State) {
    let auth = bearer(&server.admin_token);

    // Start a raw HTTP/1.1 connection so we can read the SSE stream
    // line-by-line. ureq's into_reader() works, but we need to set a
    // short timeout so the read doesn't block forever after the
    // commit/fork have landed.
    let stream = TcpStream::connect(server.bind.as_str()).expect("connect SSE");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut sse = stream.try_clone().expect("clone stream");
    let req = format!(
        "GET /v1/events HTTP/1.1\r\nHost: {host}\r\nAuthorization: {auth}\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n",
        host = server.bind,
        auth = auth,
    );
    sse.write_all(req.as_bytes()).expect("write SSE request");

    // Consume the response in a background thread so we can keep
    // issuing commits/forks meanwhile.
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let reader = BufReader::new(sse);
        for line in reader.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    // Give the SSE subscribe a moment to register on the server.
    thread::sleep(Duration::from_millis(300));

    // Create a fresh repo, commit, fork — every step emits an event.
    let create =
        send(ureq::post(&format!("{}/v1/repos", server.base_url)).set("Authorization", &auth));
    assert_status(&create, 200, "sse create repo");
    let ev_id = json_str(&parse_json(&create.1), "id").to_string();
    let commit = send_json(
        ureq::post(&format!("{}/v1/repos/{}/commits", server.base_url, ev_id))
            .set("Authorization", &auth),
        &json!({
            "branch": "main",
            "parent": null,
            "message": "first",
            "changes": [{"op": "write", "path": "README.md", "content": "hi"}]
        }),
    );
    assert_status(&commit, 200, "sse commit");
    let fork = send_json(
        ureq::post(&format!("{}/v1/repos/{}/forks", server.base_url, ev_id))
            .set("Authorization", &auth),
        &json!({}),
    );
    assert_status(&fork, 200, "sse fork");

    // Drain lines for up to 3s, looking for both `"kind":"commit"` and
    // `"kind":"fork"` for our ev_id. SSE events can span multiple
    // `data:` lines; collect everything so the failure diagnostic
    // shows what we actually received.
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut seen_commit = false;
    let mut seen_fork = false;
    let mut transcript = Vec::new();
    // commit events carry `repoId`; fork events carry `parentRepoId` +
    // `childRepoId` instead (no `repoId` field). Match each event kind
    // against the field it actually has.
    let commit_marker = format!(r#""repoId":"{ev_id}""#);
    let fork_marker = format!(r#""parentRepoId":"{ev_id}""#);
    while Instant::now() < deadline && !(seen_commit && seen_fork) {
        let timeout = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(timeout) {
            Ok(line) => {
                if line.contains(r#""kind":"commit""#) && line.contains(&commit_marker) {
                    seen_commit = true;
                }
                if line.contains(r#""kind":"fork""#) && line.contains(&fork_marker) {
                    seen_fork = true;
                }
                transcript.push(line);
            }
            Err(_) => break,
        }
    }
    assert!(
        seen_commit,
        "SSE stream missing commit event for {ev_id}; saw: {transcript:?}"
    );
    assert!(
        seen_fork,
        "SSE stream missing fork event for {ev_id}; saw: {transcript:?}"
    );
    let _ = st;
}

fn step_admin_inspection(server: &TestServer, st: &State) {
    let auth = bearer(&server.admin_token);
    let list =
        send(ureq::get(&format!("{}/v1/admin/repos", server.base_url)).set("Authorization", &auth));
    assert_status(&list, 200, "admin list");
    let lv: Vec<Value> = serde_json::from_str(&list.1).expect("admin list array");
    assert!(
        lv.len() >= 5,
        "admin list returned {} rows, expected ≥ 5",
        lv.len()
    );
    let with_source = lv
        .iter()
        .filter(|r| r.get("sourceId").and_then(Value::as_str).is_some())
        .count();
    assert!(
        with_source >= 1,
        "no rows with sourceId — fork discovery via alternates broken"
    );
    // JWT user → 403.
    let jwt = send(
        ureq::get(&format!("{}/v1/admin/repos", server.base_url))
            .set("Authorization", &bearer(&st.alice_jwt)),
    );
    assert_status(&jwt, 403, "JWT user on admin/repos");
    // ?limit=1 — 1 row, X-Total-Count = full count.
    let p1 = send(
        ureq::get(&format!("{}/v1/admin/repos?limit=1", server.base_url))
            .set("Authorization", &auth),
    );
    assert_status(&p1, 200, "admin/repos?limit=1");
    let p1v: Vec<Value> = serde_json::from_str(&p1.1).unwrap();
    assert_eq!(p1v.len(), 1);
    assert_eq!(
        p1.2.get("x-total-count")
            .map(String::as_str)
            .unwrap_or("")
            .parse::<usize>()
            .unwrap_or(0),
        lv.len(),
    );
    // Detail — ≥1 ref + size > 0.
    let det = send(
        ureq::get(&format!(
            "{}/v1/admin/repos/{}",
            server.base_url, st.repo_id
        ))
        .set("Authorization", &auth),
    );
    assert_status(&det, 200, "admin detail");
    let dv = parse_json(&det.1);
    let refs = dv.get("refs").and_then(Value::as_array).expect("refs");
    assert!(!refs.is_empty());
    assert!(
        dv.get("sizeBytes").and_then(Value::as_u64).unwrap_or(0) > 0,
        "sizeBytes must be > 0"
    );
}

fn step_audit_log(server: &TestServer, st: &State) {
    let auth = bearer(&server.admin_token);
    let resp = send(
        ureq::get(&format!("{}/v1/admin/audit?limit=200", server.base_url))
            .set("Authorization", &auth),
    );
    assert_status(&resp, 200, "audit list");
    let rows: Vec<Value> = serde_json::from_str(&resp.1).expect("audit array");
    assert!(
        rows.len() >= 5,
        "audit list returned {} rows, expected ≥ 5",
        rows.len()
    );
    for kind in ["repo.create", "repo.fork", "token.mint", "token.revoke"] {
        let seen = rows
            .iter()
            .filter(|r| r.get("event").and_then(Value::as_str) == Some(kind))
            .count();
        assert!(seen >= 1, "audit log missing event kind `{kind}`");
    }
    // Trigger a repo.delete to round out the set.
    let create =
        send(ureq::post(&format!("{}/v1/repos", server.base_url)).set("Authorization", &auth));
    let del_id = json_str(&parse_json(&create.1), "id").to_string();
    let del = send(
        ureq::delete(&format!("{}/v1/repos/{}", server.base_url, del_id))
            .set("Authorization", &auth),
    );
    assert_status(&del, 200, "delete repo for audit");
    let after = send(
        ureq::get(&format!(
            "{}/v1/admin/audit?event=repo.delete&limit=10",
            server.base_url
        ))
        .set("Authorization", &auth),
    );
    let arows: Vec<Value> = serde_json::from_str(&after.1).expect("audit delete rows");
    assert!(
        arows
            .iter()
            .any(|r| r.get("repoId").and_then(Value::as_str) == Some(del_id.as_str())),
        "just-deleted repo missing from audit log"
    );
    // Filter by event kind round-trips.
    let filtered = send(
        ureq::get(&format!(
            "{}/v1/admin/audit?event=repo.create&limit=50",
            server.base_url
        ))
        .set("Authorization", &auth),
    );
    let fv: Vec<Value> = serde_json::from_str(&filtered.1).unwrap();
    assert!(!fv.is_empty());
    assert!(
        fv.iter()
            .all(|r| r.get("event").and_then(Value::as_str) == Some("repo.create")),
        "?event=repo.create filter leaked other kinds"
    );
    // JWT user → 403.
    let jwt = send(
        ureq::get(&format!("{}/v1/admin/audit", server.base_url))
            .set("Authorization", &bearer(&st.alice_jwt)),
    );
    assert_status(&jwt, 403, "JWT on audit");
    // Pagination — page1 (offset=2) is strictly older than page0.
    let p0 = send(
        ureq::get(&format!("{}/v1/admin/audit?limit=2", server.base_url))
            .set("Authorization", &auth),
    );
    let p1 = send(
        ureq::get(&format!(
            "{}/v1/admin/audit?limit=2&offset=2",
            server.base_url
        ))
        .set("Authorization", &auth),
    );
    let p0v: Vec<Value> = serde_json::from_str(&p0.1).unwrap();
    let p1v: Vec<Value> = serde_json::from_str(&p1.1).unwrap();
    let min_id = |rows: &[Value]| {
        rows.iter()
            .filter_map(|r| r.get("id").and_then(Value::as_u64))
            .min()
            .expect("id in page")
    };
    let max_id = |rows: &[Value]| {
        rows.iter()
            .filter_map(|r| r.get("id").and_then(Value::as_u64))
            .max()
            .expect("id in page")
    };
    assert!(
        max_id(&p1v) < min_id(&p0v),
        "audit page1 not strictly older"
    );
    // Cheap stats endpoint.
    let stats = send(
        ureq::get(&format!("{}/v1/admin/audit/stats", server.base_url)).set("Authorization", &auth),
    );
    let sv = parse_json(&stats.1);
    let total = sv.get("count").and_then(Value::as_u64).expect("count");
    assert!(total >= rows.len() as u64);
}

fn step_admin_jwt_key_rotation(server: &TestServer, st: &mut State) {
    let auth = bearer(&server.admin_token);

    // JWT user denied (must fire BEFORE the rotation; alice_jwt is
    // still signed under the original secret here).
    let jwt = send(
        ureq::post(&format!("{}/v1/admin/jwt-key/rotate", server.base_url))
            .set("Authorization", &bearer(&st.alice_jwt)),
    );
    assert_status(&jwt, 403, "JWT user cannot rotate JWT key");

    // Admin rotation succeeds + returns a non-empty key.
    let rotate = send(
        ureq::post(&format!("{}/v1/admin/jwt-key/rotate", server.base_url))
            .set("Authorization", &auth),
    );
    assert_status(&rotate, 200, "admin rotates JWT key");
    let v = parse_json(&rotate.1);
    let new_key = json_str(&v, "key").to_string();
    assert!(!new_key.is_empty(), "rotated jwt key is empty");
    // Env-pinned deployments don't persist to disk — the smoke harness
    // sets ARTIFACTS_JWT_SECRET so persisted should be false.
    assert_eq!(
        v.get("persisted").and_then(Value::as_bool),
        Some(false),
        "env-pinned deployment should not persist on rotate"
    );

    // The new key is the live one — a JWT signed under it must
    // authorize. Re-sign alice_jwt + bob_jwt under the new key so
    // the subsequent admin-token-rotation step's "JWT user → 403"
    // check still has a valid token to present (otherwise it would
    // fail signature verification first and return 401).
    st.alice_jwt = sign_jwt(&new_key, "alice");
    st.bob_jwt = sign_jwt(&new_key, "bob");

    let new_jwt_check = send(
        ureq::get(&format!("{}/v1/repos", server.base_url))
            .set("Authorization", &bearer(&st.alice_jwt)),
    );
    assert_status(
        &new_jwt_check,
        200,
        "JWT signed under new key should authorize",
    );
}

fn step_admin_token_rotation(server: &TestServer, _st: &State) {
    let auth = bearer(&server.admin_token);
    let rotate = send(
        ureq::post(&format!("{}/v1/admin/token/rotate", server.base_url))
            .set("Authorization", &auth),
    );
    assert_status(&rotate, 200, "rotate token");
    let new_admin = json_str(&parse_json(&rotate.1), "token").to_string();
    assert!(!new_admin.is_empty() && new_admin != server.admin_token);
    // Old token → 401.
    let old = send(
        ureq::get(&format!("{}/v1/admin/repos", server.base_url))
            .set("Authorization", &bearer(&server.admin_token)),
    );
    assert_status(&old, 401, "old admin token");
    // New token → 200.
    let new = send(
        ureq::get(&format!("{}/v1/admin/repos", server.base_url))
            .set("Authorization", &bearer(&new_admin)),
    );
    assert_status(&new, 200, "new admin token");
    // Rotate back via the new token so subsequent steps still authorize
    // with `server.admin_token` — though the test does no more admin
    // calls after this, this keeps the harness's invariant consistent.
    let _ = send(
        ureq::post(&format!("{}/v1/admin/token/rotate", server.base_url))
            .set("Authorization", &bearer(&new_admin)),
    );
    // JWT user cannot rotate.
    let jwt = send(
        ureq::post(&format!("{}/v1/admin/token/rotate", server.base_url))
            .set("Authorization", &bearer(&_st.alice_jwt)),
    );
    assert_status(&jwt, 403, "JWT cannot rotate admin token");
}

fn step_drain_readiness(server: &mut TestServer, _st: &State) {
    // Tear down the current server. The drain step runs a dedicated
    // server that opts into a 2 s drain-delay so the readiness flip is
    // observable; the rest of the smoke ran with drain_delay=0 for
    // iteration speed.
    server.stop();
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base_url = format!("http://{bind}");
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&server.log_path)
        .expect("open log");
    let log_stderr = log_file.try_clone().expect("clone log handle");
    let bin = env!("CARGO_BIN_EXE_artifacts");
    let mut child = Command::new(bin)
        .env("ARTIFACTS_ADMIN_TOKEN", &server.admin_token)
        .env("ARTIFACTS_JWT_SECRET", &server.jwt_secret)
        .env("ARTIFACTS_SHUTDOWN_DRAIN_DELAY_SECS", "2")
        .arg("serve")
        .arg("--data-dir")
        .arg(server.data_dir.path())
        .arg("--bind")
        .arg(&bind)
        .arg("--public-base-url")
        .arg(&base_url)
        .stdin(Stdio::null())
        .stdout(log_file)
        .stderr(log_stderr)
        .spawn()
        .expect("spawn drain server");
    // Wait until /v1/health answers.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut ready = false;
    while Instant::now() < deadline {
        if let Ok(r) = ureq::get(&format!("{base_url}/v1/health"))
            .timeout(Duration::from_millis(200))
            .call()
        {
            if r.status() == 200 {
                ready = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    if !ready {
        let _ = child.kill();
        panic!("drain server did not become ready");
    }
    // Pre-flight: readiness == 200 + ok.
    let pre = send(ureq::get(&format!("{base_url}/v1/health/ready")));
    assert_status(&pre, 200, "pre-shutdown readiness");
    // SIGTERM. Readiness must flip to 503 + draining:true within the
    // 2 s drain-delay window.
    // SAFETY: `libc::kill` is an FFI call with no preconditions on the
    // caller beyond a valid pid; `child.id()` is this process's live
    // child, and SIGTERM is a valid signal number. No memory is shared.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut flipped = false;
    while Instant::now() < deadline {
        let reply = send(
            ureq::get(&format!("{base_url}/v1/health/ready")).timeout(Duration::from_millis(200)),
        );
        if reply.0 == 503
            && parse_json(&reply.1)
                .get("draining")
                .and_then(Value::as_bool)
                == Some(true)
        {
            flipped = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        flipped,
        "readiness did not flip to 503+draining within drain-delay"
    );
    // Reap the drain server so the next start sees a clean port.
    let _ = child.wait();
    // Restart the original server so we can read the server.shutdown
    // audit event.
    server.spawn();
    server.wait_ready();
    let after = send(
        ureq::get(&format!(
            "{}/v1/admin/audit?event=server.shutdown",
            server.base_url
        ))
        .set("Authorization", &bearer(&server.admin_token)),
    );
    assert_status(&after, 200, "shutdown audit list");
    let av: Vec<Value> = serde_json::from_str(&after.1).expect("audit array");
    assert!(!av.is_empty(), "no server.shutdown audit row");
    // Newest row's fields_json carries kind=graceful + uptime_secs ≥ 0.
    let fields_raw = av[0]
        .get("fields")
        .and_then(Value::as_str)
        .expect("fields_json string");
    let fields: Value = serde_json::from_str(fields_raw).expect("fields parse");
    assert_eq!(fields.get("kind").and_then(Value::as_str), Some("graceful"));
    assert!(
        fields
            .get("uptime_secs")
            .and_then(Value::as_i64)
            .unwrap_or(-1)
            >= 0
    );
}

// ---------------------------------------------------------------------
// Misc helpers.
// ---------------------------------------------------------------------

/// Collect every file path relative to `root`, excluding `.git/**`.
/// Used for byte-comparing two working trees.
fn list_files_excluding_git(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let p = entry.path();
        let rel = p.strip_prefix(root).unwrap().to_path_buf();
        if rel
            .components()
            .next()
            .map(|c| c.as_os_str() == ".git")
            .unwrap_or(false)
        {
            continue;
        }
        if p.is_dir() {
            walk(root, &p, out);
        } else {
            let bytes = std::fs::read(&p).unwrap_or_default();
            out.push((rel, bytes));
        }
    }
}

/// Pull a Prometheus gauge value out of the /metrics body. Returns 0.0
/// if missing (caller asserts ≥ 1).
fn extract_gauge(body: &str, name: &str) -> f64 {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix(name) {
            if rest.starts_with(' ') {
                return rest.trim().parse::<f64>().unwrap_or(0.0);
            }
        }
    }
    0.0
}
