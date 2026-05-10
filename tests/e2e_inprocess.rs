//! In-process end-to-end coverage of the real server.
//!
//! `integration_smoke.rs` spawns the compiled `artifacts` binary as a
//! child process and drives it over HTTP. That validates the shipping
//! binary (and process-level behaviours like SIGTERM drain), but the
//! server-side execution happens in a *separate process* that coverage
//! instrumentation can't follow — so the bulk of `app::serve`,
//! `smart_http`, `commits`, `merge`, `reads`, and `rest/*` reads as
//! "uncovered" even though every push/clone/commit exercises them.
//!
//! This test boots `app::serve` **in-process** on an ephemeral port (a
//! Tokio runtime owned by the test, the server on its worker threads),
//! then drives it with the real `git` CLI as a client plus blocking
//! HTTP. The git *client* is a subprocess we don't care about; the
//! server request handling runs in this test binary, so it counts.
//!
//! Scope is deliberately broad — one long scenario rather than many
//! short ones — because `serve()` installs process-global state
//! (tracing subscriber, metrics recorder) that can only be initialised
//! once per process.

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser as _;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::{json, Value};

// ---------------------------------------------------------------------
// In-process server harness.
// ---------------------------------------------------------------------

struct InProcServer {
    base_url: String,
    admin_token: String,
    jwt_secret: String,
    _data_dir: tempfile::TempDir,
    // The runtime keeps the server task alive; dropping it shuts the
    // server down at end of test. Declared last so it drops last.
    rt: tokio::runtime::Runtime,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl InProcServer {
    fn start() -> Self {
        // A clap wrapper lets the real arg parser fill every default;
        // we only override what the scenario needs. This also exercises
        // the `ServeArgs` parse path itself.
        #[derive(clap::Parser)]
        struct Wrapper {
            #[command(flatten)]
            args: artifacts::app::ServeArgs,
        }

        let data_dir = tempfile::Builder::new()
            .prefix("artifacts-e2e-")
            .tempdir()
            .expect("tempdir");
        let port = pick_free_port();
        let bind = format!("127.0.0.1:{port}");
        let base_url = format!("http://{bind}");
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let admin_token = format!("e2e-admin-{ts}");
        let jwt_secret = format!("e2e-jwt-{ts}");

        let args = Wrapper::parse_from([
            "artifacts",
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "--bind",
            &bind,
            "--public-base-url",
            &base_url,
            "--admin-token",
            &admin_token,
            "--jwt-secret",
            &jwt_secret,
            "--max-repos-per-user",
            "10",
            "--max-commit-blob-bytes",
            "1024",
            // Disable the periodic GC sweep + drain delay so the test
            // stays fast and deterministic.
            "--gc-interval-secs",
            "0",
            "--shutdown-drain-delay-secs",
            "0",
            "--shutdown-timeout-secs",
            "2",
        ])
        .args;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build runtime");
        let handle = rt.spawn(async move {
            if let Err(e) = artifacts::app::serve(args).await {
                eprintln!("in-process serve() exited with error: {e:#}");
            }
        });

        let server = InProcServer {
            base_url,
            admin_token,
            jwt_secret,
            _data_dir: data_dir,
            rt,
            handle: Some(handle),
        };
        server.wait_ready();
        server
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        let url = format!("{}/v1/health", self.base_url);
        while Instant::now() < deadline {
            if let Ok(resp) = ureq::get(&url).timeout(Duration::from_millis(200)).call() {
                if resp.status() == 200 {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("in-process server did not become ready within 10s");
    }
}

impl Drop for InProcServer {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
        // Give the abort a moment; the runtime drop then finalises.
        self.rt
            .block_on(async { tokio::time::sleep(Duration::from_millis(50)).await });
    }
}

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe socket");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

// ---------------------------------------------------------------------
// HTTP + git helpers (compact versions of the smoke's).
// ---------------------------------------------------------------------

type HttpReply = (u16, String, BTreeMap<String, String>);

fn collect(resp: ureq::Response) -> HttpReply {
    let status = resp.status();
    let mut headers = BTreeMap::new();
    for name in resp.headers_names() {
        if let Some(v) = resp.header(&name) {
            headers.insert(name.to_lowercase(), v.to_string());
        }
    }
    (status, resp.into_string().unwrap_or_default(), headers)
}

fn send(req: ureq::Request) -> HttpReply {
    match req.call() {
        Ok(r) => collect(r),
        Err(ureq::Error::Status(_, r)) => collect(r),
        Err(e) => panic!("transport error: {e}"),
    }
}

fn send_json(req: ureq::Request, body: &Value) -> HttpReply {
    match req.send_json(body.clone()) {
        Ok(r) => collect(r),
        Err(ureq::Error::Status(_, r)) => collect(r),
        Err(e) => panic!("transport error: {e}"),
    }
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn parse(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("bad json: {e}; body=`{body}`"))
}

fn jstr<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string `{key}` in {v}"))
}

fn assert_status(reply: &HttpReply, expected: u16, ctx: &str) {
    assert_eq!(
        reply.0, expected,
        "{ctx}: expected {expected}, got {}; body={}",
        reply.0, reply.1
    );
}

fn git(repo: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("spawn git")
}

fn git_must(repo: &Path, args: &[&str]) {
    let out = git(repo, args);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn git_clone(remote: &str, dest: &Path) {
    let out = Command::new("git")
        .args(["clone", "--quiet", remote, dest.to_str().unwrap()])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("spawn git clone");
    assert!(
        out.status.success(),
        "git clone {remote} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn git_config_user(repo: &Path) {
    git_must(repo, &["config", "user.email", "e2e@artifacts.local"]);
    git_must(repo, &["config", "user.name", "E2E"]);
}

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
    .unwrap()
}

// ---------------------------------------------------------------------
// The scenario.
// ---------------------------------------------------------------------

#[test]
fn e2e_inprocess_full_surface() {
    let work = tempfile::tempdir().unwrap();
    let srv = InProcServer::start();
    let base = &srv.base_url;
    let admin = &srv.admin_token;

    // --- liveness / readiness / metrics ------------------------------
    let h = send(ureq::get(&format!("{base}/v1/health")));
    assert_status(&h, 200, "health");
    let r = send(ureq::get(&format!("{base}/v1/health/ready")));
    assert_status(&r, 200, "ready");
    let m = send(ureq::get(&format!("{base}/metrics")));
    assert_status(&m, 200, "metrics");
    assert!(m.1.contains("artifacts_"), "metrics body: {}", m.1);

    // Unauthorized control-plane call is rejected.
    let unauth = send(ureq::get(&format!("{base}/v1/repos")));
    assert_status(&unauth, 401, "list repos without auth");

    // --- create repo + clone/push over smart-HTTP --------------------
    let created =
        send(ureq::post(&format!("{base}/v1/repos")).set("Authorization", &bearer(admin)));
    assert_status(&created, 200, "create repo");
    let cv = parse(&created.1);
    let repo_id = jstr(&cv, "id").to_string();
    let remote = jstr(&cv, "remote").to_string();

    let clone_a = work.path().join("a");
    git_clone(&remote, &clone_a); // empty-repo upload-pack
    git_config_user(&clone_a);
    std::fs::write(clone_a.join("README.md"), "hello from e2e\n").unwrap();
    std::fs::create_dir_all(clone_a.join("src")).unwrap();
    std::fs::write(clone_a.join("src/main.rs"), "fn main(){}\n").unwrap();
    git_must(&clone_a, &["add", "."]);
    git_must(&clone_a, &["commit", "--quiet", "-m", "init"]);
    git_must(&clone_a, &["branch", "-M", "main"]);
    git_must(&clone_a, &["push", "--quiet", "origin", "main"]); // receive-pack

    // Re-clone into a fresh dir → upload-pack with real objects.
    let clone_a2 = work.path().join("a2");
    git_clone(&remote, &clone_a2);
    assert_eq!(
        std::fs::read_to_string(clone_a2.join("README.md")).unwrap(),
        "hello from e2e\n"
    );

    // --- per-repo read endpoints on the pushed repo ------------------
    let auth = |req: ureq::Request| req.set("Authorization", &bearer(admin));
    let detail = send(auth(ureq::get(&format!("{base}/v1/repos/{repo_id}"))));
    assert_status(&detail, 200, "repo detail");
    let commits = send(auth(ureq::get(&format!(
        "{base}/v1/repos/{repo_id}/commits?ref=main&limit=10"
    ))));
    assert_status(&commits, 200, "list commits");
    assert!(parse(&commits.1).as_array().is_some_and(|a| !a.is_empty()));
    let tree = send(auth(ureq::get(&format!(
        "{base}/v1/repos/{repo_id}/tree?ref=main"
    ))));
    assert_status(&tree, 200, "tree");
    let blob = send(auth(ureq::get(&format!(
        "{base}/v1/repos/{repo_id}/blob?commit=main&path=README.md"
    ))));
    assert_status(&blob, 200, "blob");
    let refs = send(auth(ureq::get(&format!("{base}/v1/repos/{repo_id}/refs"))));
    assert_status(&refs, 200, "refs");

    // --- REST commit builder (orphan + CAS + conflict + bad path) ----
    let rest = send(auth(ureq::post(&format!("{base}/v1/repos"))));
    assert_status(&rest, 200, "create rest repo");
    let rid = jstr(&parse(&rest.1), "id").to_string();
    let commit_url = format!("{base}/v1/repos/{rid}/commits");

    let c1 = send_json(
        auth(ureq::post(&commit_url)),
        &json!({
            "branch": "main", "parent": null, "message": "c1",
            "changes": [{"op":"write","path":"README.md","content":"# c1\n"},
                        {"op":"write","path":"src/a.txt","content":"a"}]
        }),
    );
    assert_status(&c1, 200, "rest c1");
    let c1_sha = jstr(&parse(&c1.1), "commit").to_string();
    assert_eq!(c1_sha.len(), 40);

    let c2 = send_json(
        auth(ureq::post(&commit_url)),
        &json!({
            "branch": "main", "parent": c1_sha, "message": "c2",
            "changes": [{"op":"delete","path":"src/a.txt"},
                        {"op":"write","path":"src/b.txt","content":"b"}]
        }),
    );
    assert_status(&c2, 200, "rest c2");
    let c2_sha = jstr(&parse(&c2.1), "commit").to_string();

    // Stale parent → 409 ref_conflict.
    let stale = send_json(
        auth(ureq::post(&commit_url)),
        &json!({
            "branch": "main", "parent": c1_sha, "message": "stale",
            "changes": [{"op":"write","path":"x","content":"x"}]
        }),
    );
    assert_status(&stale, 409, "rest stale parent");

    // Path traversal → 400.
    let bad = send_json(
        auth(ureq::post(&commit_url)),
        &json!({
            "branch": "main", "parent": c2_sha, "message": "bad",
            "changes": [{"op":"write","path":"../escape","content":"x"}]
        }),
    );
    assert_status(&bad, 400, "rest bad path");

    // Diff of c2.
    let diff = send(auth(ureq::get(&format!(
        "{base}/v1/repos/{rid}/diff?commit={c2_sha}"
    ))));
    assert_status(&diff, 200, "diff");

    // --- merge (clean fast-forward of a feature branch) --------------
    // Branches are created the way a real client does: push a new
    // branch off main, then merge it back. Reuses `repo_id`, which
    // already has a `main` with one commit.
    let merge_work = work.path().join("merge_work");
    git_clone(&remote, &merge_work);
    git_config_user(&merge_work);
    git_must(&merge_work, &["checkout", "-q", "-B", "feature", "main"]);
    std::fs::write(merge_work.join("feature.txt"), "feat\n").unwrap();
    git_must(&merge_work, &["add", "feature.txt"]);
    git_must(&merge_work, &["commit", "-q", "-m", "feature work"]);
    git_must(&merge_work, &["push", "-q", "origin", "feature"]);
    let merge = send_json(
        auth(ureq::post(&format!("{base}/v1/repos/{repo_id}/merge"))),
        &json!({"sourceBranch":"feature","targetBranch":"main"}),
    );
    assert_status(&merge, 200, "merge feature->main");
    assert_eq!(
        parse(&merge.1).get("fastForward").and_then(Value::as_bool),
        Some(true),
        "expected fast-forward merge"
    );

    // --- fork --------------------------------------------------------
    let fork = send_json(
        auth(ureq::post(&format!("{base}/v1/repos/{repo_id}/forks"))),
        &json!({}),
    );
    assert_status(&fork, 200, "fork");
    let fork_remote = jstr(&parse(&fork.1), "remote").to_string();
    git_clone(&fork_remote, &work.path().join("fork"));

    // --- tokens: mint / list / rotate / revoke ----------------------
    let mint = send_json(
        auth(ureq::post(&format!("{base}/v1/repos/{repo_id}/tokens"))),
        &json!({"scope":"read"}),
    );
    assert_status(&mint, 200, "mint token");
    let minted = jstr(&parse(&mint.1), "token").to_string();
    let list_tok = send(auth(ureq::get(&format!(
        "{base}/v1/repos/{repo_id}/tokens"
    ))));
    assert_status(&list_tok, 200, "list tokens");
    let rotate = send_json(
        auth(ureq::post(&format!(
            "{base}/v1/repos/{repo_id}/tokens/rotate"
        ))),
        &json!({}),
    );
    assert_status(&rotate, 200, "rotate tokens");
    let revoke = send_json(
        auth(ureq::post(&format!("{base}/v1/tokens/revoke"))),
        &json!({"token": minted}),
    );
    assert_status(&revoke, 200, "revoke token");

    // --- webhooks: create / list / delete ----------------------------
    let wh = send_json(
        auth(ureq::post(&format!("{base}/v1/repos/{repo_id}/webhooks"))),
        &json!({"url":"https://example.invalid/hook","events":["commit","fork"]}),
    );
    assert_status(&wh, 200, "create webhook");
    let hook_id = jstr(&parse(&wh.1), "id").to_string();
    // A misspelled event kind is rejected at the body-deserialize
    // boundary (axum's Json extractor → 422), so a typo'd subscription
    // can never be created and then silently never fire.
    let bad_wh = send_json(
        auth(ureq::post(&format!("{base}/v1/repos/{repo_id}/webhooks"))),
        &json!({"url":"https://example.invalid/h2","events":["comit"]}),
    );
    assert_status(&bad_wh, 422, "webhook bad event kind");
    let list_wh = send(auth(ureq::get(&format!(
        "{base}/v1/repos/{repo_id}/webhooks"
    ))));
    assert_status(&list_wh, 200, "list webhooks");
    let del_wh = send(auth(ureq::delete(&format!(
        "{base}/v1/repos/{repo_id}/webhooks/{hook_id}"
    ))));
    assert_status(&del_wh, 200, "delete webhook");

    // --- admin surfaces ----------------------------------------------
    assert_status(
        &send(auth(ureq::get(&format!("{base}/v1/admin/repos")))),
        200,
        "admin list repos",
    );
    assert_status(
        &send(auth(ureq::get(&format!("{base}/v1/admin/repos/{repo_id}")))),
        200,
        "admin get repo",
    );
    assert_status(
        &send(auth(ureq::get(&format!(
            "{base}/v1/admin/repos/{repo_id}/gc-preview"
        )))),
        200,
        "admin gc preview",
    );
    assert_status(
        &send_json(
            auth(ureq::post(&format!("{base}/v1/admin/repos/{repo_id}/gc"))),
            &json!({}),
        ),
        200,
        "admin gc run",
    );
    assert_status(
        &send(auth(ureq::get(&format!("{base}/v1/admin/audit")))),
        200,
        "admin audit list",
    );
    assert_status(
        &send(auth(ureq::get(&format!("{base}/v1/admin/audit/stats")))),
        200,
        "admin audit stats",
    );
    assert_status(
        &send(auth(ureq::get(&format!(
            "{base}/v1/admin/audit/verify-chain"
        )))),
        200,
        "admin audit verify-chain",
    );

    // Key rotations that don't disturb the admin token.
    assert_status(
        &send_json(
            auth(ureq::post(&format!("{base}/v1/admin/webhook-key/rotate"))),
            &json!({}),
        ),
        200,
        "rotate webhook key",
    );

    // --- JWT-user ownership scoping ----------------------------------
    let alice = sign_jwt(&srv.jwt_secret, "alice");
    let alice_repo =
        send(ureq::post(&format!("{base}/v1/repos")).set("Authorization", &bearer(&alice)));
    assert_status(&alice_repo, 200, "alice creates repo");
    let alice_list =
        send(ureq::get(&format!("{base}/v1/repos")).set("Authorization", &bearer(&alice)));
    assert_status(&alice_list, 200, "alice lists repos");
    // Alice sees exactly her own repo, not admin's.
    let arr = parse(&alice_list.1);
    assert_eq!(
        arr.as_array().map(Vec::len),
        Some(1),
        "owner-scoped listing: {}",
        alice_list.1
    );

    // --- delete a repo (force, since it has a fork) ------------------
    let del = send(auth(ureq::delete(&format!(
        "{base}/v1/repos/{rid}?force=true"
    ))));
    assert_status(&del, 200, "delete repo");
}
