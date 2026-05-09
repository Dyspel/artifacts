//! Reproducible `cargo bench` harness for the pack-generation hot path.
//!
//! B3 ("concurrent load bench") was historically driven by an ad-hoc
//! shell script with no committed, reproducible entry point. This is
//! that entry point: a criterion bench over [`generate_pack`], the
//! function on the clone/fetch hot path that walks a repo's history
//! and encodes a v2 packfile.
//!
//! Two scenarios, both fed a synthetic linear-history repo built once
//! via git plumbing (`hash-object` / `mktree` / `commit-tree`) in
//! setup so the timed region is pure pack generation:
//!
//!   - `full_clone`: `wants = [tip]`, `haves = []` — packs the entire
//!     history closure, the cold-clone cost.
//!   - `incremental`: `wants = [tip]`, `haves = [tip~1]` — packs just
//!     the last commit's delta, the steady-state fetch cost.
//!
//! Run with `cargo bench --bench pack`. Requires `git` on PATH (same
//! contract as the integration tests).

use artifacts::native_pack::generate_pack;
use criterion::{criterion_group, criterion_main, Criterion};
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

/// Number of commits in the synthetic history. Large enough that the
/// full-clone walk does real work, small enough that setup stays fast.
const HISTORY_DEPTH: usize = 200;

/// Run a git plumbing command against `git_dir`, returning trimmed
/// stdout. Panics on failure — a bench that can't build its fixture
/// has nothing meaningful to measure.
fn git(git_dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("git stdout utf8")
        .trim()
        .to_owned()
}

/// Write `content` as a loose blob via `hash-object -w --stdin`,
/// returning its OID.
fn write_blob(git_dir: &Path, content: &[u8]) -> String {
    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(["hash-object", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn hash-object");
    child
        .stdin
        .as_mut()
        .expect("hash-object stdin")
        .write_all(content)
        .expect("write blob");
    let out = child.wait_with_output().expect("hash-object wait");
    String::from_utf8(out.stdout)
        .expect("blob oid utf8")
        .trim()
        .to_owned()
}

/// Build a `tree` with a single `file.txt` entry pointing at `blob`.
fn write_tree(git_dir: &Path, blob: &str) -> String {
    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(["mktree"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mktree");
    child
        .stdin
        .as_mut()
        .expect("mktree stdin")
        .write_all(format!("100644 blob {blob}\tfile.txt\n").as_bytes())
        .expect("write tree entry");
    let out = child.wait_with_output().expect("mktree wait");
    String::from_utf8(out.stdout)
        .expect("tree oid utf8")
        .trim()
        .to_owned()
}

/// Build a bare repo with a linear history `HISTORY_DEPTH` commits
/// deep, each commit changing the single tracked file. Returns the
/// git dir and the OIDs of the tip and its parent (for the
/// incremental-fetch scenario).
fn build_history(git_dir: &Path) -> (String, String) {
    Command::new("git")
        .args(["init", "--quiet", "--bare"])
        .arg(git_dir)
        .status()
        .expect("git init");

    let mut parent: Option<String> = None;
    let mut prev_tip = String::new();
    for i in 0..HISTORY_DEPTH {
        let blob = write_blob(git_dir, format!("revision {i}\n").as_bytes());
        let tree = write_tree(git_dir, &blob);
        let mut args = vec![
            "commit-tree".to_owned(),
            tree,
            "-m".to_owned(),
            format!("c{i}"),
        ];
        if let Some(p) = &parent {
            args.push("-p".to_owned());
            args.push(p.clone());
        }
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let commit = {
            let out = Command::new("git")
                .arg("--git-dir")
                .arg(git_dir)
                .args(&arg_refs)
                .env("GIT_AUTHOR_NAME", "bench")
                .env("GIT_AUTHOR_EMAIL", "bench@example.invalid")
                .env("GIT_COMMITTER_NAME", "bench")
                .env("GIT_COMMITTER_EMAIL", "bench@example.invalid")
                .output()
                .expect("spawn commit-tree");
            assert!(out.status.success(), "commit-tree failed");
            String::from_utf8(out.stdout)
                .expect("commit oid utf8")
                .trim()
                .to_owned()
        };
        prev_tip = parent.take().unwrap_or_default();
        parent = Some(commit);
    }
    let tip = parent.expect("at least one commit");
    git(git_dir, &["update-ref", "refs/heads/main", &tip]);
    (tip, prev_tip)
}

fn bench_generate_pack(c: &mut Criterion) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let git_dir = tmp.path().join("bench.git");
    let (tip, parent) = build_history(&git_dir);

    let wants = vec![tip];
    let mut group = c.benchmark_group("generate_pack");

    group.bench_function("full_clone", |b| {
        b.iter(|| {
            let pack = generate_pack(&git_dir, &wants, &[]).expect("full-clone pack");
            assert!(pack.len() > 32, "non-empty history must pack > 32 bytes");
        });
    });

    let haves = vec![parent];
    group.bench_function("incremental", |b| {
        b.iter(|| {
            generate_pack(&git_dir, &wants, &haves).expect("incremental pack");
        });
    });

    group.finish();
}

criterion_group!(benches, bench_generate_pack);
criterion_main!(benches);
