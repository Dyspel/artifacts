# Test coverage

## How it's measured

```
cargo tarpaulin --lib --tests --timeout 300 --skip-clean \
  --exclude-files 'benches/*' 'src/bin/*' 'src/main.rs' '.claude/*' \
  --out Stdout
```

`cargo-tarpaulin` (line coverage, ptrace-based). Run it from a clean
tree; `--skip-clean` reuses the existing build.

## The one methodology gotcha

`tests/integration_smoke.rs` drives the server by **spawning the
compiled `artifacts` binary as a child process** (`CARGO_BIN_EXE_*`).
Coverage instrumentation does **not** follow that child, so everything
the server does in response to those requests reads as *uncovered* even
though it ran. `cargo tarpaulin --follow-exec` *would* capture it but
**segfaults** on this workload (ptrace + the many `git` subprocesses).

The fix is `tests/e2e_inprocess.rs` (and the `e2e_variant_*` /
`e2e_shutdown` / `e2e_tls` siblings): they boot `app::serve` **in the
test process** on an ephemeral port and drive it with the real `git`
CLI as a *client* plus blocking HTTP. The git client is a subprocess we
don't care about; the server request handling runs in-process, so it
counts. That single change is what moved measured coverage from ~52% to
~90%.

Because `serve()` installs process-global state (the tracing
subscriber and the Prometheus recorder, each init-once), each distinct
server *configuration* needs its own test binary:

| test binary | what it covers in `app::serve` |
|---|---|
| `e2e_inprocess` | full request surface, in-memory webhook arm |
| `e2e_variant_bootstrap` | generated admin token, JWT-from-file, GC-sweep spawn |
| `e2e_shutdown` | SQLite webhook arm + graceful SIGTERM drain |
| `e2e_tls` | TLS (`bind_rustls`) bind + shutdown listener |

`e2e_shutdown`/`e2e_tls` raise `SIGTERM` at their own process — caught
by `serve()`'s own Tokio signal handler, so it drives a *graceful
shutdown* rather than killing the test.

## What's deliberately not covered

A handful of lines are unreachable from a test and are left uncovered
on purpose rather than chased with contrived harnesses:

- **`src/main.rs`** — the CLI parse + `serve()` call. A binary
  entrypoint; exercised end-to-end by `integration_smoke` (out of
  process). Excluded from the denominator above.
- **Dead HTTP-status arms in `webhooks::dispatch_row` /
  `legacy_direct_dispatch`** — with `ureq` 2.x, `send_bytes` returns
  `Err(Status(code,_))` for *every* status ≥ 400, so the `Ok(resp)`
  branches that re-inspect 4xx/5xx are never reached. They're a guard
  against a future client swap.
- **Decompression / corruption guards** in `native_pack::parse`
  (`decompress_zlib` `BufError`/stall) and `object_store`
  (`read_loose_inflated` on a corrupt loose object) — only reachable by
  injecting malformed bytes below an API that validates them
  (`Oid`/zlib), which there's no public way to do.
- **`#[cfg(not(unix))]` fallbacks** (e.g. `secrets::write_key_file_0600`)
  — never compiled on the Linux CI target.
- **Macro-internal lines in `error.rs`** — the `json!{...}` bodies of
  the `IntoResponse` arms execute (the arms are unit-tested) but
  tarpaulin attributes the macro-expanded lines inconsistently.
- **Defensive `unreachable`-style guards** — e.g. `merge.rs`'s
  "control-flow invariant broken" 500, and CAS-conflict races that
  require two writers interleaving on one ref.

## Running the suite

`cargo test` (unit + all integration binaries) and `cargo test --doc`.
Everything passes under the project's `-D warnings` clippy gate
(pedantic + nursery).
