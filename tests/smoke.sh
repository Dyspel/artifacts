#!/usr/bin/env bash
# Thin shim that delegates to the Rust integration test
# `tests/integration_smoke.rs`. The Rust version is the CI gate (run by
# `.github/workflows/ci.yml`'s build-test job via `cargo test
# --all-targets`); this shim is kept so local-dev habits — `./tests/smoke.sh`
# — keep working.
#
# Pass `--nocapture` to see the per-step println! output and the server's
# stderr log on failure, mirroring the bash version's diagnostic dump.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
exec cargo test --test integration_smoke -- --nocapture "$@"
