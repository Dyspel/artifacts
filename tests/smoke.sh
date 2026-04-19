#!/usr/bin/env bash
# End-to-end smoke test for the Artifacts prototype.
#
# Starts the server on a random port, then exercises:
#   1. POST /v1/repos                     -> create an empty repo
#   2. git clone                          -> works against the empty repo
#   3. commit + git push                  -> write something real
#   4. POST /v1/repos/:id/forks           -> fork it
#   5. git clone the fork                 -> pulls objects via alternates
#   6. readOnly fork rejects a push
#   7. POST /v1/repos/:id/tokens          -> mints a scoped token
#
# Exits 0 on success. Tears down the server in a trap so the test is
# idempotent.

set -euo pipefail
shopt -s inherit_errexit 2>/dev/null || true

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT=${PORT:-18787}
BIND="127.0.0.1:${PORT}"
BASE_URL="http://${BIND}"
DATA_DIR="$(mktemp -d -t artifacts-smoke.XXXXXX)"
WORK_DIR="$(mktemp -d -t artifacts-smoke-work.XXXXXX)"
ADMIN_TOKEN="smoke-admin-token-$(date +%s)"
SERVER_LOG="${DATA_DIR}/server.log"

cleanup() {
    local ec=$?
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [[ $ec -ne 0 ]]; then
        echo
        echo "=== FAILED (exit $ec) ==="
        echo "--- server log (${SERVER_LOG}) ---"
        cat "$SERVER_LOG" 2>/dev/null || true
        echo "data: $DATA_DIR"
        echo "work: $WORK_DIR"
    else
        rm -rf "$DATA_DIR" "$WORK_DIR"
    fi
    exit $ec
}
trap cleanup EXIT INT TERM

echo "==> building"
cargo build --quiet

echo "==> starting server on $BIND"
ARTIFACTS_ADMIN_TOKEN="$ADMIN_TOKEN" \
    ./target/debug/artifacts serve \
        --data-dir "$DATA_DIR" \
        --bind "$BIND" \
        --public-base-url "$BASE_URL" \
    >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Wait for the server to come up.
for _ in $(seq 1 50); do
    if curl -fsS "$BASE_URL/v1/health" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
curl -fsS "$BASE_URL/v1/health" >/dev/null

auth=(-H "Authorization: Bearer ${ADMIN_TOKEN}")

json() { python3 -c 'import json,sys; print(json.load(sys.stdin)["'"$1"'"])'; }

echo "==> [1] create empty repo"
resp=$(curl -fsS -X POST "${auth[@]}" "$BASE_URL/v1/repos")
echo "    resp: $resp"
repo_id=$(echo "$resp" | json id)
remote_a=$(echo "$resp"  | json remote)
token_a=$(echo "$resp"   | json token)
test -n "$repo_id" && test -n "$remote_a" && test -n "$token_a"

echo "==> [2] clone empty repo"
clone_a="${WORK_DIR}/a"
GIT_TERMINAL_PROMPT=0 git clone --quiet "$remote_a" "$clone_a"

echo "==> [3] commit + push"
pushd "$clone_a" >/dev/null
git config user.email "smoke@artifacts.local"
git config user.name  "Smoke Test"
echo "hello from artifacts" > README.md
mkdir -p src && echo 'fn main(){ println!("hi"); }' > src/main.rs
git add .
git commit --quiet -m "initial commit"
git branch -M main
GIT_TERMINAL_PROMPT=0 git push --quiet origin main
popd >/dev/null

echo "==> [4] fork (writable)"
fork_resp=$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{}' "$BASE_URL/v1/repos/${repo_id}/forks")
echo "    resp: $fork_resp"
fork_id=$(echo "$fork_resp"   | json id)
fork_remote=$(echo "$fork_resp" | json remote)

echo "==> [5] clone fork and verify content"
clone_b="${WORK_DIR}/b"
GIT_TERMINAL_PROMPT=0 git clone --quiet "$fork_remote" "$clone_b"
diff -r "$clone_a" "$clone_b" -x .git
test "$(cat "$clone_b/README.md")" = "hello from artifacts"

# Prove we didn't duplicate object data: the fork's objects dir is empty
# (save for info/alternates and empty pack dir).
fork_git_dir="$DATA_DIR/repos/${fork_id}.git"
test -f "$fork_git_dir/objects/info/alternates"
# objects/ should contain only info/ and pack/ — no loose object fanout dirs.
fork_obj_dirs=$(find "$fork_git_dir/objects" -mindepth 1 -maxdepth 1 -type d | sort)
expected=$(printf "%s/objects/info\n%s/objects/pack" "$fork_git_dir" "$fork_git_dir")
test "$fork_obj_dirs" = "$expected" \
    || { echo "FAIL: fork has extra object dirs:"; echo "$fork_obj_dirs"; exit 1; }
echo "    fork objects dir is empty (alternates only) — zero copy confirmed"

echo "==> [6] readOnly fork rejects push"
ro_resp=$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{"readOnly": true}' "$BASE_URL/v1/repos/${repo_id}/forks")
ro_remote=$(echo "$ro_resp" | json remote)
clone_ro="${WORK_DIR}/ro"
GIT_TERMINAL_PROMPT=0 git clone --quiet "$ro_remote" "$clone_ro"
pushd "$clone_ro" >/dev/null
git config user.email "smoke@artifacts.local"
git config user.name "Smoke Test"
echo "change" >> README.md
git add README.md
git commit --quiet -m "attempt push to readonly"
if GIT_TERMINAL_PROMPT=0 git push --quiet origin main 2>/dev/null; then
    echo "FAIL: push to readOnly fork succeeded"
    exit 1
fi
popd >/dev/null
echo "    push correctly rejected"

echo "==> [7] mint read-only token"
tok_resp=$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{"scope":"read"}' "$BASE_URL/v1/repos/${repo_id}/tokens")
tok_remote=$(echo "$tok_resp" | json remote)
clone_tok="${WORK_DIR}/tok"
GIT_TERMINAL_PROMPT=0 git clone --quiet "$tok_remote" "$clone_tok"
test "$(cat "$clone_tok/README.md")" = "hello from artifacts"

echo
echo "==> all checks passed"
