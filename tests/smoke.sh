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
#   8. POST /v1/repos/:id/commits         -> REST-side commit (no git client),
#                                            with CAS conflict + path validation
#   9. POST /v1/tokens/revoke             -> revoked token no longer clones
#  10. token persists across a server restart (SQLite durability)
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
# Enable the JWT auth path so step 11 can exercise it. The secret is
# shared with the Dyspel backend in real deployments; for the smoke
# test it just needs to match what we sign with below.
JWT_SECRET="smoke-jwt-secret-$(date +%s)"
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

start_server() {
    ARTIFACTS_ADMIN_TOKEN="$ADMIN_TOKEN" \
    ARTIFACTS_JWT_SECRET="$JWT_SECRET" \
        ./target/debug/artifacts serve \
            --data-dir "$DATA_DIR" \
            --bind "$BIND" \
            --public-base-url "$BASE_URL" \
        >>"$SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 50); do
        if curl -fsS "$BASE_URL/v1/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    curl -fsS "$BASE_URL/v1/health" >/dev/null
}

stop_server() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    SERVER_PID=
    # Wait until the port is free before we start a new server on it.
    for _ in $(seq 1 50); do
        if ! curl -fsS "$BASE_URL/v1/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
}

echo "==> starting server on $BIND"
start_server

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

# The next block exercises the REST-side commit endpoint (M5) — the
# headline "agent-first" path: a caller with no git client writes a
# commit via plain JSON, and the resulting state is observable via git.
echo "==> [8] create-then-commit via REST (no git client)"
rest_resp=$(curl -fsS -X POST "${auth[@]}" "$BASE_URL/v1/repos")
rest_id=$(echo "$rest_resp" | json id)
rest_remote=$(echo "$rest_resp" | json remote)

# Commit 1: orphan — seed README + src/a.txt
c1_resp=$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{
      "branch": "main",
      "parent": null,
      "message": "rest-initial",
      "changes": [
        {"op":"write","path":"README.md","content":"# rest-initial\n"},
        {"op":"write","path":"src/a.txt","content":"a"}
      ]
    }' \
    "$BASE_URL/v1/repos/${rest_id}/commits")
c1_sha=$(echo "$c1_resp" | json commit)
test -n "$c1_sha" && [[ ${#c1_sha} -eq 40 ]] \
    || { echo "FAIL: bad c1 sha: $c1_sha"; exit 1; }
echo "    c1 = $c1_sha"

# Commit 2: delete src/a.txt, add src/b.txt, with CAS parent=c1
c2_resp=$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d "{
      \"branch\": \"main\",
      \"parent\": \"${c1_sha}\",
      \"message\": \"rest-delete-and-add\",
      \"changes\": [
        {\"op\":\"delete\",\"path\":\"src/a.txt\"},
        {\"op\":\"write\",\"path\":\"src/b.txt\",\"content\":\"b\"}
      ]
    }" \
    "$BASE_URL/v1/repos/${rest_id}/commits")
c2_sha=$(echo "$c2_resp" | json commit)
test -n "$c2_sha" && [[ ${#c2_sha} -eq 40 ]] \
    || { echo "FAIL: bad c2 sha: $c2_sha"; exit 1; }
echo "    c2 = $c2_sha"

# Commit 3: reuse parent=c1 (stale). Should 409 with ref_conflict.
ec3_file="${WORK_DIR}/c3_body.json"
ec3_code=$(curl -sS -o "$ec3_file" -w '%{http_code}' \
    -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d "{
      \"branch\": \"main\",
      \"parent\": \"${c1_sha}\",
      \"message\": \"stale\",
      \"changes\": [{\"op\":\"write\",\"path\":\"x\",\"content\":\"x\"}]
    }" \
    "$BASE_URL/v1/repos/${rest_id}/commits")
[[ "$ec3_code" == "409" ]] \
    || { echo "FAIL: stale-parent expected 409, got $ec3_code; body:"; cat "$ec3_file"; exit 1; }
ec3_code_field=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["error"]["code"])' < "$ec3_file")
ec3_current=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["error"]["current"])' < "$ec3_file")
[[ "$ec3_code_field" == "ref_conflict" ]] \
    || { echo "FAIL: wanted code ref_conflict, got $ec3_code_field"; exit 1; }
[[ "$ec3_current" == "$c2_sha" ]] \
    || { echo "FAIL: wanted current=$c2_sha, got $ec3_current"; exit 1; }
echo "    stale-parent rejected with 409 ref_conflict, current=$c2_sha"

# Clone and verify we see c2's state: README present, src/a.txt gone,
# src/b.txt present.
rest_clone="${WORK_DIR}/rest"
GIT_TERMINAL_PROMPT=0 git clone --quiet "$rest_remote" "$rest_clone"
[[ -f "$rest_clone/README.md" ]] || { echo "FAIL: README.md missing"; exit 1; }
[[ ! -f "$rest_clone/src/a.txt" ]] || { echo "FAIL: src/a.txt should have been deleted"; exit 1; }
[[ -f "$rest_clone/src/b.txt" ]] || { echo "FAIL: src/b.txt missing"; exit 1; }
[[ "$(cat "$rest_clone/src/b.txt")" == "b" ]] || { echo "FAIL: src/b.txt content wrong"; exit 1; }
echo "    clone shows c2 state: README + src/b.txt, no src/a.txt"

# Bad-request sanity: invalid path should 400, not 500.
bad_code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d "{
      \"branch\": \"main\",
      \"parent\": \"${c2_sha}\",
      \"message\": \"bad path\",
      \"changes\": [{\"op\":\"write\",\"path\":\"../escape\",\"content\":\"x\"}]
    }" \
    "$BASE_URL/v1/repos/${rest_id}/commits")
[[ "$bad_code" == "400" ]] \
    || { echo "FAIL: bad path expected 400, got $bad_code"; exit 1; }
echo "    path validation rejects '..' with 400"

# Token revocation. Mint a read-only token, prove it works for a clone,
# revoke it, prove the clone now fails with auth. Revoke is an admin-only
# endpoint that takes the token in the request body (not the URL, which
# would leak into access logs).
echo "==> [9] revoke a token"
mint_resp=$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{"scope":"read"}' "$BASE_URL/v1/repos/${repo_id}/tokens")
revokable_token=$(echo "$mint_resp" | json token)
revokable_remote=$(echo "$mint_resp" | json remote)
# Clone with the token — should succeed.
rm -rf "${WORK_DIR}/rev" && GIT_TERMINAL_PROMPT=0 git clone --quiet "$revokable_remote" "${WORK_DIR}/rev"
# Revoke.
rv=$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d "{\"token\":\"${revokable_token}\"}" "$BASE_URL/v1/tokens/revoke" \
    | json revoked)
[[ "$rv" == "True" ]] \
    || { echo "FAIL: revoke response expected True, got $rv"; exit 1; }
# Clone again with the same URL — should fail with auth.
rm -rf "${WORK_DIR}/rev2"
if GIT_TERMINAL_PROMPT=0 git clone --quiet "$revokable_remote" "${WORK_DIR}/rev2" 2>/dev/null; then
    echo "FAIL: clone with revoked token unexpectedly succeeded"
    exit 1
fi
# Double-revoke should be idempotent (returns revoked=False).
rv2=$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d "{\"token\":\"${revokable_token}\"}" "$BASE_URL/v1/tokens/revoke" \
    | json revoked)
[[ "$rv2" == "False" ]] \
    || { echo "FAIL: second revoke expected False, got $rv2"; exit 1; }
echo "    revoked token rejected on clone; double-revoke is a no-op"

# Token persistence across restart. Mint a token, stop the server, start
# it again on the same data dir (same tokens.db), and verify the token
# still clones. This is the entire reason to back tokens with SQLite
# instead of a HashMap.
echo "==> [10] tokens persist across server restart"
persist_resp=$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{"scope":"read"}' "$BASE_URL/v1/repos/${repo_id}/tokens")
persist_remote=$(echo "$persist_resp" | json remote)
stop_server
echo "    server stopped; data_dir=$DATA_DIR"
start_server
echo "    server restarted; cloning with pre-restart token..."
rm -rf "${WORK_DIR}/persist"
GIT_TERMINAL_PROMPT=0 git clone --quiet "$persist_remote" "${WORK_DIR}/persist"
[[ -f "${WORK_DIR}/persist/README.md" ]] \
    || { echo "FAIL: restart-then-clone missing README.md"; exit 1; }
echo "    pre-restart token still authorizes after restart"

# JWT + ownership (the Dyspel integration shape). A Dyspel-signed JWT
# with a `userId` claim becomes a `Principal::User { subject }`. The
# user can create and touch their own repos; cross-user access 403s.
echo "==> [11] JWT auth + per-user repo ownership"

# Self-contained HS256 signer — no extra deps, python3 is already in use.
sign_jwt() {
    local secret="$1" user="$2"
    python3 - "$secret" "$user" <<'PY'
import base64, hmac, hashlib, json, sys, time
secret, user = sys.argv[1], sys.argv[2]
b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
header  = b64(json.dumps({"alg":"HS256","typ":"JWT"}, separators=(",",":")).encode())
payload = b64(json.dumps({"userId":user,"exp":int(time.time())+3600}, separators=(",",":")).encode())
signing_input = f"{header}.{payload}".encode()
sig = b64(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
print(f"{header}.{payload}.{sig}")
PY
}

alice_jwt="$(sign_jwt "$JWT_SECRET" alice)"
bob_jwt="$(sign_jwt   "$JWT_SECRET" bob)"

alice_auth=(-H "Authorization: Bearer ${alice_jwt}")
bob_auth=(-H "Authorization: Bearer ${bob_jwt}")

# Alice creates a repo via her JWT.
alice_resp=$(curl -fsS -X POST "${alice_auth[@]}" "$BASE_URL/v1/repos")
alice_repo=$(echo "$alice_resp" | json id)
echo "    alice created repo $alice_repo"

# Bob tries to mint a token for alice's repo — should 403.
bob_mint_code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST "${bob_auth[@]}" -H 'Content-Type: application/json' \
    -d '{"scope":"read"}' "$BASE_URL/v1/repos/${alice_repo}/tokens")
[[ "$bob_mint_code" == "403" ]] \
    || { echo "FAIL: bob mint-token on alice's repo expected 403, got $bob_mint_code"; exit 1; }
echo "    bob → alice's repo/tokens → 403 (ownership enforced)"

# Bob tries to delete alice's repo — should 403.
bob_del_code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X DELETE "${bob_auth[@]}" "$BASE_URL/v1/repos/${alice_repo}")
[[ "$bob_del_code" == "403" ]] \
    || { echo "FAIL: bob delete on alice's repo expected 403, got $bob_del_code"; exit 1; }
echo "    bob → DELETE alice's repo → 403"

# Alice mints her own token — should 200.
alice_tok_code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST "${alice_auth[@]}" -H 'Content-Type: application/json' \
    -d '{"scope":"read"}' "$BASE_URL/v1/repos/${alice_repo}/tokens")
[[ "$alice_tok_code" == "200" ]] \
    || { echo "FAIL: alice mint-token on her own repo expected 200, got $alice_tok_code"; exit 1; }
echo "    alice → her own repo/tokens → 200"

# Admin still works on alice's repo (bypasses ownership).
admin_tok_code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{"scope":"read"}' "$BASE_URL/v1/repos/${alice_repo}/tokens")
[[ "$admin_tok_code" == "200" ]] \
    || { echo "FAIL: admin mint on alice's repo expected 200, got $admin_tok_code"; exit 1; }
echo "    admin → alice's repo/tokens → 200 (bypasses ownership)"

# Non-admin JWT cannot revoke (admin-only endpoint).
alice_revoke_code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST "${alice_auth[@]}" -H 'Content-Type: application/json' \
    -d '{"token":"whatever"}' "$BASE_URL/v1/tokens/revoke")
[[ "$alice_revoke_code" == "403" ]] \
    || { echo "FAIL: alice revoke expected 403 (admin-only), got $alice_revoke_code"; exit 1; }
echo "    non-admin JWT → /v1/tokens/revoke → 403 (admin-only)"

echo
echo "==> all checks passed"
