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
    # Tight quota + blob cap so the steps below that exercise them
    # don't have to burn through production-sized limits.
    # `ARTIFACTS_SHUTDOWN_DRAIN_DELAY_SECS=0` opts the smoke harness
    # out of the production-default 5s pre-drain hold-off so each
    # stop/start cycle stays fast. The drain-flip itself is exercised
    # directly by the dedicated step at the end of this file.
    ARTIFACTS_ADMIN_TOKEN="$ADMIN_TOKEN" \
    ARTIFACTS_JWT_SECRET="$JWT_SECRET" \
    ARTIFACTS_MAX_REPOS_PER_USER=3 \
    ARTIFACTS_MAX_COMMIT_BLOB_BYTES=1024 \
    ARTIFACTS_SHUTDOWN_DRAIN_DELAY_SECS=0 \
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

# Per-user repo-count quota. Server was started with limit=3; alice
# already owns one (from step 11). Create two more, then expect 429
# quota_exceeded on the fourth.
echo "==> [12] per-user repo-count quota"
for i in 2 3; do
    code=$(curl -sS -o /dev/null -w '%{http_code}' \
        -X POST "${alice_auth[@]}" "$BASE_URL/v1/repos")
    [[ "$code" == "200" ]] \
        || { echo "FAIL: alice create #$i expected 200, got $code"; exit 1; }
done
quota_body="${WORK_DIR}/quota_body.json"
quota_code=$(curl -sS -o "$quota_body" -w '%{http_code}' \
    -X POST "${alice_auth[@]}" "$BASE_URL/v1/repos")
[[ "$quota_code" == "429" ]] \
    || { echo "FAIL: alice create over-quota expected 429, got $quota_code"; cat "$quota_body"; exit 1; }
quota_code_field=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["error"]["code"])' < "$quota_body")
[[ "$quota_code_field" == "quota_exceeded" ]] \
    || { echo "FAIL: wanted code quota_exceeded, got $quota_code_field"; exit 1; }
echo "    alice 4th repo → 429 quota_exceeded (limit: 3)"

# Different user: bob has 0 repos, should succeed and consume 1 of his 3.
# Capture the id too — step 13 commits to this repo.
bob_create_body="${WORK_DIR}/bob_create.json"
bob_create_code=$(curl -sS -o "$bob_create_body" -w '%{http_code}' \
    -X POST "${bob_auth[@]}" "$BASE_URL/v1/repos")
[[ "$bob_create_code" == "200" ]] \
    || { echo "FAIL: bob's first repo expected 200 (separate quota), got $bob_create_code"; exit 1; }
bob_repo=$(json id < "$bob_create_body")
echo "    bob first repo → 200 (quotas are per-user); id=$bob_repo"

# Admin bypasses quota — creating via admin still works even after
# alice is over limit and bob has burned some of his.
admin_unlimited=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST "${auth[@]}" "$BASE_URL/v1/repos")
[[ "$admin_unlimited" == "200" ]] \
    || { echo "FAIL: admin create should bypass quota, got $admin_unlimited"; exit 1; }
echo "    admin create → 200 (bypasses quota)"

# Per-blob size cap. Server was started with max_commit_blob_bytes=1024.
# Reuse the repo bob created above; commit a blob larger than the cap.
echo "==> [13] per-blob size cap on REST commits"
# Build a 2KB blob in python (over the 1KB cap).
big_content=$(python3 -c 'print("x" * 2000)')
big_body=$(python3 -c 'import json,sys; print(json.dumps({
    "branch":"main","parent":None,"message":"too big",
    "changes":[{"op":"write","path":"big.txt","content":"'"$big_content"'"}]
}))')
blob_body="${WORK_DIR}/blob_body.json"
blob_code=$(curl -sS -o "$blob_body" -w '%{http_code}' \
    -X POST "${bob_auth[@]}" -H 'Content-Type: application/json' \
    -d "$big_body" "$BASE_URL/v1/repos/${bob_repo}/commits")
[[ "$blob_code" == "400" ]] \
    || { echo "FAIL: oversized blob expected 400, got $blob_code"; cat "$blob_body"; exit 1; }
grep -q 'over limit of' "$blob_body" \
    || { echo "FAIL: error body should mention the blob-size limit; got:"; cat "$blob_body"; exit 1; }
echo "    2 KB blob with 1 KB cap → 400 (bad_request)"

# Under-cap commit works on the same repo.
small_body='{"branch":"main","parent":null,"message":"ok","changes":[{"op":"write","path":"ok.txt","content":"small"}]}'
ok_code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST "${bob_auth[@]}" -H 'Content-Type: application/json' \
    -d "$small_body" "$BASE_URL/v1/repos/${bob_repo}/commits")
[[ "$ok_code" == "200" ]] \
    || { echo "FAIL: under-cap commit expected 200, got $ok_code"; exit 1; }
echo "    under-cap commit on same repo → 200"

# Observability surface: /metrics is reachable without auth, emits
# Prometheus text format, and contains rows generated by the requests
# above. X-Request-Id round-trips on every response.
echo "==> [14] observability: /metrics + X-Request-Id"
metrics_body="${WORK_DIR}/metrics_body.txt"
curl -fsS -o "$metrics_body" "$BASE_URL/metrics"
grep -q '^# TYPE artifacts_requests_total counter' "$metrics_body" \
    || { echo "FAIL: /metrics missing artifacts_requests_total TYPE line"; exit 1; }
grep -q '^artifacts_build_info' "$metrics_body" \
    || { echo "FAIL: /metrics missing build_info"; exit 1; }
# Path label must use route template (':id') not concrete IDs. This is
# how we keep cardinality bounded — a regression here would balloon the
# label space as repos are created.
grep -q '/v1/repos/:id/tokens' "$metrics_body" \
    || { echo "FAIL: /metrics path label not using route template"; exit 1; }
echo "    /metrics emits Prometheus format with route-template path labels"

# Rate-limit and quota counters should have been bumped by earlier
# steps (alice's 4th-repo 429 quota_exceeded).
grep -q '^artifacts_quota_exceeded_total' "$metrics_body" \
    || { echo "FAIL: /metrics missing quota_exceeded counter"; exit 1; }
echo "    quota_exceeded counter observed in /metrics"

# repos-total gauge: at this point the smoke has created several repos
# (root + forks + per-user repos) so the gauge must be non-zero. The
# gauge is populated synchronously at startup and refreshed every 60s,
# so it tracks creates within a minute — this scrape is well within
# that window.
repos_gauge=$(grep '^artifacts_repos_total ' "$metrics_body" \
    | awk '{print $2}' || true)
[[ -n "$repos_gauge" ]] \
    || { echo "FAIL: /metrics missing artifacts_repos_total gauge"; exit 1; }
# Compare as integers — Prometheus emits "5" for an integer-valued gauge.
[[ "${repos_gauge%.*}" -ge 1 ]] \
    || { echo "FAIL: artifacts_repos_total=$repos_gauge, expected ≥ 1 (smoke creates repos)"; exit 1; }
echo "    artifacts_repos_total gauge → $repos_gauge"

# audit-events-stored gauge: every mutating call earlier in this run
# emitted a record into the audit log, so the gauge must be ≥ 1. The
# distinction vs the `artifacts_audit_events_total{event}` counter
# matters — the gauge is rows-in-table (post-prune), the counter is
# lifetime emissions.
audit_stored=$(grep '^artifacts_audit_events_stored_total ' "$metrics_body" \
    | awk '{print $2}' || true)
[[ -n "$audit_stored" ]] \
    || { echo "FAIL: /metrics missing artifacts_audit_events_stored_total gauge"; exit 1; }
[[ "${audit_stored%.*}" -ge 1 ]] \
    || { echo "FAIL: artifacts_audit_events_stored_total=$audit_stored, expected ≥ 1"; exit 1; }
echo "    artifacts_audit_events_stored_total gauge → $audit_stored"

# Audit-event counter should be incremented per event kind. Counters
# reset at the step-10 restart, so we can only assert on kinds that
# fire AFTER the restart — repo.create and token.mint both fire
# during step 11's JWT/ownership exercise. (repo.fork and
# token.revoke fire pre-restart only in this smoke run.)
for kind in repo.create token.mint; do
    grep -q "^artifacts_audit_events_total{event=\"${kind}\"}" "$metrics_body" \
        || { echo "FAIL: /metrics missing artifacts_audit_events_total{event=\"${kind}\"}"; exit 1; }
done
echo "    audit-event counter has labeled series for repo.create + token.mint"

# Readiness probe — exercises both SQLite stores; must report all
# components ok on a healthy server.
ready_body=$(curl -fsS "$BASE_URL/v1/health/ready")
ready_ok=$(echo "$ready_body" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ok"])')
[[ "$ready_ok" == "True" ]] || { echo "FAIL: /v1/health/ready not ok: $ready_body"; exit 1; }
ready_components=$(echo "$ready_body" | python3 -c 'import json,sys; c=json.load(sys.stdin)["components"]; print(",".join(f"{k}={v}" for k,v in sorted(c.items())))')
echo "    /v1/health/ready → ok=true, components: $ready_components"

# X-Request-Id roundtrip: client-supplied id must be echoed.
echo_code=$(curl -sS -D "${WORK_DIR}/rid_headers.txt" -o /dev/null -w '%{http_code}' \
    -H 'X-Request-Id: smoke-trace-xyz' "$BASE_URL/v1/health")
[[ "$echo_code" == "200" ]] || { echo "FAIL: health probe code $echo_code"; exit 1; }
grep -qi '^x-request-id: smoke-trace-xyz' "${WORK_DIR}/rid_headers.txt" \
    || { echo "FAIL: server did not echo client X-Request-Id:"; cat "${WORK_DIR}/rid_headers.txt"; exit 1; }
echo "    X-Request-Id: smoke-trace-xyz echoed on response"

# No client id → server generates a 32-hex UUID.
curl -sS -D "${WORK_DIR}/rid_gen.txt" -o /dev/null "$BASE_URL/v1/health"
gen_id=$(awk 'tolower($1)=="x-request-id:"{print $2}' "${WORK_DIR}/rid_gen.txt" | tr -d '\r\n')
[[ ${#gen_id} -eq 32 ]] \
    || { echo "FAIL: generated X-Request-Id is not 32 chars (got $gen_id len=${#gen_id})"; exit 1; }
echo "    generated X-Request-Id observed ($gen_id)"

# POST /v1/repos/:id/merge — fast-forward, three-way, and conflict paths.
#
# The REST commits endpoint treats `parent` as both the new commit's parent
# and the CAS expectation on the target branch's current head, which means
# it can't create a branch off a non-orphan parent in one call. We use
# smart-HTTP (git push) to set up the feature/side/conflict-* branches
# instead — exactly how a real git client would.
echo "==> [15] merge: fast-forward, three-way clean, three-way conflict"
merge_resp=$(curl -fsS -X POST "${auth[@]}" "$BASE_URL/v1/repos")
merge_id=$(echo "$merge_resp" | json id)
merge_remote=$(echo "$merge_resp" | json remote)

# c1 on main: seed README + a.txt (this is the merge base for every later step).
m_c1=$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{
      "branch": "main",
      "parent": null,
      "message": "base",
      "changes": [
        {"op":"write","path":"README.md","content":"# base\n"},
        {"op":"write","path":"a.txt","content":"one\n"}
      ]
    }' \
    "$BASE_URL/v1/repos/${merge_id}/commits" | json commit)

# Clone and use the working copy as a branch-push source. `GIT_*` env vars
# pin identity so `git commit` doesn't fail on an empty user.name config.
merge_work="${WORK_DIR}/merge_work"
rm -rf "$merge_work"
GIT_TERMINAL_PROMPT=0 git clone --quiet "$merge_remote" "$merge_work"
export GIT_AUTHOR_NAME="smoke" GIT_AUTHOR_EMAIL="smoke@artifacts.local"
export GIT_COMMITTER_NAME="smoke" GIT_COMMITTER_EMAIL="smoke@artifacts.local"

push_branch() {
    local branch="$1" path="$2" content="$3"
    git -C "$merge_work" checkout -q -B "$branch" "$m_c1"
    printf '%s' "$content" > "$merge_work/$path"
    git -C "$merge_work" add "$path"
    git -C "$merge_work" commit -q -m "$branch: $path"
    git -C "$merge_work" push -q origin "$branch" >/dev/null 2>&1
    git -C "$merge_work" rev-parse HEAD
}

# Fast-forward: "feature" adds b.txt on top of c1. Merging feature → main
# advances main to feature's tip without a merge commit.
ff_c=$(push_branch feature b.txt b)
ff_resp=$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{"sourceBranch":"feature","targetBranch":"main"}' \
    "$BASE_URL/v1/repos/${merge_id}/merge")
ff_head=$(echo "$ff_resp" | json commit)
ff_flag=$(echo "$ff_resp" | json fastForward)
[[ "$ff_head" == "$ff_c" ]] \
    || { echo "FAIL: FF merge expected head=$ff_c, got $ff_head"; exit 1; }
[[ "$ff_flag" == "True" ]] \
    || { echo "FAIL: FF merge expected fastForward=True, got $ff_flag"; exit 1; }
echo "    fast-forward merge advances main to feature head ($ff_c)"

# Three-way clean: advance main with a new commit that doesn't touch c.txt;
# create "side" off ff_c (the current main) that adds c.txt; merge side →
# main. This forces divergence without conflict.
git -C "$merge_work" checkout -q main
git -C "$merge_work" pull -q --ff-only origin main
printf 'd' > "$merge_work/d.txt"
git -C "$merge_work" add d.txt
git -C "$merge_work" commit -q -m "main: add d"
m_c2=$(git -C "$merge_work" rev-parse HEAD)
git -C "$merge_work" push -q origin main >/dev/null 2>&1

side_c=$(push_branch side c.txt c)

tw_resp=$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{"sourceBranch":"side","targetBranch":"main","message":"merge side"}' \
    "$BASE_URL/v1/repos/${merge_id}/merge")
tw_head=$(echo "$tw_resp" | json commit)
tw_flag=$(echo "$tw_resp" | json fastForward)
[[ "$tw_flag" == "False" ]] \
    || { echo "FAIL: 3-way merge expected fastForward=False, got $tw_flag"; exit 1; }
[[ "$tw_head" != "$m_c2" && "$tw_head" != "$side_c" ]] \
    || { echo "FAIL: 3-way merge head should be new commit; got $tw_head"; exit 1; }
tw_clone="${WORK_DIR}/merge_tw"
rm -rf "$tw_clone"
GIT_TERMINAL_PROMPT=0 git clone --quiet "$merge_remote" "$tw_clone"
parents=$(git -C "$tw_clone" rev-list --parents -n 1 HEAD | awk '{$1=""; print substr($0,2)}')
[[ "$parents" == "${m_c2} ${side_c}" ]] \
    || { echo "FAIL: merge commit parents expected '$m_c2 $side_c', got '$parents'"; exit 1; }
[[ -f "$tw_clone/c.txt" && -f "$tw_clone/d.txt" ]] \
    || { echo "FAIL: merge tree missing c.txt or d.txt"; exit 1; }
echo "    three-way clean merge produces commit with two parents + unified tree"

# Three-way conflict: both sides edit a.txt differently on top of c1.
push_branch conflict-left  a.txt $'left\n'  >/dev/null
push_branch conflict-right a.txt $'right\n' >/dev/null

cf_file="${WORK_DIR}/merge_conflict.json"
cf_code=$(curl -sS -o "$cf_file" -w '%{http_code}' \
    -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{"sourceBranch":"conflict-right","targetBranch":"conflict-left","message":"should conflict"}' \
    "$BASE_URL/v1/repos/${merge_id}/merge")
[[ "$cf_code" == "409" ]] \
    || { echo "FAIL: conflicting merge expected 409, got $cf_code; body:"; cat "$cf_file"; exit 1; }
cf_err_code=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["error"]["code"])' < "$cf_file")
[[ "$cf_err_code" == "merge_conflict" ]] \
    || { echo "FAIL: expected code=merge_conflict, got $cf_err_code"; exit 1; }
cf_paths=$(python3 -c 'import json,sys; print(",".join(json.load(sys.stdin)["error"]["conflicts"]))' < "$cf_file")
[[ "$cf_paths" == "a.txt" ]] \
    || { echo "FAIL: expected conflicts=[a.txt], got [$cf_paths]"; exit 1; }
echo "    conflicting merge reports 409 merge_conflict with path=a.txt"

# ff-only strategy refuses a non-FF. Use the already-diverged conflict-left
# vs conflict-right: no FF exists in either direction. Should 400.
ffo_code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{"sourceBranch":"conflict-right","targetBranch":"conflict-left","strategy":"ff-only"}' \
    "$BASE_URL/v1/repos/${merge_id}/merge")
[[ "$ffo_code" == "400" ]] \
    || { echo "FAIL: ff-only on diverged expected 400, got $ffo_code"; exit 1; }
echo "    ff-only refuses diverged branches with 400"

# Admin inspection endpoints. Admin sees every repo; JWT users are 403.
# The source_id field is populated for forks (from reading the
# alternates file) and absent for roots.
# User-scoped repo listing. The new GET /v1/repos endpoint scopes by who's
# asking: admin sees everything, user JWTs see only their own repos.
echo "==> [16] user-scoped repo listing (GET /v1/repos)"
# Alice has repos from earlier ownership tests; pull her list via her JWT.
alice_list="${WORK_DIR}/alice_list.json"
curl -fsS "${alice_auth[@]}" "$BASE_URL/v1/repos" -o "$alice_list"
alice_ids=$(python3 -c 'import json,sys; print(" ".join(r["id"] for r in json.load(sys.stdin)))' < "$alice_list")
# Must contain her repo from step 11 (alice created repo `alice_repo`).
echo "$alice_ids" | grep -q "$alice_repo" \
    || { echo "FAIL: alice's list missing $alice_repo; got: $alice_ids"; exit 1; }
# Must NOT contain bob's repo from step 12 (cross-user isolation).
echo "$alice_ids" | grep -qv "$bob_repo" \
    || { echo "FAIL: alice's list leaked bob's repo $bob_repo"; exit 1; }
echo "    alice → GET /v1/repos → her repos only, bob's absent"

# Admin sees all repos including ones alice doesn't own.
admin_repos_list="${WORK_DIR}/admin_repos_list.json"
curl -fsS "${auth[@]}" "$BASE_URL/v1/repos" -o "$admin_repos_list"
admin_count=$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' < "$admin_repos_list")
alice_count=$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' < "$alice_list")
[[ "$admin_count" -gt "$alice_count" ]] \
    || { echo "FAIL: admin count ($admin_count) should exceed alice's ($alice_count)"; exit 1; }
echo "    admin → GET /v1/repos → $admin_count repos (alice sees $alice_count)"

# Read endpoints: per-repo detail + git plumbing (commits, refs, tree,
# blob, diff, notes). All owner-scoped — admin token is fine here and
# keeps the setup short. Uses `rest_id` which already has the REST-side
# commits `c1_sha` → `c2_sha` from section [8].
echo "==> [17] per-repo read endpoints (GET /v1/repos/:id/{detail,commits,refs,tree,blob,diff,notes})"

# Detail — should echo the owner (null for admin-created), created_at,
# HEAD sha, list the main branch ref, and now report commitCount +
# forkCount (Phase 3a). `rest_id` has c1 + c2 from section [8], so
# commitCount must be ≥ 2. No forks of rest_id, so forkCount = 0.
det="${WORK_DIR}/read_detail.json"
curl -fsS "${auth[@]}" "$BASE_URL/v1/repos/${rest_id}" -o "$det"
det_id=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' < "$det")
det_head=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("headSha",""))' < "$det")
det_ref_count=$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)["refs"]))' < "$det")
det_commit_count=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["commitCount"])' < "$det")
det_fork_count=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["forkCount"])' < "$det")
[[ "$det_id" == "$rest_id" ]] || { echo "FAIL: detail id mismatch: $det_id vs $rest_id"; exit 1; }
[[ "$det_head" == "$c2_sha" ]] || { echo "FAIL: detail headSha=$det_head, expected $c2_sha"; exit 1; }
[[ "$det_ref_count" -ge 1 ]] || { echo "FAIL: detail refs count=$det_ref_count"; exit 1; }
[[ "$det_commit_count" -ge 2 ]] || { echo "FAIL: detail commitCount=$det_commit_count, expected ≥ 2"; exit 1; }
[[ "$det_fork_count" == "0" ]] || { echo "FAIL: detail forkCount=$det_fork_count, expected 0 (no forks of rest_id)"; exit 1; }
echo "    detail → id=$det_id head=$det_head refs=$det_ref_count commits=$det_commit_count forks=$det_fork_count"

# Fork-count sanity: repo_id (from section [1]) has a writable fork + a
# read-only fork from sections [4] and [6]. forkCount should be ≥ 2.
# Verified only on a root repo so alternates-scanning picks up both.
root_det="${WORK_DIR}/read_detail_root.json"
curl -fsS "${auth[@]}" "$BASE_URL/v1/repos/${repo_id}" -o "$root_det"
root_fork_count=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["forkCount"])' < "$root_det")
[[ "$root_fork_count" -ge 2 ]] \
    || { echo "FAIL: root forkCount=$root_fork_count, expected ≥ 2"; exit 1; }
echo "    detail on root repo → forkCount=$root_fork_count (two forks from earlier steps)"

# Commits — returns c1 and c2 (orphan + delete+add). Most-recent first.
commits_body="${WORK_DIR}/read_commits.json"
curl -fsS "${auth[@]}" "$BASE_URL/v1/repos/${rest_id}/commits" -o "$commits_body"
commits_count=$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' < "$commits_body")
first_sha=$(python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["sha"])' < "$commits_body")
[[ "$commits_count" -ge 2 ]] || { echo "FAIL: commits count=$commits_count, expected ≥ 2"; exit 1; }
[[ "$first_sha" == "$c2_sha" ]] || { echo "FAIL: newest commit sha=$first_sha, expected $c2_sha"; exit 1; }
# Parents field is a list — c2 has c1 as parent; c1 has no parents (orphan).
c2_parents=$(python3 -c 'import json,sys; print(",".join(json.load(sys.stdin)[0]["parents"]))' < "$commits_body")
[[ "$c2_parents" == "$c1_sha" ]] || { echo "FAIL: c2 parents=$c2_parents, expected $c1_sha"; exit 1; }
echo "    commits → $commits_count entries, newest=$first_sha, parent chain intact"

# Refs — contains refs/heads/main.
refs_body="${WORK_DIR}/read_refs.json"
curl -fsS "${auth[@]}" "$BASE_URL/v1/repos/${rest_id}/refs" -o "$refs_body"
main_sha=$(python3 -c 'import json,sys; refs=json.load(sys.stdin); print(next(r["sha"] for r in refs if r["name"]=="refs/heads/main"))' < "$refs_body")
[[ "$main_sha" == "$c2_sha" ]] || { echo "FAIL: refs main=$main_sha, expected $c2_sha"; exit 1; }
echo "    refs → refs/heads/main → $main_sha"

# Tree — c2 has README.md + src/ + src/b.txt, src/a.txt deleted.
tree_body="${WORK_DIR}/read_tree.json"
curl -fsS "${auth[@]}" "$BASE_URL/v1/repos/${rest_id}/tree" -o "$tree_body"
tree_has_readme=$(python3 -c 'import json,sys; print(int(any(e["path"]=="README.md" and e["type"]=="file" for e in json.load(sys.stdin))))' < "$tree_body")
tree_has_src_b=$(python3 -c 'import json,sys; print(int(any(e["path"]=="src/b.txt" and e["type"]=="file" for e in json.load(sys.stdin))))' < "$tree_body")
tree_has_src_a=$(python3 -c 'import json,sys; print(int(any(e["path"]=="src/a.txt" for e in json.load(sys.stdin))))' < "$tree_body")
tree_has_src_dir=$(python3 -c 'import json,sys; print(int(any(e["path"]=="src" and e["type"]=="dir" for e in json.load(sys.stdin))))' < "$tree_body")
[[ "$tree_has_readme" == "1" ]] || { echo "FAIL: tree missing README.md"; cat "$tree_body"; exit 1; }
[[ "$tree_has_src_b" == "1" ]] || { echo "FAIL: tree missing src/b.txt"; exit 1; }
[[ "$tree_has_src_dir" == "1" ]] || { echo "FAIL: tree missing src/ directory entry"; exit 1; }
[[ "$tree_has_src_a" == "0" ]] || { echo "FAIL: tree should not have src/a.txt (deleted in c2)"; exit 1; }
echo "    tree → README.md + src/ + src/b.txt present, src/a.txt absent"

# Blob — raw bytes of README.md at HEAD.
blob_body="${WORK_DIR}/read_blob.txt"
blob_code=$(curl -sS -o "$blob_body" -w '%{http_code}' \
    "${auth[@]}" "$BASE_URL/v1/repos/${rest_id}/blob?path=README.md")
[[ "$blob_code" == "200" ]] || { echo "FAIL: blob expected 200, got $blob_code"; exit 1; }
grep -q "rest-initial" "$blob_body" \
    || { echo "FAIL: blob content unexpected:"; cat "$blob_body"; exit 1; }
echo "    blob → README.md → $(wc -c < "$blob_body") bytes"

# Diff — c2 deletes src/a.txt and adds src/b.txt. Expect two files in
# the response with the right statuses.
diff_body="${WORK_DIR}/read_diff.json"
curl -fsS "${auth[@]}" "$BASE_URL/v1/repos/${rest_id}/diff?commit=${c2_sha}" -o "$diff_body"
diff_file_count=$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' < "$diff_body")
diff_has_delete=$(python3 -c 'import json,sys; print(int(any(f["status"]=="deleted" for f in json.load(sys.stdin))))' < "$diff_body")
diff_has_add=$(python3 -c 'import json,sys; print(int(any(f["status"]=="added" for f in json.load(sys.stdin))))' < "$diff_body")
[[ "$diff_file_count" -ge 2 ]] || { echo "FAIL: diff had $diff_file_count files, expected ≥ 2"; exit 1; }
[[ "$diff_has_delete" == "1" ]] || { echo "FAIL: diff missing deleted file"; cat "$diff_body"; exit 1; }
[[ "$diff_has_add" == "1" ]] || { echo "FAIL: diff missing added file"; exit 1; }
echo "    diff → $diff_file_count files, add + delete statuses parsed"

# Notes — create one via git CLI against a clone, then fetch via REST.
# Exercises the `refs/notes/agent` path cc-wasm uses in production.
note_clone="${WORK_DIR}/note_setup"
rm -rf "$note_clone"
GIT_TERMINAL_PROMPT=0 git clone --quiet "$rest_remote" "$note_clone"
git -C "$note_clone" notes --ref=refs/notes/agent add \
    -m '{"version":1,"sessionId":"smoke","model":"test","turns":[]}' "${c2_sha}"
GIT_TERMINAL_PROMPT=0 git -C "$note_clone" push --quiet "$rest_remote" refs/notes/agent

note_body="${WORK_DIR}/read_note.json"
note_code=$(curl -sS -o "$note_body" -w '%{http_code}' \
    "${auth[@]}" "$BASE_URL/v1/repos/${rest_id}/notes?ref=refs/notes/agent&commit=${c2_sha}")
[[ "$note_code" == "200" ]] || { echo "FAIL: note fetch expected 200, got $note_code"; cat "$note_body"; exit 1; }
note_text=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["text"])' < "$note_body")
echo "$note_text" | grep -q '"sessionId":"smoke"' \
    || { echo "FAIL: note text missing sessionId field; got: $note_text"; exit 1; }
echo "    notes → refs/notes/agent payload round-trips"

# Missing note → 404. A commit with no note on the requested ref.
missing_code=$(curl -sS -o /dev/null -w '%{http_code}' \
    "${auth[@]}" "$BASE_URL/v1/repos/${rest_id}/notes?ref=refs/notes/agent&commit=${c1_sha}")
[[ "$missing_code" == "404" ]] || { echo "FAIL: missing note expected 404, got $missing_code"; exit 1; }
echo "    notes → missing note → 404"

# Event bus + SSE: commit via REST and verify a matching `commit` event
# shows up on the /v1/events stream. Open the SSE connection *before*
# the mutation so we don't miss the event (it fires synchronously from
# the handler post-CAS).
echo "==> [18] event bus — SSE stream delivers commit/fork events"
sse_log="${WORK_DIR}/sse.log"
curl -sN "${auth[@]}" "$BASE_URL/v1/events" > "$sse_log" &
sse_pid=$!
# Give the subscribe a moment to register.
sleep 0.5

# Trigger a commit on a fresh repo so only one commit event lands in
# the window we care about.
ev_resp=$(curl -fsS -X POST "${auth[@]}" "$BASE_URL/v1/repos")
ev_id=$(echo "$ev_resp" | json id)
curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{"branch":"main","parent":null,"message":"first","changes":[{"op":"write","path":"README.md","content":"hi"}]}' \
    "$BASE_URL/v1/repos/${ev_id}/commits" > /dev/null

# Fork it too so we pick up a `fork` event.
curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{}' "$BASE_URL/v1/repos/${ev_id}/forks" > /dev/null

# Give events a moment to propagate to the SSE stream before we tear down.
sleep 0.5
kill "$sse_pid" 2>/dev/null || true
wait "$sse_pid" 2>/dev/null || true

grep -q '"kind":"commit"' "$sse_log" \
    || { echo "FAIL: no commit event on SSE stream:"; cat "$sse_log"; exit 1; }
grep -q '"kind":"fork"' "$sse_log" \
    || { echo "FAIL: no fork event on SSE stream:"; cat "$sse_log"; exit 1; }
grep -q "\"repoId\":\"$ev_id\"" "$sse_log" \
    || { echo "FAIL: event missing repoId=$ev_id"; exit 1; }
echo "    SSE stream delivered commit + fork events for repo $ev_id"

# Admin inspection endpoints. Admin sees every repo; JWT users are 403.
# The source_id field is populated for forks (from reading the
# alternates file) and absent for roots.
echo "==> [??] admin inspection endpoints"
admin_list="${WORK_DIR}/admin_list.json"
curl -fsS "${auth[@]}" "$BASE_URL/v1/admin/repos" -o "$admin_list"
# Must be a JSON array; must contain all the repos we created in the
# preceding steps; at least one row must have sourceId (from step 4's
# fork + step 6's ro fork).
count=$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' < "$admin_list")
[[ "$count" -ge 5 ]] \
    || { echo "FAIL: admin_list returned $count rows, expected ≥ 5"; cat "$admin_list"; exit 1; }
with_source=$(python3 -c 'import json,sys; rows=json.load(sys.stdin); print(sum(1 for r in rows if r.get("sourceId")))' < "$admin_list")
[[ "$with_source" -ge 1 ]] \
    || { echo "FAIL: no repos with sourceId — forks should derive one from alternates"; exit 1; }
echo "    admin → list → $count repos, $with_source with sourceId (fork relationships visible)"

# JWT user should get 403 on admin endpoints (non-admin principals).
jwt_code=$(curl -sS -o /dev/null -w '%{http_code}' \
    "${alice_auth[@]}" "$BASE_URL/v1/admin/repos")
[[ "$jwt_code" == "403" ]] \
    || { echo "FAIL: JWT user hitting /v1/admin/repos expected 403, got $jwt_code"; exit 1; }
echo "    JWT user → /v1/admin/repos → 403 (admin-only)"

# Pagination: ?limit=1 returns one row, X-Total-Count header carries
# the unpaginated total. Default behavior (no query) was just exercised
# above and must keep returning the full list, so this only pokes the
# explicit-pagination path.
paginated_headers="${WORK_DIR}/admin_list_paginated.headers"
paginated_body="${WORK_DIR}/admin_list_paginated.json"
curl -fsS "${auth[@]}" -D "$paginated_headers" -o "$paginated_body" \
    "$BASE_URL/v1/admin/repos?limit=1"
paginated_count=$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' < "$paginated_body")
[[ "$paginated_count" == "1" ]] \
    || { echo "FAIL: ?limit=1 returned $paginated_count rows, expected exactly 1"; exit 1; }
total_header=$(grep -i '^x-total-count:' "$paginated_headers" \
    | tr -d '\r' | awk '{print $2}')
[[ "$total_header" == "$count" ]] \
    || { echo "FAIL: X-Total-Count='$total_header' should match unpaginated count='$count'"; exit 1; }
echo "    admin → ?limit=1 → 1 row, X-Total-Count=$total_header"

# Detail endpoint returns refs + size-on-disk.
detail="${WORK_DIR}/admin_detail.json"
curl -fsS "${auth[@]}" "$BASE_URL/v1/admin/repos/${repo_id}" -o "$detail"
ref_count=$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)["refs"]))' < "$detail")
size=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["sizeBytes"])' < "$detail")
[[ "$ref_count" -ge 1 ]] \
    || { echo "FAIL: detail has $ref_count refs, expected ≥ 1 (main branch)"; exit 1; }
[[ "$size" -gt 0 ]] \
    || { echo "FAIL: detail sizeBytes is $size, expected > 0"; exit 1; }
echo "    admin → detail → ${ref_count} refs, ${size} bytes on disk"

echo "==> [??] persistent audit log"
audit_resp="${WORK_DIR}/audit.json"
curl -fsS "${auth[@]}" "$BASE_URL/v1/admin/audit?limit=200" -o "$audit_resp"
audit_count=$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' < "$audit_resp")
[[ "$audit_count" -ge 5 ]] \
    || { echo "FAIL: audit list returned $audit_count rows, expected ≥ 5"; cat "$audit_resp"; exit 1; }
# Earlier steps mint at least one repo.create, repo.fork, token.mint, and
# token.revoke; verify each kind shows up at least once. (repo.delete is
# exercised in a follow-up smoke step here so the kind is covered too.)
for kind in repo.create repo.fork token.mint token.revoke; do
    seen=$(python3 -c "import json,sys; rows=json.load(sys.stdin); print(sum(1 for r in rows if r['event']=='${kind}'))" < "$audit_resp")
    [[ "$seen" -ge 1 ]] \
        || { echo "FAIL: audit log missing event kind '${kind}'"; exit 1; }
done
# Trigger a repo.delete to verify that kind also persists, then re-pull
# the log and check it landed.
del_repo=$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{}' "$BASE_URL/v1/repos" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
curl -fsS -X DELETE "${auth[@]}" "$BASE_URL/v1/repos/${del_repo}" >/dev/null
curl -fsS "${auth[@]}" "$BASE_URL/v1/admin/audit?event=repo.delete&limit=10" -o "${WORK_DIR}/audit_del.json"
del_seen=$(python3 -c "import json,sys; rows=json.load(sys.stdin); print(sum(1 for r in rows if r.get('repoId')=='${del_repo}'))" < "${WORK_DIR}/audit_del.json")
[[ "$del_seen" -ge 1 ]] \
    || { echo "FAIL: just-deleted repo missing from audit log"; cat "${WORK_DIR}/audit_del.json"; exit 1; }
# Filter by event kind round-trips (server-side filtering, not client).
filtered="${WORK_DIR}/audit_filtered.json"
curl -fsS "${auth[@]}" "$BASE_URL/v1/admin/audit?event=repo.create&limit=50" -o "$filtered"
filtered_ok=$(python3 -c "import json,sys; rows=json.load(sys.stdin); print(all(r['event']=='repo.create' for r in rows) and len(rows)>=1)" < "$filtered")
[[ "$filtered_ok" == "True" ]] \
    || { echo "FAIL: ?event=repo.create filter not honored"; cat "$filtered"; exit 1; }
# JWT user should get 403.
jwt_audit_code=$(curl -sS -o /dev/null -w '%{http_code}' \
    "${alice_auth[@]}" "$BASE_URL/v1/admin/audit")
[[ "$jwt_audit_code" == "403" ]] \
    || { echo "FAIL: JWT user GET /v1/admin/audit expected 403, got $jwt_audit_code"; exit 1; }
echo "    audit log → $audit_count rows, all 5 expected kinds present, ?event= filter honored, JWT-user→403"

# Pagination: ?limit=2&offset=1 must skip the very newest row and
# return the next two. Symmetric with /v1/admin/repos pagination.
page0="${WORK_DIR}/audit_page0.json"
page1="${WORK_DIR}/audit_page1.json"
curl -fsS "${auth[@]}" "$BASE_URL/v1/admin/audit?limit=2" -o "$page0"
curl -fsS "${auth[@]}" "$BASE_URL/v1/admin/audit?limit=2&offset=2" -o "$page1"
page0_ids=$(python3 -c 'import json,sys; print(",".join(str(r["id"]) for r in json.load(sys.stdin)))' < "$page0")
page1_ids=$(python3 -c 'import json,sys; print(",".join(str(r["id"]) for r in json.load(sys.stdin)))' < "$page1")
# IDs are monotonic-on-insert; offset=2 must yield strictly older
# IDs than the first page. Disjoint set guarantees no overlap.
disjoint=$(python3 -c "p0=set('$page0_ids'.split(',')); p1=set('$page1_ids'.split(',')); print(p0.isdisjoint(p1))")
[[ "$disjoint" == "True" ]] \
    || { echo "FAIL: audit pages overlapped — page0=$page0_ids page1=$page1_ids"; exit 1; }
echo "    audit ?offset= → page0=$page0_ids, page1=$page1_ids (disjoint)"

# /v1/admin/audit/stats returns the same total via the cheap count.
stats=$(curl -fsS "${auth[@]}" "$BASE_URL/v1/admin/audit/stats")
stats_count=$(echo "$stats" | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])')
[[ "$stats_count" -ge "$audit_count" ]] \
    || { echo "FAIL: /v1/admin/audit/stats count ($stats_count) lower than list count ($audit_count)"; exit 1; }
echo "    /v1/admin/audit/stats → $stats_count rows (≥ list count $audit_count)"

echo "==> [??] admin-token in-process rotation"
# Admin can rotate; old token stops working immediately; new token works.
# Then rotate it back (using the new value) so subsequent steps that rely
# on $ADMIN_TOKEN continue to work — this step is order-independent if
# we leave $ADMIN_TOKEN intact at the end.
rotate_resp="${WORK_DIR}/rotate.json"
curl -fsS -X POST "${auth[@]}" "$BASE_URL/v1/admin/token/rotate" -o "$rotate_resp"
new_admin=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' < "$rotate_resp")
[[ -n "$new_admin" && "$new_admin" != "$ADMIN_TOKEN" ]] \
    || { echo "FAIL: rotate returned empty/identical token"; cat "$rotate_resp"; exit 1; }
old_code=$(curl -sS -o /dev/null -w '%{http_code}' "${auth[@]}" "$BASE_URL/v1/admin/repos")
[[ "$old_code" == "401" ]] \
    || { echo "FAIL: old admin token still works after rotate (got $old_code, want 401)"; exit 1; }
new_auth=(-H "Authorization: Bearer ${new_admin}")
new_code=$(curl -sS -o /dev/null -w '%{http_code}' "${new_auth[@]}" "$BASE_URL/v1/admin/repos")
[[ "$new_code" == "200" ]] \
    || { echo "FAIL: new admin token does not work (got $new_code, want 200)"; exit 1; }
# Rotate back to ADMIN_TOKEN (using the new token's authority) so the
# rest of the script can reuse $auth if needed.
curl -fsS -X POST "${new_auth[@]}" -H 'Content-Type: application/json' \
    "$BASE_URL/v1/admin/token/rotate" >/dev/null
# After this second rotate, $ADMIN_TOKEN is also stale — but we don't
# call any more admin endpoints, so that's fine.
# JWT user can't rotate.
jwt_rotate_code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST \
    "${alice_auth[@]}" "$BASE_URL/v1/admin/token/rotate")
[[ "$jwt_rotate_code" == "403" ]] \
    || { echo "FAIL: JWT user POST /v1/admin/token/rotate expected 403, got $jwt_rotate_code"; exit 1; }
echo "    rotate → old=401, new=200; JWT-user→403"

# Drain-readiness: when SIGTERM fires, /v1/health/ready must flip to
# 503 with `draining: true` BEFORE the listener stops accepting new
# connections, so an orchestrator (k8s/systemd) can pull the process
# out of rotation cleanly. We test this in isolation against a fresh
# server that opts in to a small explicit drain delay (the rest of
# the smoke runs with delay=0 for iteration speed).
echo "==> [??] graceful shutdown — readiness probe drains before listener"
stop_server
DRAIN_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
DRAIN_BIND="127.0.0.1:${DRAIN_PORT}"
DRAIN_BASE="http://${DRAIN_BIND}"
ARTIFACTS_ADMIN_TOKEN="$ADMIN_TOKEN" \
ARTIFACTS_JWT_SECRET="$JWT_SECRET" \
ARTIFACTS_SHUTDOWN_DRAIN_DELAY_SECS=2 \
    ./target/debug/artifacts serve \
        --data-dir "$DATA_DIR" \
        --bind "$DRAIN_BIND" \
        --public-base-url "$DRAIN_BASE" \
    >>"$SERVER_LOG" 2>&1 &
DRAIN_PID=$!
# Wait until the new server is up.
for _ in $(seq 1 50); do
    if curl -fsS "$DRAIN_BASE/v1/health" >/dev/null 2>&1; then break; fi
    sleep 0.1
done
# Pre-flight: readiness must be 200 + ok=true before we touch anything.
pre_status=$(curl -sS -o /dev/null -w '%{http_code}' "$DRAIN_BASE/v1/health/ready")
[[ "$pre_status" == "200" ]] \
    || { echo "FAIL: pre-shutdown readiness expected 200, got $pre_status"; kill "$DRAIN_PID" 2>/dev/null; wait "$DRAIN_PID" 2>/dev/null; exit 1; }
# Send SIGTERM; readiness must flip within the 2s drain-delay window.
kill -TERM "$DRAIN_PID" 2>/dev/null
flipped=0
for _ in $(seq 1 20); do
    # Single curl per iteration: capture body and HTTP status in one
    # round-trip. `-w "\n%{http_code}"` appends the status on its
    # own line so we can split body from code without a second probe.
    resp=$(curl -sS -w "\n%{http_code}" "$DRAIN_BASE/v1/health/ready" 2>/dev/null || true)
    code="${resp##*$'\n'}"
    body="${resp%$'\n'*}"
    if [[ "$code" == "503" ]] && echo "$body" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("draining") is True else 1)' 2>/dev/null; then
        flipped=1
        break
    fi
    sleep 0.1
done
[[ "$flipped" == "1" ]] \
    || { echo "FAIL: readiness did not flip to 503+draining within drain-delay window"; kill "$DRAIN_PID" 2>/dev/null; wait "$DRAIN_PID" 2>/dev/null; exit 1; }
echo "    SIGTERM → readiness 503 + draining:true within drain-delay window"
# Wait for the server to actually exit so the next teardown is clean.
wait "$DRAIN_PID" 2>/dev/null || true

# `server.shutdown` audit event must land — paired with the
# `server.start` event emitted at boot, this gives the audit log a
# bracket-record per process instance. Restart a server pointed at
# the same audit DB and query for the event.
start_server
shutdown_audit="${WORK_DIR}/shutdown_audit.json"
curl -fsS "${auth[@]}" "$BASE_URL/v1/admin/audit?event=server.shutdown" \
    -o "$shutdown_audit"
shutdown_count=$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' < "$shutdown_audit")
[[ "$shutdown_count" -ge 1 ]] \
    || { echo "FAIL: no server.shutdown audit event recorded after SIGTERM"; cat "$shutdown_audit"; exit 1; }
# Newest row should be the one we just produced — fields_json contains
# `kind` + `uptime_secs`. Both must be present.
shutdown_kind=$(python3 -c 'import json,sys; rows=json.load(sys.stdin); print(json.loads(rows[0]["fields"]).get("kind",""))' < "$shutdown_audit")
shutdown_uptime=$(python3 -c 'import json,sys; rows=json.load(sys.stdin); print(json.loads(rows[0]["fields"]).get("uptime_secs",-1))' < "$shutdown_audit")
[[ "$shutdown_kind" == "graceful" ]] \
    || { echo "FAIL: server.shutdown kind=$shutdown_kind, expected 'graceful'"; exit 1; }
[[ "$shutdown_uptime" -ge 0 ]] \
    || { echo "FAIL: server.shutdown uptime_secs=$shutdown_uptime, expected ≥ 0"; exit 1; }
echo "    server.shutdown audit event recorded — kind=$shutdown_kind, uptime_secs=$shutdown_uptime"

echo
echo "==> all checks passed"
