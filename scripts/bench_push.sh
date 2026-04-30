#!/usr/bin/env bash
# Push-latency benchmark — the symmetric measurement to bench_clone.sh.
#
# Why this exists: bench_clone.sh quantified the M1b-2c win (gix-pack
# replacing `git pack-objects`). The push side has its own native swap
# (M1b-3 protocol layer + M1b-3-gix gix-pack indexing replacing
# `git unpack-objects`), and we'd like a number on it. Same shape as
# bench_clone.sh, just timing pushes instead.
#
# The bench:
#   1. Start the server.
#   2. Create one repo per push iteration (so each iteration starts
#      from an empty server-side repo — fairness).
#   3. Mint a write token + clone the empty repo as a working dir.
#   4. Pre-stage a small commit (one blob, one tree, one commit).
#   5. Time `git push` end-to-end, N times.
#   6. Report p50 / p95 / p99 / max and total throughput.
#
# A/B mode:
#   ARTIFACTS_DISABLE_NATIVE=1 scripts/bench_push.sh
# disables every native dispatcher (ls-refs / fetch / receive-pack /
# pack-indexing) and the request falls through to the legacy
# subprocess paths. Useful for A/B-ing native vs subprocess on the
# same binary.
#
# Usage: PUSHES=200 scripts/bench_push.sh

set -euo pipefail
shopt -s inherit_errexit 2>/dev/null || true

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PUSHES=${PUSHES:-200}
PORT=${PORT:-18793}
BIND="127.0.0.1:${PORT}"
BASE_URL="http://${BIND}"
DATA_DIR="$(mktemp -d -t art-bench-push.XXXXXX)"
WORK_DIR="$(mktemp -d -t art-bench-push-work.XXXXXX)"
ADMIN_TOKEN="bench-push-$(date +%s)"
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
    fi
    rm -rf "$DATA_DIR" "$WORK_DIR"
    exit $ec
}
trap cleanup EXIT INT TERM

echo "==> building (release)"
cargo build --release --quiet

echo "==> starting server"
ARTIFACTS_ADMIN_TOKEN="$ADMIN_TOKEN" \
ARTIFACTS_DISABLE_NATIVE="${ARTIFACTS_DISABLE_NATIVE:-}" \
    ./target/release/artifacts serve \
        --data-dir "$DATA_DIR" \
        --bind "$BIND" \
        --public-base-url "$BASE_URL" \
    >>"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 50); do
    curl -fsS "$BASE_URL/v1/health" >/dev/null 2>&1 && break
    sleep 0.1
done
curl -fsS "$BASE_URL/v1/health" >/dev/null

if [[ -n "${ARTIFACTS_DISABLE_NATIVE:-}" && "${ARTIFACTS_DISABLE_NATIVE}" != "0" ]]; then
    echo "    mode: SUBPROCESS (ARTIFACTS_DISABLE_NATIVE=$ARTIFACTS_DISABLE_NATIVE)"
else
    echo "    mode: NATIVE"
fi

# Pre-stage a tiny commit in a working dir we'll re-push N times.
# Each iteration creates a fresh server-side repo and points origin
# at it, so the server-side state is empty every time (no fast-path
# from already-seen objects).
echo "==> preparing source tree"
TREE_SRC="${WORK_DIR}/source"
mkdir -p "$TREE_SRC"
git -c init.defaultBranch=main init -q "$TREE_SRC"
git -C "$TREE_SRC" config user.email bench@bench
git -C "$TREE_SRC" config user.name bench
echo 'hello world' > "$TREE_SRC/README.md"
mkdir -p "$TREE_SRC/src"
echo 'fn main() {}' > "$TREE_SRC/src/main.rs"
echo 'docs' > "$TREE_SRC/src/lib.rs"
git -C "$TREE_SRC" add .
git -C "$TREE_SRC" commit -q -m "bench seed"

echo "==> warming up (3 pushes)"
for _ in 1 2 3; do
    create_resp=$(curl -fsS -X POST \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H 'Content-Type: application/json' \
        -d '{}' \
        "$BASE_URL/v1/repos")
    url=$(echo "$create_resp" | python3 -c 'import sys,json;print(json.load(sys.stdin)["remote"])')
    git -C "$TREE_SRC" push -q "$url" main 2>/dev/null || true
done

echo "==> timing $PUSHES sequential pushes"
LATENCIES_FILE="${WORK_DIR}/latencies"
: > "$LATENCIES_FILE"
START=$(date +%s.%N)
for _ in $(seq 1 "$PUSHES"); do
    create_resp=$(curl -fsS -X POST \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H 'Content-Type: application/json' \
        -d '{}' \
        "$BASE_URL/v1/repos")
    url=$(echo "$create_resp" | python3 -c 'import sys,json;print(json.load(sys.stdin)["remote"])')
    push_start=$(date +%s.%N)
    git -C "$TREE_SRC" push -q "$url" main 2>/dev/null
    push_end=$(date +%s.%N)
    awk "BEGIN{printf \"%.6f\n\", ($push_end - $push_start) * 1000}" >> "$LATENCIES_FILE"
done
END=$(date +%s.%N)

# Stats: read all latencies, sort, pick percentiles.
TOTAL=$(awk "BEGIN{printf \"%.3f\", $END - $START}")
RATE=$(awk "BEGIN{printf \"%.1f\", $PUSHES / ($END - $START)}")
SORTED=$(sort -n "$LATENCIES_FILE")
read -r P50 P95 P99 MAX <<<"$(echo "$SORTED" | awk -v n="$PUSHES" '
    {a[NR]=$1}
    END {
        p50 = a[int(n*0.5)+1]
        p95 = a[int(n*0.95)+1]
        p99 = a[int(n*0.99)+1]
        max = a[n]
        printf "%.3f %.3f %.3f %.3f\n", p50, p95, p99, max
    }')"

echo
echo "==> $PUSHES pushes in ${TOTAL}s ($RATE pushes/sec)"
printf '    latency ms:  p50=%s  p95=%s  p99=%s  max=%s\n' \
    "$P50" "$P95" "$P99" "$MAX"

echo
echo "==> done"
