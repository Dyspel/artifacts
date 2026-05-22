#!/usr/bin/env bash
# Concurrent-load benchmark for the Artifacts server.
#
# Existing bench scripts measure single-client latency end-to-end —
# bench_clone.sh times sequential clones, bench_push.sh times
# sequential pushes. Neither exposes contention. This script runs N
# parallel clones + N parallel pushes against the same running
# server, so the SQLite pool (A5) and the smart-HTTP layer see real
# concurrency.
#
# What it does, in order:
#   1. Start the server.
#   2. Create a seed repo with a small commit so the clone target
#      has content.
#   3. Run N=32 concurrent clones of that repo, each into its own
#      tempdir, timing each individually.
#   4. Create N=32 distinct empty repos (avoids ref-CAS contention
#      that would otherwise dominate the push half — push concurrency
#      against ONE repo is a fundamentally different shape and lives
#      in the M3b distributed-RefStore work).
#   5. Run N=32 concurrent pushes, one to each of those repos.
#   6. Report per-test p50/p95/p99 + total wall clock + throughput.
#
# Usage:
#   N=32 scripts/bench_concurrent.sh    # default
#   N=64 scripts/bench_concurrent.sh    # heavier
#   KEEP=1 N=4 scripts/bench_concurrent.sh    # debug — keep DATA_DIR
#
# Honest caveat: 32 concurrent clones against a 28 KB seed repo
# saturate the loopback interface long before they saturate the
# server's compute or the SQLite pool. The right way to read these
# numbers is "is p99 / max blowing out under fan-in?", not "what's
# the absolute throughput?". An actual throughput bench needs larger
# packs + a longer time window — out of scope for the prototype.

set -euo pipefail
shopt -s inherit_errexit 2>/dev/null || true

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

N=${N:-32}
PORT=${PORT:-18799}
BIND="127.0.0.1:${PORT}"
BASE_URL="http://${BIND}"
DATA_DIR="$(mktemp -d -t art-bench-conc.XXXXXX)"
WORK_DIR="$(mktemp -d -t art-bench-conc-work.XXXXXX)"
ADMIN_TOKEN="bench-conc-$(date +%s)"
SERVER_LOG="${DATA_DIR}/server.log"

cleanup() {
    local ec=$?
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [[ $ec -ne 0 ]]; then
        echo
        echo "=== bench_concurrent FAILED (exit $ec) ==="
        echo "--- server log tail ---"
        tail -60 "$SERVER_LOG" 2>/dev/null || true
        echo "data: $DATA_DIR"
        echo "work: $WORK_DIR"
    fi
    if [[ "${KEEP:-0}" != 1 && $ec -eq 0 ]]; then
        rm -rf "$DATA_DIR" "$WORK_DIR"
    fi
    exit $ec
}
trap cleanup EXIT INT TERM

echo "==> building (release)"
cargo build --release --quiet

echo "==> starting server on $BIND"
ARTIFACTS_ADMIN_TOKEN="$ADMIN_TOKEN" \
    ./target/release/artifacts serve \
        --data-dir "$DATA_DIR" \
        --bind "$BIND" \
        --public-base-url "$BASE_URL" \
    >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 100); do
    curl -fsS "$BASE_URL/v1/health" >/dev/null 2>&1 && break
    sleep 0.05
done
curl -fsS "$BASE_URL/v1/health" >/dev/null

auth=(-H "Authorization: Bearer ${ADMIN_TOKEN}")
json() { python3 -c 'import json,sys; print(json.load(sys.stdin)["'"$1"'"])'; }

# ---------------------------------------------------------------------
# Phase 1 — seed a source repo to clone from.
# ---------------------------------------------------------------------
echo "==> seeding source repo"
src_resp=$(curl -fsS -X POST "${auth[@]}" "$BASE_URL/v1/repos")
src_id=$(echo "$src_resp" | json id)
src_remote=$(echo "$src_resp" | json remote)

src_clone="${WORK_DIR}/src"
GIT_TERMINAL_PROMPT=0 git clone --quiet "$src_remote" "$src_clone"
pushd "$src_clone" >/dev/null
git config user.email "bench@artifacts.local"
git config user.name "Bench"
mkdir -p src docs
for i in $(seq 1 8); do
    printf 'pub fn m%02d() {}\n' "$i" > "src/m${i}.rs"
done
for i in $(seq 1 4); do
    printf '# doc %d\n' "$i" > "docs/d${i}.md"
done
echo "# seed" > README.md
git add .
git commit --quiet -m "seed"
git branch -M main
GIT_TERMINAL_PROMPT=0 git push --quiet origin main
popd >/dev/null

# One read token for every clone — removes mint-token from the hot path.
tok_resp=$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{"scope":"read"}' "$BASE_URL/v1/repos/${src_id}/tokens")
clone_remote=$(echo "$tok_resp" | json remote)

# ---------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------
# Report p50/p95/p99/max for a file of one-latency-per-line values.
# Args: <label> <file> <total_count> <wall_seconds>
report() {
    local label="$1" file="$2" total="$3" wall="$4"
    sort -n "$file" > "${file}.sorted"
    local count
    count=$(wc -l < "${file}.sorted")
    if [[ "$count" -ne "$total" ]]; then
        echo "WARN: $label expected $total samples, got $count" >&2
    fi
    local pct
    pct() {
        local p="$1"
        local line=$(( (count * p + 99) / 100 ))
        [[ $line -lt 1 ]] && line=1
        sed -n "${line}p" "${file}.sorted"
    }
    local p50 p95 p99 mx tput
    p50=$(pct 50); p95=$(pct 95); p99=$(pct 99)
    mx=$(tail -n1 "${file}.sorted")
    tput=$(awk -v n="$count" -v t="$wall" 'BEGIN { printf("%.1f\n", n / t) }')
    printf "    %-7s  count=%d  wall=%.3fs  tput=%s ops/s  p50=%s  p95=%s  p99=%s  max=%s\n" \
        "$label" "$count" "$wall" "$tput" "$p50" "$p95" "$p99" "$mx"
}

# ---------------------------------------------------------------------
# Phase 2 — N concurrent clones.
# ---------------------------------------------------------------------
echo "==> running $N concurrent clones"
clone_lat_dir="${WORK_DIR}/clone-lat"
mkdir -p "$clone_lat_dir"

t_start=$EPOCHREALTIME
clone_pids=()
for i in $(seq 1 "$N"); do
    (
        d="${WORK_DIR}/c-${i}"
        t0=$EPOCHREALTIME
        GIT_TERMINAL_PROMPT=0 git clone --quiet "$clone_remote" "$d"
        t1=$EPOCHREALTIME
        awk -v a="$t0" -v b="$t1" 'BEGIN { printf("%.3f\n", (b - a) * 1000) }' \
            > "${clone_lat_dir}/${i}.ms"
    ) &
    clone_pids+=($!)
done
# `wait` with no args waits for every backgrounded job, including
# SERVER_PID, which would block for shutdown_timeout_secs. Wait on
# only the specific subshell PIDs.
wait "${clone_pids[@]}"
t_end=$EPOCHREALTIME
clone_wall=$(awk -v a="$t_start" -v b="$t_end" 'BEGIN { printf("%.6f\n", b - a) }')

cat "$clone_lat_dir"/*.ms > "${WORK_DIR}/clone-lat.txt"
report "clone" "${WORK_DIR}/clone-lat.txt" "$N" "$clone_wall"

# ---------------------------------------------------------------------
# Phase 3 — N concurrent pushes (each to a distinct repo).
#
# Same-repo push concurrency is bounded by ref-CAS and isn't the
# fan-in shape this bench is for. Distinct-repo pushes exercise the
# SQLite pool + receive-pack invocation paths in parallel.
# ---------------------------------------------------------------------
echo "==> creating $N target repos for the push phase"
push_targets_file="${WORK_DIR}/push_targets.txt"
: > "$push_targets_file"
for i in $(seq 1 "$N"); do
    resp=$(curl -fsS -X POST "${auth[@]}" "$BASE_URL/v1/repos")
    # remote URL only — the response already embeds a write token.
    remote=$(echo "$resp" | json remote)
    echo "$remote" >> "$push_targets_file"
done

echo "==> preparing $N local clones to push from"
push_work_dir="${WORK_DIR}/push-work"
mkdir -p "$push_work_dir"
for i in $(seq 1 "$N"); do
    remote=$(sed -n "${i}p" "$push_targets_file")
    d="${push_work_dir}/r-${i}"
    GIT_TERMINAL_PROMPT=0 git clone --quiet "$remote" "$d"
    pushd "$d" >/dev/null
    git config user.email "bench@artifacts.local"
    git config user.name "Bench"
    echo "hi from r-${i}" > README.md
    git add README.md
    git commit --quiet -m "push bench r-${i}"
    git branch -M main
    popd >/dev/null
done

echo "==> running $N concurrent pushes"
push_lat_dir="${WORK_DIR}/push-lat"
mkdir -p "$push_lat_dir"

t_start=$EPOCHREALTIME
push_pids=()
for i in $(seq 1 "$N"); do
    (
        d="${push_work_dir}/r-${i}"
        t0=$EPOCHREALTIME
        GIT_TERMINAL_PROMPT=0 git -C "$d" push --quiet origin main
        t1=$EPOCHREALTIME
        awk -v a="$t0" -v b="$t1" 'BEGIN { printf("%.3f\n", (b - a) * 1000) }' \
            > "${push_lat_dir}/${i}.ms"
    ) &
    push_pids+=($!)
done
wait "${push_pids[@]}"
t_end=$EPOCHREALTIME
push_wall=$(awk -v a="$t_start" -v b="$t_end" 'BEGIN { printf("%.6f\n", b - a) }')

cat "$push_lat_dir"/*.ms > "${WORK_DIR}/push-lat.txt"
report "push" "${WORK_DIR}/push-lat.txt" "$N" "$push_wall"

# ---------------------------------------------------------------------
# Phase 4 — quick pool-state snapshot so the operator can see whether
# we actually saturated the pool. The gauges land on `/metrics`.
# ---------------------------------------------------------------------
echo "==> SQLite pool-state snapshot (post-bench)"
curl -fsS "$BASE_URL/metrics" \
    | grep -E '^artifacts_sqlite_pool_(size|in_use)' \
    | sed 's/^/    /' \
    || echo "    (pool gauges not exposed — A5 not yet wired?)"

echo
echo "==> done"
