#!/usr/bin/env bash
# Fork benchmark — the 10,000-fork test.
#
# The whole value proposition of Artifacts-as-described hinges on the claim
# that forks are cheap. This script puts a number on it. It:
#   1. Starts a server.
#   2. Creates a seed repo, pushes a real working tree into it (a handful
#      of files + a commit), so there are real objects to fork.
#   3. Forks N times in parallel (default 10,000, configurable via $FORKS).
#   4. Reports wall-clock time, throughput, and disk growth.
#   5. Clones a random fork to verify alternates resolution still works
#      after the stampede.
#
# Usage: FORKS=10000 PARALLEL=64 scripts/bench_fork.sh

set -euo pipefail
shopt -s inherit_errexit 2>/dev/null || true

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

FORKS=${FORKS:-10000}
PARALLEL=${PARALLEL:-64}
PORT=${PORT:-18789}
BIND="127.0.0.1:${PORT}"
BASE_URL="http://${BIND}"
DATA_DIR="$(mktemp -d -t artifacts-bench.XXXXXX)"
WORK_DIR="$(mktemp -d -t artifacts-bench-work.XXXXXX)"
ADMIN_TOKEN="bench-admin-$(date +%s)"
SERVER_LOG="${DATA_DIR}/server.log"

cleanup() {
    local ec=$?
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [[ $ec -ne 0 ]]; then
        echo
        echo "=== bench FAILED (exit $ec) ==="
        echo "server log: $SERVER_LOG"
    fi
    # Leave DATA_DIR alone on request for disk-inspection after the run.
    if [[ "${KEEP:-0}" != 1 ]]; then
        rm -rf "$DATA_DIR" "$WORK_DIR"
    else
        echo "(kept data: $DATA_DIR)"
        echo "(kept work: $WORK_DIR)"
    fi
    exit $ec
}
trap cleanup EXIT INT TERM

echo "==> building (release)"
cargo build --release --quiet

echo "==> starting server"
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

echo "==> seeding source repo with a real working tree"
src_resp=$(curl -fsS -X POST "${auth[@]}" "$BASE_URL/v1/repos")
src_id=$(echo "$src_resp" | json id)
src_remote=$(echo "$src_resp" | json remote)

src_clone="${WORK_DIR}/src"
GIT_TERMINAL_PROMPT=0 git clone --quiet "$src_remote" "$src_clone"
pushd "$src_clone" >/dev/null
git config user.email "bench@artifacts.local"
git config user.name "Bench"
# ~30 small files so there's non-trivial object content to share.
mkdir -p src docs tests
for i in $(seq 1 10); do
    printf 'pub fn m%02d() { println!("m%02d"); }\n' "$i" "$i" > "src/m${i}.rs"
done
for i in $(seq 1 10); do
    printf '# doc %d\n\nSome prose.\n' "$i" > "docs/d${i}.md"
done
for i in $(seq 1 10); do
    printf '#[test] fn t%02d() { assert!(true); }\n' "$i" > "tests/t${i}.rs"
done
echo "# seed repo" > README.md
git add .
git commit --quiet -m "seed"
git branch -M main
GIT_TERMINAL_PROMPT=0 git push --quiet origin main
popd >/dev/null

src_git_dir="$DATA_DIR/repos/${src_id}.git"
src_bytes=$(du -sb "$src_git_dir" | cut -f1)
echo "    source repo size: $src_bytes bytes"

echo "==> forking ${FORKS}x with parallelism ${PARALLEL}"
# Write a scratch file per fork so we can collect latencies. We use
# `xargs -P` for concurrency; each worker calls curl and prints the
# millisecond time of the single request.
work_latency_file="$WORK_DIR/latencies.txt"
: > "$work_latency_file"

fork_one() {
    local id="$1"
    # %{time_total} is in seconds with microsecond precision.
    local t
    t=$(curl -o /dev/null -s -w '%{time_total}' -X POST \
        -H "Authorization: Bearer ${2}" \
        -H 'Content-Type: application/json' \
        -d '{}' \
        "${3}/v1/repos/${4}/forks") || { echo "fail"; return 1; }
    # emit ms
    awk -v t="$t" 'BEGIN { printf("%.3f\n", t * 1000) }'
}
export -f fork_one

t_start=$(date +%s.%N)
seq 1 "$FORKS" \
    | xargs -n1 -P"$PARALLEL" -I {} bash -c "fork_one {} $ADMIN_TOKEN $BASE_URL $src_id" \
    >> "$work_latency_file"
t_end=$(date +%s.%N)

elapsed=$(awk -v a="$t_start" -v b="$t_end" 'BEGIN { printf("%.3f\n", b - a) }')
throughput=$(awk -v n="$FORKS" -v t="$elapsed" 'BEGIN { printf("%.1f\n", n / t) }')

echo "    forks done in ${elapsed}s (${throughput} forks/sec wall clock)"

# Latency percentiles.
sort -n "$work_latency_file" > "$WORK_DIR/latencies_sorted.txt"
total_lines=$(wc -l < "$WORK_DIR/latencies_sorted.txt")
pct() {
    local p="$1"
    # 1-indexed nth-percentile line.
    local line=$(( (total_lines * p + 99) / 100 ))
    [[ $line -lt 1 ]] && line=1
    sed -n "${line}p" "$WORK_DIR/latencies_sorted.txt"
}
echo "    latency ms: p50=$(pct 50)  p95=$(pct 95)  p99=$(pct 99)  max=$(tail -n1 "$WORK_DIR/latencies_sorted.txt")"

echo "==> measuring disk growth"
repos_dir="$DATA_DIR/repos"
total_bytes=$(du -sb "$repos_dir" | cut -f1)
fork_only_bytes=$(( total_bytes - src_bytes ))
per_fork_bytes=$(( fork_only_bytes / FORKS ))
echo "    repos dir total:    $total_bytes bytes"
echo "    source alone:       $src_bytes bytes"
echo "    added by forks:     $fork_only_bytes bytes (${per_fork_bytes} bytes/fork)"
echo "    (a copy would have added ~$(( src_bytes * FORKS )) bytes)"

echo "==> spot-check: clone a random fork"
# Pick a real fork id from the data dir.
sample_fork=$(find "$repos_dir" -maxdepth 1 -mindepth 1 -type d \
    ! -name "${src_id}.git" -print -quit | xargs -n1 basename)
sample_id="${sample_fork%.git}"
echo "    picked fork: $sample_id"
tok_resp=$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{"scope":"read"}' "$BASE_URL/v1/repos/${sample_id}/tokens")
sample_remote=$(echo "$tok_resp" | json remote)
sample_clone="${WORK_DIR}/sample"
GIT_TERMINAL_PROMPT=0 git clone --quiet "$sample_remote" "$sample_clone"
# Confirm the fork actually received all the expected content. If alternates
# failed, clone would produce an empty tree; if only refs failed, we'd see
# "You appear to have cloned an empty repository".
[[ -f "$sample_clone/README.md" ]] \
    || { echo "FAIL: fork clone missing README.md"; exit 1; }
[[ -f "$sample_clone/src/m1.rs" ]] \
    || { echo "FAIL: fork clone missing src/m1.rs (alternates likely broken)"; exit 1; }
[[ -f "$sample_clone/src/m10.rs" ]] \
    || { echo "FAIL: fork clone missing src/m10.rs"; exit 1; }
[[ -f "$sample_clone/docs/d5.md" ]] \
    || { echo "FAIL: fork clone missing docs/d5.md"; exit 1; }
# Byte-equal with the source working tree.
diff -q "$sample_clone/src/m1.rs" "$src_clone/src/m1.rs" >/dev/null \
    || { echo "FAIL: content mismatch"; exit 1; }
echo "    random fork cloned, all files present, content matches source"

echo
echo "==> bench done"
