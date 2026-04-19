#!/usr/bin/env bash
# Clone-latency benchmark.
#
# Why this exists: the fork benchmark (scripts/bench_fork.sh) measures the
# storage hot path — pure metadata writes, no git-protocol traffic. Clone
# latency, by contrast, is dominated by whatever runs inside `GET
# /info/refs` + `POST /git-upload-pack`. That's where the CGI boundary
# lived, and where M1a removed a process layer.
#
# The bench:
#   1. Start the server.
#   2. Seed one repo with a small working tree.
#   3. Mint a read token.
#   4. Do N clones of that repo, one at a time, timing each end-to-end.
#   5. Report p50 / p95 / p99 / max and total throughput.
#
# Usage: CLONES=200 scripts/bench_clone.sh

set -euo pipefail
shopt -s inherit_errexit 2>/dev/null || true

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CLONES=${CLONES:-200}
PORT=${PORT:-18792}
BIND="127.0.0.1:${PORT}"
BASE_URL="http://${BIND}"
DATA_DIR="$(mktemp -d -t art-bench-clone.XXXXXX)"
WORK_DIR="$(mktemp -d -t art-bench-clone-work.XXXXXX)"
ADMIN_TOKEN="bench-clone-$(date +%s)"
SERVER_LOG="${DATA_DIR}/server.log"

cleanup() {
    local ec=$?
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [[ $ec -ne 0 ]]; then
        echo
        echo "=== bench_clone FAILED (exit $ec) ==="
        cat "$SERVER_LOG" 2>/dev/null | tail -40 || true
    fi
    if [[ "${KEEP:-0}" != 1 ]]; then
        rm -rf "$DATA_DIR" "$WORK_DIR"
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

# Mint one read token we'll reuse for every clone; removes token-mint
# from the measured path.
tok_resp=$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{"scope":"read"}' "$BASE_URL/v1/repos/${src_id}/tokens")
clone_remote=$(echo "$tok_resp" | json remote)

echo "==> warming up (3 clones)"
for i in 1 2 3; do
    d="${WORK_DIR}/warm-${i}"
    GIT_TERMINAL_PROMPT=0 git clone --quiet "$clone_remote" "$d" >/dev/null
    rm -rf "$d"
done

echo "==> timing ${CLONES} sequential clones"
latency_file="${WORK_DIR}/clone-ms.txt"
: > "$latency_file"

t_start=$(date +%s.%N)
for i in $(seq 1 "$CLONES"); do
    d="${WORK_DIR}/c-${i}"
    # Use python's perf_counter for microsecond-precision timing.
    python3 - <<PY >> "$latency_file"
import subprocess, time
t0 = time.perf_counter()
subprocess.run(["git", "clone", "--quiet", "$clone_remote", "$d"],
               env={"GIT_TERMINAL_PROMPT":"0","PATH":"/usr/bin:/bin"},
               check=True)
t1 = time.perf_counter()
print(f"{(t1 - t0) * 1000:.3f}")
PY
    rm -rf "$d"
done
t_end=$(date +%s.%N)

elapsed=$(awk -v a="$t_start" -v b="$t_end" 'BEGIN { printf("%.3f\n", b - a) }')
tput=$(awk -v n="$CLONES" -v t="$elapsed" 'BEGIN { printf("%.1f\n", n / t) }')

sort -n "$latency_file" > "${latency_file}.sorted"
total=$(wc -l < "${latency_file}.sorted")
pct() {
    local p="$1"
    local line=$(( (total * p + 99) / 100 ))
    [[ $line -lt 1 ]] && line=1
    sed -n "${line}p" "${latency_file}.sorted"
}
p50=$(pct 50); p95=$(pct 95); p99=$(pct 99)
mx=$(tail -n1 "${latency_file}.sorted")

echo
echo "==> ${CLONES} clones in ${elapsed}s (${tput} clones/sec)"
echo "    latency ms:  p50=${p50}  p95=${p95}  p99=${p99}  max=${mx}"

echo
echo "==> done"
