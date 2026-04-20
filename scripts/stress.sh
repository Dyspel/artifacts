#!/usr/bin/env bash
# Sustained mixed-workload stress test against a *running* artifacts server.
#
# Unlike scripts/bench_fork.sh (which spawns its own server and measures
# one specific op) this one talks to whatever is listening at $URL and
# generates varied traffic: admin creates, two JWT users creating /
# forking at different rates, and a steady read-side stream to /metrics
# and /v1/admin/repos.
#
# Designed to make the GUI's Overview charts interesting:
#   - the "requests / sec" line climbs to ~20-40 rps
#   - the latency histogram accumulates observations so p50/p95/p99 draw
#   - `artifacts_rate_limited_total` bumps when alice's burst drains her
#     rate-limit bucket
#   - `artifacts_quota_exceeded_total` bumps when alice hits the
#     per-user quota cap
#
# Admin bypasses both rate-limit and quota (by design), so those
# counters are only moved by JWT-authenticated workers.
#
# Usage:
#     URL=http://127.0.0.1:8787 \
#     ARTIFACTS_ADMIN_TOKEN=... \
#     ARTIFACTS_JWT_SECRET=... \
#     DURATION=30 \
#         scripts/stress.sh
#
# Requires the server to be started with a matching --jwt-secret; the
# admin token obviously has to match too. The script prints a before
# and after snapshot of the counters it exercises.

set -euo pipefail

URL="${URL:-http://127.0.0.1:8787}"
ADMIN="${ARTIFACTS_ADMIN_TOKEN:?set ARTIFACTS_ADMIN_TOKEN}"
JWT_SECRET="${ARTIFACTS_JWT_SECRET:-}"
DURATION="${DURATION:-30}"

# ------------------------------------------------------------------ helpers

# Sign a Dyspel-shape HS256 JWT. No external tool needed — python stdlib
# only. If no secret is configured, emit empty so callers can detect.
sign_jwt() {
    local user="$1"
    if [[ -z "$JWT_SECRET" ]]; then
        echo ""
        return
    fi
    python3 - "$JWT_SECRET" "$user" <<'PY'
import base64, hmac, hashlib, json, sys, time
secret, user = sys.argv[1], sys.argv[2]
b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
h = b64(json.dumps({"alg":"HS256","typ":"JWT"}, separators=(",",":")).encode())
p = b64(json.dumps({"userId": user, "exp": int(time.time()) + 3600},
                   separators=(",",":")).encode())
s = b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
print(f"{h}.{p}.{s}")
PY
}

snapshot() {
    local label="$1"
    echo "--- ${label} ---"
    curl -sS -H "Authorization: Bearer $ADMIN" "$URL/metrics" | awk '
        /^artifacts_requests_total\{/      { req += $NF }
        /^artifacts_rate_limited_total /   { rl = $NF }
        /^artifacts_quota_exceeded_total / { qe = $NF }
        END {
            printf "  requests_total (sum):   %d\n", req+0;
            printf "  rate_limited_total:     %d\n", rl+0;
            printf "  quota_exceeded_total:   %d\n", qe+0;
        }'
}

# ------------------------------------------------------------------ setup

admin_h=("-H" "Authorization: Bearer $ADMIN")
alice_jwt="$(sign_jwt alice-stress)"
bob_jwt="$(sign_jwt bob-stress)"

if [[ -z "$alice_jwt" ]]; then
    echo "note: ARTIFACTS_JWT_SECRET not set — JWT workers will be skipped."
    echo "      rate_limited / quota_exceeded counters won't move (admin is exempt)."
fi

echo "target:   $URL"
echo "duration: ${DURATION}s"
echo
snapshot 'pre-test'
echo

# ------------------------------------------------------------------ workers

end=$(( $(date +%s) + DURATION ))

# Worker: admin creates source repos (fast, ~1.5 rps). Admin bypasses
# rate-limit + quota, so this purely generates activity in the request
# counter without touching the error counters.
(
    while [ "$(date +%s)" -lt "$end" ]; do
        curl -sS -o /dev/null -X POST "${admin_h[@]}" "$URL/v1/repos" || true
    done
) &

# Worker: alice bursts 30 requests then sleeps 3s, on repeat. The
# rate-limit bucket (burst 20, refill 10/min) drains within each burst
# and refills slowly, so each cycle contributes ~10 successful creates
# and the rest hit 429 rate_limited. Once alice passes 40 repos she'll
# also start hitting quota_exceeded.
if [[ -n "$alice_jwt" ]]; then
    (
        alice_h=("-H" "Authorization: Bearer $alice_jwt")
        while [ "$(date +%s)" -lt "$end" ]; do
            for _ in $(seq 1 30); do
                curl -sS -o /dev/null -X POST "${alice_h[@]}" "$URL/v1/repos" 2>/dev/null || true
            done
            sleep 3
        done
    ) &
fi

# Worker: bob steady trickle ~1 per 2s. Never hits either limit, just
# contributes a well-behaved baseline to the request-rate chart.
if [[ -n "$bob_jwt" ]]; then
    (
        bob_h=("-H" "Authorization: Bearer $bob_jwt")
        while [ "$(date +%s)" -lt "$end" ]; do
            curl -sS -o /dev/null -X POST "${bob_h[@]}" "$URL/v1/repos" || true
            sleep 2
        done
    ) &
fi

# Worker: read-side traffic — admin-list + /metrics a few times per
# second. Exercises the read path that the GUI itself is hitting.
(
    while [ "$(date +%s)" -lt "$end" ]; do
        curl -sS -o /dev/null "${admin_h[@]}" "$URL/v1/admin/repos" || true
        sleep 0.5
    done
) &

wait

echo
snapshot 'post-test'
