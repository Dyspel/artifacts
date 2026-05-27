# Security policy

## Reporting a vulnerability

Email security reports to **security@artifacts.invalid** (replace
with the real address for your fork). Do **not** open public GitHub
issues for vulnerabilities — file them privately so the fix can ship
before the bug is widely known.

A useful report includes:

- A short description of the bug + the threat model it breaks.
- The affected version (commit SHA or release tag).
- Reproducer: a minimal request sequence, payload, or test case.
- Impact: what an attacker can do with this — read other users'
  data, escalate to admin, exhaust memory, deny service, etc.

You'll get an acknowledgement within 72 hours and a disposition
(fixed / won't-fix / out-of-scope) within 14 days. Coordinated
disclosure is preferred; a public-disclosure deadline of 90 days
from the initial report is the default if not otherwise agreed.

## Scope

The `artifacts` server binary and its on-disk state (SQLite stores,
bare git dirs, webhook outbox) are in scope.

In scope:

- Auth bypass on REST or `/git/*` endpoints.
- Privilege escalation (a user-scope token gaining admin access).
- Audit-log tamper that the chain-verify endpoint fails to detect.
- Information disclosure — secrets in logs, traversal off the
  repos dir, oracle that exposes another user's repo existence.
- Crash / DoS via a single crafted request (a slow-body request
  is bounded by the `--request-timeout-secs` budget and is *not*
  in scope unless it bypasses the timeout).
- Memory-safety issues in the hand-rolled pack parser
  (`src/native_pack/parse.rs`) — high-value target, fuzzed in CI.

Out of scope:

- Vulnerabilities in dependencies that the upstream maintainer
  has already patched (`cargo deny check advisories` is the CI
  gate; please open an issue if it's regressing).
- Issues that require an attacker to already hold the admin
  token (that token is the platform credential — compromise of
  it is "you've already lost").
- The `artifacts-gui` binary's TLS/cert-store path (it doesn't
  ship as the production deployment).
- Multi-process deployments running against the same data dir —
  the distributed `RefStore` (M3b) is not implemented; running
  two servers on one data dir is undefined behavior and not a
  supported configuration.

## Hardening already in place

Documented here so a reporter can skip what's already known:

- All secret comparisons in the auth-rest path use
  `subtle::ConstantTimeEq` with length-gating. See
  `src/auth.rs::authorize_rest`.
- JWT validation: HS256 algorithm allow-list (rejects `alg=none`
  + asymmetric-via-HMAC confusion), `exp` required, `nbf` honored
  when present, optional `aud` / `iss` strict-mode via
  `--jwt-expected-aud` / `--jwt-expected-iss`.
- Audit log is tamper-evident via a per-row SHA-256 hash chain;
  `GET /v1/admin/audit/verify-chain` walks the chain and reports
  the offending row id on the first mismatch.
- 5xx error responses are redacted at the wire: the body says
  `"message": "internal"` while the full Display chain goes only
  to `tracing::error`. 4xx responses keep their user-input-shaped
  messages.
- Per-request timeout (default 5 min) bounds slow-body attacks;
  per-route body caps bound memory consumption from a hostile
  uploader.
- Tokens are stored as SHA-256 hashes; webhook HMAC secrets are
  AES-256-GCM-sealed at rest under a key loaded from
  `ARTIFACTS_WEBHOOK_KEY` or `<data-dir>/webhook-key.bin`.
- Supply-chain: `cargo deny check` runs on every PR
  (advisories + bans + licenses + sources) plus `cargo machete`
  for unused-dep drift.

The brutal-assessment scan (see commits prefixed `audit(J*)`)
documents the trust-boundary analysis at the granularity each
reviewer needs.
