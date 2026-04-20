# artifacts-gui

Live structural view of an Artifacts server. A feature-gated companion
binary that talks HTTPS/HTTP to a running artifacts instance and renders
what's there with eframe/egui. Useful for operations (is anything
happening?), debugging (why does this fork have no parent?), and
demos (show someone what Artifacts is without teaching them git).

## Install and run

```sh
# Build. (Not included in the default binary — the server stays lean
# without the egui dep tree.)
cargo build --release --bin artifacts-gui --features gui

# Point it at a running server.
./target/release/artifacts-gui \
    --url http://127.0.0.1:8787 \
    --admin-token "$ARTIFACTS_ADMIN_TOKEN"
```

`--admin-token` reads `ARTIFACTS_ADMIN_TOKEN` from the environment if
the flag isn't set — keeps the token out of shell history.

## Platform support

Linux with Wayland or X11. eframe picks the backend via winit at
startup; on a Wayland session you get Wayland, on an XWayland session
you get X11. No config needed.

Not tested on macOS/Windows but eframe supports them in theory — pass
defaults through and see what happens.

## What the three views show

**Overview** — server version string (from `artifacts_build_info`),
repo count, total requests served, rate-limited and quota-exceeded
counters, and aggregate p50/p95/p99 latency derived from the
request-duration histogram. Percentiles are bucket-approximated;
tighten the bucket list in `src/metrics.rs` if you need sub-ms
precision.

**Repos** — sortable-by-eye (egui's Grid; actual sort is by insert
order which is `created_at DESC` from the server). Four columns: id,
owner (or `<admin>`), relative created-at, and source id (the parent
repo in a fork chain, or `—` for roots).

**Forks** — tree view. Roots (repos without a source) at the top,
their children nested underneath. Children's children nest further.
Orphaned forks (source id not in the list — parent was deleted, or
data is partial) appear in a separate section at the bottom so they
stay visible rather than vanishing.

## What it does NOT do

Intentionally read-only:

- No create / fork / delete / revoke buttons. Mutation stays in curl
  or a proper client SDK. Eliminates a whole class of accidental-click
  incidents.
- No repo detail view yet. The `GET /v1/admin/repos/:id` endpoint
  exists (returns refs + size-on-disk), but there's no page that
  renders it. Drop-in work for a future commit.
- No token browsing or audit log. Tokens are hashed in the DB; the
  server never exposes them through the admin API and the GUI never
  asks.
- No time-series of metrics. Each poll overwrites the last view. For a
  historical record, scrape `/metrics` into Prometheus / VictoriaMetrics
  / Grafana — the GUI is a current-state browser, not a historian.
- No authentication UI. The admin token is a static value. If you need
  per-user viewing, the JWT path on the server exists but the GUI
  only speaks admin auth today.

## Polling cadence

Defaults to 2 seconds between polls. Tweak with `--poll-interval-secs`.
Polls are independent of window repaint — the background thread
updates shared state, egui repaints every 500 ms and reads the
latest. A slow server response doesn't block the UI; the last-poll
label in the top bar shows how stale the view is, and a red error
string surfaces if polling fails.

## Troubleshooting

- **Window doesn't appear on Wayland.** Check that `winit` picked the
  Wayland backend: set `RUST_LOG=winit=debug` and look for a
  "created wayland compositor" line. If it falls back to X11 on a
  Wayland session that's winit's decision based on available
  protocol support; usually fine.
- **"connecting…" never becomes "polled Ns ago".** The server isn't
  reachable at the URL you passed, or the admin token is wrong. The
  top-right red text will show the underlying reqwest / JSON parse
  error. Common causes: wrong port, forgot `--allow-insecure` when
  running the server non-loopback, token mismatch.
- **Percentiles show 0.00 ms.** No request-duration observations yet
  — make a few REST calls and they'll populate.

## File pointer

Single binary, single file: [src/bin/artifacts-gui.rs](./src/bin/artifacts-gui.rs).
No separate crate, no build config beyond the feature flag. Modifying
the GUI means editing that one file.
