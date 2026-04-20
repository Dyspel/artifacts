# artifacts-gui

Live structural view of an Artifacts server. A feature-gated companion
binary that talks HTTP(S) to a running artifacts instance and renders
what's there with eframe/egui. Useful for operations (is anything
happening?), debugging (why does this fork have no parent?), and demos
(show someone what Artifacts is without teaching them git).

## Getting started — one-shot

Copy-paste from an interactive shell (Wayland or X11, either works):

```sh
cd /data4/ex-cc/artifacts

# 1. Build both binaries — server + GUI — in release mode.
cargo build --release --bin artifacts
cargo build --release --bin artifacts-gui --features gui

# 2. Start the server in the background. Pick any admin token string;
#    the GUI will need to present it. (Below we use a dev default.)
mkdir -p ./data
ARTIFACTS_ADMIN_TOKEN=dyspel-dev-shared \
    ./target/release/artifacts serve \
        --data-dir ./data \
        --bind 127.0.0.1:8787 \
        --public-base-url http://127.0.0.1:8787 \
    > /tmp/artifacts-server.log 2>&1 &
disown
sleep 1
curl -fsS http://127.0.0.1:8787/v1/health && echo

# 3. (Optional) Seed one source + one fork so the GUI has something to show
TOK=dyspel-dev-shared
SRC=$(curl -fsS -X POST -H "Authorization: Bearer $TOK" \
        http://127.0.0.1:8787/v1/repos | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
curl -fsS -X POST -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d '{}' http://127.0.0.1:8787/v1/repos/$SRC/forks > /dev/null

# 4. Launch the GUI. IT MUST BE RUN FROM YOUR INTERACTIVE SHELL so it
#    inherits your session's WAYLAND_DISPLAY / DISPLAY / XDG_RUNTIME_DIR.
ARTIFACTS_ADMIN_TOKEN=dyspel-dev-shared \
    ./target/release/artifacts-gui --url http://127.0.0.1:8787
```

The window opens titled **`artifacts-gui`**, ~980×680. Use the left
sidebar to switch between **Overview** / **Repos** / **Forks**.

## Shutting down

```sh
pkill -f 'artifacts-gui'     # close the window
pkill -f 'artifacts serve'   # stop the server
```

(The server's SQLite db at `./data/tokens.db` and the bare repos under
`./data/repos/` persist across restarts — that's the point.)

## CLI flags

```
artifacts-gui [OPTIONS]

  --url <URL>                    Base URL of the Artifacts server.
                                 Default: http://127.0.0.1:8787
  --admin-token <TOKEN>          Required. Env: ARTIFACTS_ADMIN_TOKEN
  --poll-interval-secs <SECS>    How often to refresh. Default: 2.0
```

`--admin-token` reads `ARTIFACTS_ADMIN_TOKEN` from the environment if
the flag isn't set — keeps the token out of shell history.

## Platform notes

Linux with Wayland or X11. eframe picks the backend via winit at
startup; on a Wayland session you get Wayland, on an XWayland-only
session you get X11. No config needed *if* you run the GUI from a
shell that already has your session's display env vars. See
[Troubleshooting](#troubleshooting) for when it doesn't.

Not tested on macOS or Windows. eframe supports both in principle; if
you try it there, pass the default build through and see what happens.

## What the three views show

**Overview** — the most useful tab. Shows:

- Server version from `artifacts_build_info`
- Repo count
- Cumulative request / rate-limited / quota-exceeded counters
- Aggregate p50/p95/p99 latency (current value)
- **Three time-series charts** over the last 5 minutes of polls:
  - *Requests / sec* (derived from counter deltas between samples)
  - *Latency percentiles* (p50, p95, p99 as three lines)
  - *Rate-limited / quota-exceeded per sec* (usually zero; non-zero
    means something operator-worthy is happening)

The charts use `egui_plot`. X-axis is *seconds ago* — 0 on the right,
−300 on the left. Y always starts at 0 so a flat quiet line stays
visible instead of jumping around on an auto-ranged axis. First
couple of polls show "collecting samples…" because at least two
samples are needed to compute a rate.

**Repos** — four-column scrollable table: id, owner (or `<admin>`),
relative created-at, and source id (the parent repo in a fork chain,
or `—` for roots). Ordering is whatever the server returns, which is
`created_at DESC` (newest first).

**Forks** — tree view. Roots (repos without a source) at the top,
their children nested underneath, recursively. Orphaned forks (source
id not in the current list — parent was deleted, or admin-list data
is partial) get a separate section at the bottom so they stay visible
rather than vanishing.

## What it does NOT do

Intentionally:

- **No create / fork / delete / revoke buttons.** Mutation stays in
  curl or a proper client SDK. Eliminates a whole class of accidental-
  click incidents.
- **No repo detail view.** `GET /v1/admin/repos/:id` exists (returns
  refs + size-on-disk), but there's no page that renders it yet.
  Drop-in work for a future commit.
- **No token browsing / audit log.** Tokens are hashed in the DB; the
  server never exposes them through the admin API and the GUI never
  asks.
- **No long-term historian.** The 5-minute ring is for *live-watching*
  activity, not for post-hoc analysis. Scrape `/metrics` into
  Prometheus / VictoriaMetrics / Grafana if you want a historical
  record.
- **No authentication UI.** The admin token is a single static value.
  The server's JWT path exists; the GUI only speaks admin auth today.

## Troubleshooting

### The window doesn't open

The most common cause is a shell that doesn't have your session's
display env vars. SSH'd shells and some dev-tool environments inherit
an empty `WAYLAND_DISPLAY`, which winit treats as "Wayland configured
but unreachable" and the GUI hangs silently.

Check from the same shell you're launching the GUI in:

```sh
env | grep -E 'WAYLAND_DISPLAY|DISPLAY|XDG_RUNTIME_DIR'
```

Good output looks like:

```
WAYLAND_DISPLAY=wayland-0
DISPLAY=:0
XDG_RUNTIME_DIR=/run/user/1000
```

If `WAYLAND_DISPLAY` is empty or unset on a Wayland session, export it
explicitly:

```sh
export WAYLAND_DISPLAY=wayland-0
export XDG_RUNTIME_DIR=/run/user/$(id -u)
```

The socket path is `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`. Verify it
exists:

```sh
ls -l $XDG_RUNTIME_DIR/wayland-0
# should be: srwxrwxr-x ... wayland-0
```

If you're reaching the machine from a different host (SSH, a remote
editor, etc.) and your compositor is on that other host — the GUI
running on *this* machine can't reach it. Either run the GUI on your
local machine and point `--url` at the remote server, or set up
X11-forwarding (`ssh -X`) and run the GUI over that.

### "connecting…" never becomes "polled Ns ago"

The server isn't reachable at the URL, or the admin token is wrong.
The top-right red text shows the underlying ureq/JSON error. Common
causes:

- wrong port (`--url http://127.0.0.1:8787` if the server is on its
  default bind)
- admin token mismatch — the token the GUI presents must match the
  server's `ARTIFACTS_ADMIN_TOKEN`
- server refused to start because `--bind` wasn't loopback and
  `--public-base-url` wasn't `https://` — see the server's log for
  `refusing to start`

### Percentiles show 0.00 ms

No request-duration observations yet. Make a few REST calls:

```sh
TOK=dyspel-dev-shared
for _ in $(seq 1 5); do
    curl -fsS -o /dev/null http://127.0.0.1:8787/v1/health
    curl -fsS -o /dev/null -H "Authorization: Bearer $TOK" \
        http://127.0.0.1:8787/v1/admin/repos
done
```

Within one poll cycle the percentiles populate.

### Charts say "(collecting samples…)"

At least two polls are needed to compute a rate. If you just launched,
wait ~4 seconds (two poll cycles) and the lines appear.

## Polling cadence

Defaults to 2 seconds between polls. Tweak with `--poll-interval-secs`.
Polls are independent of window repaint — the background thread
updates shared state, egui repaints every 500 ms and reads the
latest. A slow server response doesn't block the UI; the last-poll
label in the top bar shows how stale the view is, and a red error
string surfaces if polling fails.

The time-series window keeps the last ~5 minutes of samples. At the
default 2-s interval that's ~150 points — cheap to render, enough
resolution to see a spike.

## File pointer

Single binary, single file: [src/bin/artifacts-gui.rs](./src/bin/artifacts-gui.rs).
No separate crate, no build config beyond the feature flag. Modifying
the GUI means editing that one file.
