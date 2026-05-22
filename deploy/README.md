# Deploy

Production-leaning runtime artifacts for the Artifacts server.

| File | Purpose |
| ---- | ------- |
| [`Dockerfile`](Dockerfile) | Multi-stage build → debian-slim runtime image with the `git` binary on PATH. |
| [`.dockerignore`](.dockerignore) | Keeps the build context lean — only Cargo.* + src/ + rust-toolchain.toml reach the builder. |
| [`systemd/artifacts.service`](systemd/artifacts.service) | Hardened systemd unit (NoNewPrivileges, ProtectSystem=strict, SystemCallFilter, …). |
| [`systemd/artifacts.env`](systemd/artifacts.env) | EnvironmentFile template — secrets + tunables. |
| [`k8s/deployment.yaml`](k8s/deployment.yaml) | Single-replica Deployment with readiness + liveness probes pinned to the right semantics. |
| [`k8s/service.yaml`](k8s/service.yaml) | ClusterIP Service. Front with an Ingress for TLS / hostname routing. |
| [`k8s/pvc.yaml`](k8s/pvc.yaml) | RWO PersistentVolumeClaim for the data dir. |
| [`k8s/secrets.example.yaml`](k8s/secrets.example.yaml) | Template Secret — admin token + JWT secret + (optional) webhook master key. |
| [`observability/dashboard.json`](observability/dashboard.json) | Starter Grafana dashboard — request rate, latency p50/p95/p99, rate-limit/quota rejections, SQLite pool, audit-event rate, gauges. Import via Grafana → Dashboards → New → Import. |
| [`observability/alerts.yml`](observability/alerts.yml) | Prometheus alertmanager rules — p99 SLO violations, sustained 429s, pool exhaustion, server-down, audit-write-failures. |

## Why single-replica

The M0 server holds its state in a single data dir: bare git repos
under `repos/` + three SQLite databases (`tokens.db`, `audit.db`,
`webhooks.db`). Two replicas pointed at the same RWO volume race for
the SQLite write lock; two replicas pointed at separate volumes
diverge immediately. Horizontal scale is genuinely a future milestone
(M3b distributed RefStore + M2b chunked-KV Storage), not a config knob.

The Deployment uses `strategy: Recreate` so a rollout doesn't deadlock
against itself trying to attach the same RWO volume to two pods.

## Distributed tracing (optional)

The server speaks OTLP/gRPC when `--otlp-endpoint <url>` (or
`ARTIFACTS_OTLP_ENDPOINT`) is set. Per-request spans — the same
ones rendered to stderr by the fmt layer — get batched out to the
configured collector. Default off; nothing is sent if the flag is
unset.

```sh
# Direct to a Jaeger / Tempo / Honeycomb collector:
artifacts serve --otlp-endpoint http://otel-collector.observability:4317 …
```

The exporter is the batched-tonic build (gRPC, protobuf). Service
identity is `service.name=artifacts`, `service.version=<cargo pkg
version>`. `RUST_LOG` controls both fmt and OTLP outputs uniformly —
spans you see on stderr are exactly the spans the collector receives.

Failure modes (collector unreachable, bad endpoint, gRPC errors) log
to stderr and drop the affected batch; the server keeps running. A
remote-tracing misconfig will never take down the data plane.

## Dashboards + alerts

[`observability/dashboard.json`](observability/dashboard.json) is a
starter Grafana dashboard targeting the metrics the server already
emits — request rate by status, latency percentiles, the rate-limit
/ quota counters, the per-store `r2d2_sqlite` pool gauges, the
audit-event-by-kind rate, and the active-tokens / active-repos /
active-webhooks / audit-rows stat panels. Import via **Grafana →
Dashboards → New → Import**, point it at your Prometheus datasource
when prompted. The dashboard uses a `${DS_PROMETHEUS}` variable so
the same JSON works against any Prometheus-compatible source.

[`observability/alerts.yml`](observability/alerts.yml) is a
Prometheus alertmanager rule file. Drop it into your `rule_files:`
list. Alerts:
- **ArtifactsP99LatencyHigh / Critical** — p99 > 1s for 5m
  (warning) or > 5s for 2m (critical).
- **ArtifactsRateLimitedSustained / QuotaExceededSustained** —
  abuse pattern or under-provisioned bucket.
- **ArtifactsSqlitePoolExhausted** — pool ≥90% saturated for 3m
  on any store. The right response is bumping
  `db_migrate::DEFAULT_POOL_SIZE`.
- **ArtifactsDown** — `absent(artifacts_build_info)` for 1m;
  catches crashloops and misconfigured scrape targets.
- **ArtifactsAuditWriteFailures** — audit events flat despite live
  mutation traffic; the audit writer is best-effort, this catches
  the "silently stopped persisting" case before it becomes a
  compliance problem.

`for:` durations are the recommended starting points — tune to your
traffic shape (lengthen to silence brief blips, shorten to catch
faster regressions) rather than touching the threshold expressions.

## What still needs operator decisions

- **`ARTIFACTS_PUBLIC_BASE_URL`**: the URL the server stitches into
  repo-create responses. Must be the externally-reachable address (the
  one a `git clone` from a developer laptop can resolve), not the
  in-cluster Service DNS.
- **TLS**: the Deployment runs plain HTTP and expects an Ingress in
  front. Or pass `--tls-cert` / `--tls-key` to terminate inside the
  process via rustls.
- **`ARTIFACTS_WEBHOOK_KEY`**: leave unset for dev and the server
  auto-generates one into the data dir. In production, pin it in the
  Secret so a pod restart doesn't lose access to encrypted webhook
  secrets.
- **PVC size**: the default 20 GiB fits a few thousand small repos.
  Bump for heavier workloads — git's pack files are the dominant
  cost, SQLite DBs stay tiny.
