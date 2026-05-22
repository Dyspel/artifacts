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

## Why single-replica

The M0 server holds its state in a single data dir: bare git repos
under `repos/` + three SQLite databases (`tokens.db`, `audit.db`,
`webhooks.db`). Two replicas pointed at the same RWO volume race for
the SQLite write lock; two replicas pointed at separate volumes
diverge immediately. Horizontal scale is genuinely a future milestone
(M3b distributed RefStore + M2b chunked-KV Storage), not a config knob.

The Deployment uses `strategy: Recreate` so a rollout doesn't deadlock
against itself trying to attach the same RWO volume to two pods.

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
