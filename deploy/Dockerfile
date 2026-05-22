# Multi-stage Dockerfile for the Artifacts prototype.
#
# Build:  docker build -f deploy/Dockerfile -t artifacts .
# Run:    docker run --rm -p 8787:8787 -v artifacts-data:/var/lib/artifacts \
#             -e ARTIFACTS_ADMIN_TOKEN=… artifacts
#
# The final image is debian-slim (not distroless) because the server
# shells out to `git upload-pack` / `git receive-pack` (and a handful of
# plumbing commands) — distroless ships no git binary, and copying git
# + every libc / libpcre / libcurl dep out of a builder stage is more
# fragile than just `apt install git`. The image is ~120 MB; git itself
# is ~25 MB of that.

# -----------------------------------------------------------------------------
# Stage 1 — builder.
# -----------------------------------------------------------------------------
# rust-toolchain.toml at the repo root pins 1.88. Match it here so the
# builder image doesn't pull a newer toolchain on every build (which
# would also defeat layer caching).
FROM rust:1.88-slim-bookworm AS builder

# rusqlite vendors sqlite via `bundled` so we don't need libsqlite3-dev.
# We still want a C compiler + pkg-config + libssl-dev for transitive
# C-FFI crates (gix-features and friends sometimes pull libz; bundling
# the toolchain is cheaper than debugging missing-symbol surprises in
# CI).
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests first so dependency-only layers can cache across code
# edits. A `cargo fetch` here primes the registry index inside the
# layer; the subsequent `cargo build` then only re-fetches when
# Cargo.lock actually changed.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src/ ./src/

# Release build. `--locked` enforces that Cargo.lock matches the
# manifest's resolution — fail-loud if the image build sees a different
# lockfile than the one CI green-lit.
RUN cargo build --release --locked --bin artifacts \
    && strip target/release/artifacts

# -----------------------------------------------------------------------------
# Stage 2 — runtime.
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Runtime deps:
#   git           — server shells out to upload-pack / receive-pack
#                   and a few plumbing commands (REST commits, GC).
#   ca-certificates — webhook deliveries via ureq + TLS need a CA bundle.
#   tini          — PID 1 reaper. The server spawns short-lived `git`
#                   subprocesses per request; without a proper reaper
#                   their zombies pile up.
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends \
        git ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

# Non-root user. UID 10001 matches the k8s manifests' runAsUser so
# volume permissions line up out of the box.
RUN groupadd --system --gid 10001 artifacts \
    && useradd  --system --uid 10001 --gid artifacts \
        --home-dir /var/lib/artifacts --shell /usr/sbin/nologin \
        artifacts

# Data dir is intentionally a separate path from the binary so it can
# be mounted as a volume without overriding /usr/local/bin contents.
RUN install -d -m 0700 -o artifacts -g artifacts /var/lib/artifacts

COPY --from=builder /build/target/release/artifacts /usr/local/bin/artifacts

USER artifacts
WORKDIR /var/lib/artifacts

# Defaults assume the operator mounts a volume on /var/lib/artifacts
# and forwards an external port to 8787. `--public-base-url` MUST be
# overridden in production (the server uses it to build the `remote`
# URL it hands back in repo-create responses).
EXPOSE 8787
VOLUME ["/var/lib/artifacts"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/artifacts"]
CMD ["serve", \
     "--data-dir", "/var/lib/artifacts", \
     "--bind", "0.0.0.0:8787", \
     "--public-base-url", "http://localhost:8787"]
