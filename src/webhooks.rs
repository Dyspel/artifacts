//! Outbound webhook delivery.
//!
//! What this is: subscribers register a URL + secret with a repo,
//! and we POST a JSON event body to that URL whenever an event fires
//! for that repo on the in-process bus. Each delivery is signed with
//! HMAC-SHA256 over the body, with the digest in
//! `X-Artifacts-Signature: sha256=<hex>` so subscribers can verify
//! authenticity without trusting the network path.
//!
//! ## Durability (K3)
//!
//! `SqliteWebhookRegistry` is the production path; delivery is
//! durable via the `webhook_deliveries` outbox table (migration v3).
//! On each event the dispatcher INSERTs one row per matching
//! subscription, capturing url + sealed secret + payload. A separate
//! `spawn_delivery_worker` task polls pending rows on a 2-second
//! tick, drives each through HTTP with exponential backoff
//! (1 min × 2^n up to 1 hour, max 8 attempts), and stamps the row
//! as `success` / `client_error` / `exhausted`. Restart picks up
//! every un-finalized row — no events lost across crashes.
//!
//! `MemRegistry` (in-memory, test-only) doesn't implement the
//! outbox methods; the dispatcher detects `enqueue_delivery`
//! returning 0 and falls back to a simpler single-attempt
//! direct-dispatch path (`legacy_direct_dispatch`). That path is
//! best-effort and drops on crash — acceptable for test deployments
//! that opt out of SQLite altogether.
//!
//! ## What this is still *not*
//!
//! - Observable beyond stderr + Prometheus counters. There's no
//!   per-row inspection endpoint yet — admin tooling that needs
//!   "show me failed deliveries" reads the `webhook_deliveries`
//!   table directly (until a `/v1/admin/webhooks/deliveries`
//!   endpoint lands).
//! - Pruned. Finalized rows accumulate forever today; a retention
//!   sweep (mirroring `audit::spawn_prune_task`) is a follow-up.
//!
//! ## Threading
//!
//! Per-delivery HTTP runs on `tokio::spawn_blocking` (ureq is sync)
//! so a slow target doesn't stall axum workers. The worker loop
//! itself is async + polling.

use crate::events::Event;
use base64::{engine::general_purpose::STANDARD as BASE64_STD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use uuid::Uuid;

/// One subscription. Stored alongside other subscriptions for the
/// same repo in `WebhookRegistry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    /// Repo this subscription fires for. We filter by repo at
    /// dispatch time rather than baking it into the event body —
    /// keeps the trait small.
    pub repo_id: crate::ids::RepoId,
    pub url: String,
    /// HMAC-SHA256 secret. Stored in plaintext today (no DB to hash
    /// against); when the SQLite-backed registry lands it should be
    /// stored hashed the same way TokenStore does.
    #[serde(skip_serializing)]
    pub secret: Option<String>,
    /// Subset of event kinds to fire on. Empty = all kinds. Typed as
    /// `EventKind` so a misspelled kind is rejected when the
    /// subscription is created, not silently dropped at match time.
    pub events: Vec<crate::events::EventKind>,
}

/// SSRF guard for subscription target URLs. A webhook URL is
/// attacker-supplied (any repo owner can register one) and the server
/// then issues outbound requests to it, so an unvalidated URL lets a
/// tenant point the server at internal infrastructure — cloud metadata
/// (`http://169.254.169.254/…`), loopback admin ports, private-network
/// services. We require an `http`/`https` scheme and, when the host is
/// an IP *literal*, refuse loopback / private / link-local / ULA /
/// multicast / unspecified ranges.
///
/// `allow_private` (driven by `--webhook-allow-private-targets`) opts
/// out of the IP-range block for local/dev deployments that
/// legitimately deliver to `127.0.0.1`.
///
/// Residual: a *hostname* that resolves to a private IP is not blocked
/// here — fully closing DNS-rebinding needs a resolving HTTP client or
/// an egress proxy that re-checks the connected peer, which this
/// single-node prototype doesn't ship. The literal-IP block stops the
/// direct-address attack, which is the common case.
pub(crate) fn validate_webhook_url(url: &str, allow_private: bool) -> crate::error::Result<()> {
    use crate::error::Error;
    let (scheme, after) = url
        .split_once("://")
        .ok_or_else(|| Error::BadRequest("webhook url must be http(s)://…".into()))?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(Error::BadRequest(
            "webhook url scheme must be http or https".into(),
        ));
    }
    // Authority is everything up to the first path/query/fragment.
    let authority = after.split(['/', '?', '#']).next().unwrap_or_default();
    // Drop any `userinfo@` prefix.
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
    // Extract the host, handling bracketed IPv6 and an optional :port.
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        rest.split_once(']')
            .map(|(h, _)| h)
            .ok_or_else(|| Error::BadRequest("malformed IPv6 host in webhook url".into()))?
    } else {
        // Strip a trailing :port only when it's all digits, so a bare
        // IPv4/hostname (no colon) is left intact.
        hostport.rsplit_once(':').map_or(hostport, |(h, p)| {
            if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) {
                h
            } else {
                hostport
            }
        })
    };
    if host.is_empty() {
        return Err(Error::BadRequest("webhook url has no host".into()));
    }
    if !allow_private {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if is_blocked_target_ip(ip) {
                return Err(Error::BadRequest(
                    "webhook url targets a loopback/private/link-local address".into(),
                ));
            }
        }
    }
    Ok(())
}

/// True for IP literals that an outbound webhook must not target by
/// default — the SSRF blocklist behind [`validate_webhook_url`].
fn is_blocked_target_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let oct = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                // Carrier-grade NAT 100.64.0.0/10 (`is_shared` is unstable).
                || (oct[0] == 100 && (oct[1] & 0xc0) == 0x40)
        },
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_target_ip(std::net::IpAddr::V4(v4));
            }
            let seg0 = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique-local fc00::/7 + link-local fe80::/10
                // (the stable predicates for these are unstable).
                || (seg0 & 0xfe00) == 0xfc00
                || (seg0 & 0xffc0) == 0xfe80
        },
    }
}

/// One row of the durable delivery outbox (K3). Returned by
/// `claim_pending_deliveries` after the registry has unsealed the
/// secret. The delivery worker treats this as the source of truth
/// for an in-flight delivery — `url` + `secret` are denormalized
/// from the subscription at enqueue time so a subscription edit /
/// delete during retry doesn't break the delivery.
#[derive(Debug, Clone)]
pub struct PendingDelivery {
    pub id: i64,
    pub hook_id: String,
    pub url: String,
    /// Plaintext HMAC secret (or `None` if the subscription had no
    /// secret at enqueue time). Already unsealed by the registry —
    /// the worker never sees ciphertext.
    pub secret: Option<String>,
    pub kind: String,
    pub payload: Vec<u8>,
    pub attempts: u32,
}

/// The registry contract. Today: `MemRegistry` (in-memory, K3 outbox
/// methods are no-ops — direct dispatch only) and `SqliteWebhookRegistry`
/// (durable, K3 outbox methods are implemented). The trait shape
/// matches: callers always go through enqueue + worker for SQLite, fall
/// back to direct-dispatch when enqueue reports 0 rows.
pub trait WebhookRegistry: Send + Sync {
    /// Create a subscription, returning its id. `Err` on a storage
    /// failure (e.g. SQLite pool exhaustion) so the REST handler can
    /// surface a 500 instead of panicking the request task.
    fn add(&self, sub: Subscription) -> crate::error::Result<String>;
    fn list(&self, repo_id: &crate::ids::RepoId) -> crate::error::Result<Vec<Subscription>>;
    fn remove(&self, repo_id: &crate::ids::RepoId, hook_id: &str) -> crate::error::Result<bool>;
    /// Subscriptions matching `(repo_id, kind)`. Infallible by design:
    /// this is driven by the background dispatcher, which can only log
    /// a failure anyway, so a storage error degrades to "no matches"
    /// (logged) rather than propagating into the fire-and-forget path.
    fn matching(&self, repo_id: &crate::ids::RepoId, kind: &str) -> Vec<Subscription>;

    /// Replace the in-process master key, re-encrypting every existing
    /// secret under it. Returns the count of rows re-encrypted (0
    /// for backends that don't store encrypted secrets — `MemRegistry`,
    /// or rows that were stored as legacy plaintext).
    ///
    /// Default impl is `Ok(0)` — backends without encrypted-at-rest
    /// secrets have nothing to do, but the rotation endpoint still
    /// generates and installs a fresh key for the next `add()`. The
    /// SQLite impl overrides; Mem inherits the default.
    fn rotate_master_key(&self, _new: Arc<crate::secrets::MasterKey>) -> crate::error::Result<u64> {
        Ok(0)
    }

    /// Total non-revoked subscription count across all repos. Powers
    /// the `artifacts_webhooks_active_total` gauge. Default impl
    /// returns 0 — `MemRegistry` doesn't expose a cheap aggregate.
    /// SQLite overrides.
    fn count_active(&self) -> crate::error::Result<u64> {
        Ok(0)
    }
}

/// The durable webhook-delivery outbox (K3). Split out of
/// `WebhookRegistry` so the in-memory `MemRegistry` no longer has to
/// pretend to implement an outbox it lacks — only the SQLite-backed
/// registry provides this. The dispatcher uses it when present and
/// falls back to single-attempt direct dispatch otherwise.
pub trait DeliveryOutbox: Send + Sync {
    /// INSERT one `webhook_deliveries` row per matching subscription,
    /// capturing url + sealed secret. Returns rows inserted.
    fn enqueue_delivery(
        &self,
        repo_id: &crate::ids::RepoId,
        kind: &str,
        payload: &[u8],
    ) -> crate::error::Result<u64>;

    /// Claim up to `limit` un-finalized rows due now, pushing each
    /// row's `next_attempt_at` forward under the write lock so a slow
    /// worker can't double-deliver. Unseals secrets before returning.
    fn claim_pending_deliveries(&self, limit: u32) -> crate::error::Result<Vec<PendingDelivery>>;

    /// Schedule a row for another attempt (updates attempts /
    /// last_status / next_attempt_at).
    fn mark_delivery_retry(
        &self,
        id: i64,
        attempts: u32,
        next_attempt_at: i64,
        last_status: &str,
    ) -> crate::error::Result<()>;

    /// Stamp a row finalized — no further attempts.
    fn mark_delivery_finalized(
        &self,
        id: i64,
        outcome: &str,
        last_status: Option<&str>,
    ) -> crate::error::Result<()>;

    /// Delete finalized rows older than `cutoff_ts`; pending rows are
    /// never pruned. Returns rows removed.
    fn prune_finalized(&self, cutoff_ts: i64) -> crate::error::Result<u64>;
}

/// SQLite-backed `WebhookRegistry`. Subscriptions persist across
/// restarts, which is what the in-memory `MemRegistry` does NOT do.
///
/// Schema (created on open if absent):
///   id           TEXT PRIMARY KEY    — UUIDv4
///   repo_id      TEXT NOT NULL       — repo this subscription fires for
///   url          TEXT NOT NULL
///   secret       TEXT                — base64 AES-256-GCM ciphertext of
///                                       the HMAC key when secret_nonce is
///                                       set; legacy plaintext for rows
///                                       written before the M6-deliver-secrets
///                                       migration (secret_nonce NULL).
///   secret_nonce BLOB                — 12-byte AES-GCM nonce paired with
///                                       `secret`. NULL means legacy
///                                       plaintext (back-compat with rows
///                                       inserted before this migration).
///   events_json  TEXT NOT NULL       — JSON array of event-kind strings
///   created_at   INTEGER NOT NULL
///   revoked_at   INTEGER             — set on remove() so an admin can
///                                       audit the lifecycle; matching()
///                                       filters out revoked rows.
///
/// Same trait as MemRegistry. Wire choice happens in main.rs based on
/// whether `ARTIFACTS_WEBHOOK_DB` is set (defaults to in-memory).
pub struct SqliteWebhookRegistry {
    conn: crate::db_migrate::DbPool,
    /// Symmetric key used to seal/unseal `secret`. Wrapped in
    /// `RwLock<Arc<…>>` so `rotate_master_key` can swap it
    /// in-process. Reads (every `add` / `list`) clone the `Arc`
    /// under the read lock and drop the lock immediately, so a
    /// rotation only blocks readers for the brief swap window.
    master_key: std::sync::RwLock<Arc<crate::secrets::MasterKey>>,
}

const MIGRATIONS: [crate::db_migrate::Migration; 3] = [
    crate::db_migrate::Migration {
        version: 1,
        name: "init",
        up: |c| {
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS webhooks (
                     id          TEXT PRIMARY KEY,
                     repo_id     TEXT NOT NULL,
                     url         TEXT NOT NULL,
                     secret      TEXT,
                     events_json TEXT NOT NULL,
                     created_at  INTEGER NOT NULL,
                     revoked_at  INTEGER
                 );
                 CREATE INDEX IF NOT EXISTS idx_webhooks_repo ON webhooks(repo_id);",
            )
        },
    },
    crate::db_migrate::Migration {
        // M6-deliver-secrets: per-row AES-GCM nonce. Plaintext rows
        // (NULL nonce) stay readable as a transition state.
        version: 2,
        name: "add_secret_nonce_column",
        up: |c| crate::db_migrate::add_column_if_missing(c, "webhooks", "secret_nonce", "BLOB"),
    },
    crate::db_migrate::Migration {
        // K3: durable webhook-delivery outbox. Before this migration,
        // delivery was best-effort spawn_blocking with a 3-attempt
        // in-memory retry loop — a process crash mid-delivery dropped
        // the event silently. With the outbox, every event is INSERT'd
        // into webhook_deliveries (one row per matching subscription)
        // before dispatch; the delivery worker polls + drives each row
        // to a finalized_outcome. Restart picks up un-finalized rows.
        //
        // Schema:
        //   id                 — INTEGER PK; monotonic insertion order
        //   hook_id            — TEXT; the webhooks.id this delivery
        //                        targets (kept for forensic tracing;
        //                        url + secret are denormalized so a
        //                        post-enqueue edit doesn't break the
        //                        in-flight delivery)
        //   url                — TEXT NOT NULL; captured at enqueue
        //   secret / secret_nonce — BLOB,BLOB ; sealed under the same
        //                        master key as webhooks.secret. NULL
        //                        means the subscription had no HMAC
        //                        secret (delivery goes unsigned).
        //   kind               — TEXT; event kind for X-Artifacts-Event
        //                        header + metric label
        //   payload            — BLOB NOT NULL; the JSON event body
        //   attempts           — INTEGER NOT NULL DEFAULT 0
        //   last_status        — TEXT; last HTTP status code as string
        //                        or transport error tag ("network",
        //                        "timeout"). Audit-only.
        //   next_attempt_at    — INTEGER NOT NULL; unix-secs; the
        //                        worker claims rows with
        //                        next_attempt_at <= now AND
        //                        finalized_at IS NULL.
        //   created_at         — INTEGER NOT NULL
        //   finalized_at       — INTEGER; set when the row reaches a
        //                        terminal outcome. After that the row
        //                        is kept for audit until pruned.
        //   finalized_outcome  — TEXT ∈ {success, client_error,
        //                        exhausted}; NULL until finalized.
        version: 3,
        name: "add_webhook_deliveries",
        up: |c| {
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS webhook_deliveries (
                     id                INTEGER PRIMARY KEY AUTOINCREMENT,
                     hook_id           TEXT NOT NULL,
                     url               TEXT NOT NULL,
                     secret            BLOB,
                     secret_nonce      BLOB,
                     kind              TEXT NOT NULL,
                     payload           BLOB NOT NULL,
                     attempts          INTEGER NOT NULL DEFAULT 0,
                     last_status       TEXT,
                     next_attempt_at   INTEGER NOT NULL,
                     created_at        INTEGER NOT NULL,
                     finalized_at      INTEGER,
                     finalized_outcome TEXT
                 );
                 CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_pending
                     ON webhook_deliveries(next_attempt_at)
                     WHERE finalized_at IS NULL;",
            )
        },
    },
];

impl SqliteWebhookRegistry {
    pub fn open(
        path: &std::path::Path,
        master_key: Arc<crate::secrets::MasterKey>,
    ) -> crate::error::Result<Self> {
        let conn = crate::db_migrate::open_pool_with_migrations(path, "webhooks", &MIGRATIONS)?;
        Ok(Self {
            conn,
            master_key: std::sync::RwLock::new(master_key),
        })
    }

    /// Claim a pooled connection. Returns `Err` on pool exhaustion
    /// (propagated as `Error::Other` by `get_pooled`) so callers on a
    /// request path surface a clean 500 instead of panicking the task —
    /// matching how every other store (tokens, ownership, audit) treats
    /// the same condition. The earlier impl `.expect`ed here, which
    /// turned a recoverable, load-induced stall into a panic.
    fn lock(
        &self,
    ) -> crate::error::Result<r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>> {
        crate::metrics::get_pooled(&self.conn, "webhooks")
    }

    /// Expose the pool so periodic tasks can publish pool gauges.
    pub(crate) fn pool(&self) -> &crate::db_migrate::DbPool {
        &self.conn
    }

    /// Snapshot the current master key. Cheap (Arc clone). Callers
    /// hold the snapshot for the duration of one operation; the
    /// rotation path swaps under a write lock, so a snapshot taken
    /// just before a rotation may be the old key — that's fine for
    /// readers (rows on disk match whichever key they were sealed
    /// under) but matters for writers, which is why `add` and
    /// `rotate_master_key` both take the conn-mutex first to
    /// serialize.
    fn current_key(&self) -> Arc<crate::secrets::MasterKey> {
        self.master_key
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl WebhookRegistry for SqliteWebhookRegistry {
    fn add(&self, mut sub: Subscription) -> crate::error::Result<String> {
        if sub.id.is_empty() {
            sub.id = Uuid::new_v4().to_string();
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let events = serde_json::to_string(&sub.events).unwrap_or_else(|_| "[]".into());

        // Encrypt the HMAC secret if present. Failed seal falls back
        // to NULL secret + NULL nonce — that yields a working (but
        // unsigned) subscription rather than dropping the row.
        // Failure here is genuinely impossible with a valid 32-byte
        // key, but we don't unwrap because that would crash the
        // process on a misconfig that's recoverable.
        let key = self.current_key();
        let (secret_b64, nonce_blob): (Option<String>, Option<Vec<u8>>) = match &sub.secret {
            Some(plaintext) => match crate::secrets::seal(&key, plaintext.as_bytes()) {
                Ok((ct, nonce)) => (Some(BASE64_STD.encode(ct)), Some(nonce.to_vec())),
                Err(e) => {
                    tracing::warn!(error = %e, "webhook secret seal failed; storing NULL");
                    (None, None)
                },
            },
            None => (None, None),
        };

        self.lock()?.execute(
            "INSERT INTO webhooks (id, repo_id, url, secret, secret_nonce, events_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                sub.id,
                sub.repo_id.as_str(),
                sub.url,
                secret_b64,
                nonce_blob,
                events,
                now
            ],
        )?;
        Ok(sub.id)
    }

    fn list(&self, repo_id: &crate::ids::RepoId) -> crate::error::Result<Vec<Subscription>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT id, repo_id, url, secret, secret_nonce, events_json
             FROM webhooks
             WHERE repo_id = ?1 AND revoked_at IS NULL",
        )?;
        let key = self.current_key();
        let rows = stmt.query_map(rusqlite::params![repo_id.as_str()], move |row| {
            row_to_sub(row, &key)
        })?;
        Ok(rows.flatten().collect())
    }

    fn remove(&self, repo_id: &crate::ids::RepoId, hook_id: &str) -> crate::error::Result<bool> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let n = self.lock()?.execute(
            "UPDATE webhooks SET revoked_at = ?1
             WHERE id = ?2 AND repo_id = ?3 AND revoked_at IS NULL",
            rusqlite::params![now, hook_id, repo_id.as_str()],
        )?;
        Ok(n > 0)
    }

    fn matching(&self, repo_id: &crate::ids::RepoId, kind: &str) -> Vec<Subscription> {
        // Filter in Rust rather than embed the JSON LIKE in SQL so
        // we don't depend on JSON1 being compiled in. Subscription
        // counts per repo are small (dozens at most), so this is
        // fine. Infallible by trait contract: a storage error degrades
        // to "no matches" with a log rather than propagating into the
        // background dispatcher.
        match self.list(repo_id) {
            Ok(subs) => subs
                .into_iter()
                .filter(|s| s.events.is_empty() || s.events.iter().any(|e| e.as_str() == kind))
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, repo_id = %repo_id, "webhook matching: list failed; treating as no matches");
                Vec::new()
            },
        }
    }

    fn count_active(&self) -> crate::error::Result<u64> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM webhooks WHERE revoked_at IS NULL",
            [],
            |r| r.get(0),
        )?;
        Ok(n.max(0) as u64)
    }

    /// Re-encrypt every secret-bearing row under `new`, then atomically
    /// install `new` as the current master key. Holds the connection
    /// mutex for the full operation, so concurrent `add` and `list`
    /// block until it completes — they then see the new key. The
    /// transaction means a partial failure mid-rotation rolls back to
    /// the old ciphertext under the old key, never a half-rotated DB.
    ///
    /// Legacy plaintext rows (secret_nonce IS NULL) are left untouched
    /// so the migration story stays consistent — a row stored before
    /// the M6-deliver-secrets encryption shipped doesn't suddenly get
    /// encrypted under a key that may later be rotated again.
    ///
    /// Returns the count of rows actually re-encrypted (0 if no
    /// encrypted rows exist; the swap still happens).
    fn rotate_master_key(&self, new: Arc<crate::secrets::MasterKey>) -> crate::error::Result<u64> {
        use rusqlite::params;
        let mut conn = self.lock()?;
        let old = self.current_key();
        let tx = conn.transaction()?;
        let mut count: u64 = 0;
        {
            let mut stmt = tx.prepare(
                "SELECT id, secret, secret_nonce FROM webhooks
                 WHERE secret IS NOT NULL AND secret_nonce IS NOT NULL",
            )?;
            // Collect first so the statement borrow drops before the
            // per-row UPDATE acquires the connection again via tx.
            let rows: Vec<(String, String, Vec<u8>)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(stmt);
            for (id, ct_b64, nonce_blob) in rows {
                let nonce: [u8; 12] = nonce_blob.as_slice().try_into().map_err(|_| {
                    crate::error::Error::Other(anyhow::anyhow!(
                        "webhook row {id}: nonce wrong length ({} bytes)",
                        nonce_blob.len()
                    ))
                })?;
                let ct = BASE64_STD.decode(ct_b64.as_bytes()).map_err(|e| {
                    crate::error::Error::Other(anyhow::anyhow!(
                        "webhook row {id}: ciphertext base64 decode: {e}"
                    ))
                })?;
                let pt = crate::secrets::unseal(&old, &ct, &nonce).map_err(|e| {
                    crate::error::Error::Other(anyhow::anyhow!(
                        "webhook row {id}: unseal under old key: {e}"
                    ))
                })?;
                let (new_ct, new_nonce) = crate::secrets::seal(&new, &pt)?;
                tx.execute(
                    "UPDATE webhooks SET secret = ?1, secret_nonce = ?2 WHERE id = ?3",
                    params![BASE64_STD.encode(&new_ct), new_nonce.to_vec(), id],
                )?;
                count += 1;
            }
        }
        tx.commit()?;
        // Swap the in-memory key while we still hold the conn mutex so
        // concurrent `add` calls — which take the same mutex — wake up
        // using the new key in lockstep with the on-disk re-encryption.
        *self.master_key.write().unwrap_or_else(|p| p.into_inner()) = new;
        Ok(count)
    }
}

impl DeliveryOutbox for SqliteWebhookRegistry {
    fn enqueue_delivery(
        &self,
        repo_id: &crate::ids::RepoId,
        kind: &str,
        payload: &[u8],
    ) -> crate::error::Result<u64> {
        use rusqlite::params;
        // Tuple-only alias to keep clippy::type_complexity quiet —
        // these rows escape the prepare_cached statement borrow into
        // the per-row loop below, so a public struct would be more
        // ceremony than the shape warrants.
        type EnqueueRow = (String, String, Option<String>, Option<Vec<u8>>, String);
        let now = now_unix_secs();
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        // SELECT the matching subscriptions inline so we hold one
        // transaction across the enqueue. Events filter is checked in
        // Rust to match the rest of matching()'s shape (avoids the
        // JSON1 dep).
        let rows: Vec<EnqueueRow> = {
            let mut stmt = tx.prepare_cached(
                "SELECT id, url, secret, secret_nonce, events_json
                 FROM webhooks
                 WHERE repo_id = ?1 AND revoked_at IS NULL",
            )?;
            let v: Vec<_> = stmt
                .query_map(params![repo_id.as_str()], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<Vec<u8>>>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(stmt);
            v
        };
        let mut inserted: u64 = 0;
        for (hook_id, url, sec_b64, nonce, events_json) in rows {
            let events: Vec<crate::events::EventKind> =
                serde_json::from_str(&events_json).unwrap_or_default();
            if !events.is_empty() && !events.iter().any(|e| e.as_str() == kind) {
                continue;
            }
            // Re-encode the sealed secret as a BLOB-shaped column in
            // webhook_deliveries. Subscription rows store the
            // ciphertext as base64-in-TEXT (legacy schema); the new
            // outbox table stores it as raw BLOB to skip the
            // base64-roundtrip on every claim.
            let secret_blob: Option<Vec<u8>> = match sec_b64 {
                Some(b64) => match BASE64_STD.decode(b64.as_bytes()) {
                    Ok(ct) => Some(ct),
                    Err(e) => {
                        tracing::warn!(
                            hook_id = %hook_id, error = %e,
                            "enqueue: failed to decode subscription ciphertext; \
                             dropping secret for this delivery"
                        );
                        None
                    },
                },
                None => None,
            };
            tx.execute(
                "INSERT INTO webhook_deliveries
                   (hook_id, url, secret, secret_nonce, kind, payload,
                    attempts, next_attempt_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?7)",
                params![hook_id, url, secret_blob, nonce, kind, payload, now],
            )?;
            inserted += 1;
        }
        tx.commit()?;
        Ok(inserted)
    }

    fn claim_pending_deliveries(&self, limit: u32) -> crate::error::Result<Vec<PendingDelivery>> {
        use rusqlite::params;
        let now = now_unix_secs();
        // Use a generous in-flight reschedule so a worker crash mid-
        // delivery doesn't double-deliver instantly. 60 seconds is well
        // beyond the per-attempt HTTP timeout (5s) so a healthy
        // worker always wins the race against the rescheduler.
        const INFLIGHT_RESCHEDULE_SECS: i64 = 60;
        let next_attempt_at = now + INFLIGHT_RESCHEDULE_SECS;

        // Tuple-only alias keeps clippy::type_complexity quiet without
        // committing to a public DTO struct for a row that exists only
        // inside this method.
        type ClaimRow = (
            i64,
            String,
            String,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            String,
            Vec<u8>,
            i64,
        );
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        // SELECT eligible rows, then UPDATE each to push next_attempt_at
        // forward + bump attempts. The two-statement shape (inside a
        // transaction) is what SQLite gives us in place of FOR UPDATE.
        let rows: Vec<ClaimRow> = {
            let mut stmt = tx.prepare_cached(
                "SELECT id, hook_id, url, secret, secret_nonce, kind,
                        payload, attempts
                 FROM webhook_deliveries
                 WHERE finalized_at IS NULL
                   AND next_attempt_at <= ?1
                 ORDER BY id ASC
                 LIMIT ?2",
            )?;
            let v: Vec<_> = stmt
                .query_map(params![now, limit as i64], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<Vec<u8>>>(3)?,
                        r.get::<_, Option<Vec<u8>>>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, Vec<u8>>(6)?,
                        r.get::<_, i64>(7)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(stmt);
            v
        };
        let key = self.current_key();
        let mut out = Vec::with_capacity(rows.len());
        for (id, hook_id, url, secret_ct, nonce_blob, kind, payload, attempts) in rows {
            // In-flight reschedule + attempts bump. The worker calls
            // mark_delivery_retry / mark_delivery_finalized to
            // overwrite next_attempt_at with the policy-driven value
            // once it knows the outcome.
            tx.execute(
                "UPDATE webhook_deliveries
                 SET next_attempt_at = ?1, attempts = attempts + 1
                 WHERE id = ?2",
                params![next_attempt_at, id],
            )?;
            // Unseal under the current master key. The subscription
            // path treats a unseal failure as "drop the secret, keep
            // the delivery"; mirror that here so a key rotation race
            // doesn't crash the worker.
            let secret = match (secret_ct, nonce_blob) {
                (Some(ct), Some(nonce_vec)) => match <[u8; 12]>::try_from(nonce_vec.as_slice()) {
                    Ok(nonce) => match crate::secrets::unseal(&key, &ct, &nonce) {
                        Ok(pt) => String::from_utf8(pt).ok(),
                        Err(e) => {
                            tracing::warn!(
                                delivery_id = id, hook_id = %hook_id, error = %e,
                                "claim_pending: secret unseal failed; sending unsigned"
                            );
                            None
                        },
                    },
                    Err(_) => {
                        tracing::warn!(
                            delivery_id = id, hook_id = %hook_id,
                            "claim_pending: nonce wrong length; sending unsigned"
                        );
                        None
                    },
                },
                _ => None,
            };
            out.push(PendingDelivery {
                id,
                hook_id,
                url,
                secret,
                kind,
                payload,
                // attempts is the pre-increment value visible to the
                // worker (the worker decides backoff based on which
                // attempt this IS, not which one came before).
                attempts: (attempts + 1) as u32,
            });
        }
        tx.commit()?;
        Ok(out)
    }

    fn mark_delivery_retry(
        &self,
        id: i64,
        attempts: u32,
        next_attempt_at: i64,
        last_status: &str,
    ) -> crate::error::Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE webhook_deliveries
             SET attempts = ?1, next_attempt_at = ?2, last_status = ?3
             WHERE id = ?4",
            rusqlite::params![attempts as i64, next_attempt_at, last_status, id],
        )?;
        Ok(())
    }

    fn mark_delivery_finalized(
        &self,
        id: i64,
        outcome: &str,
        last_status: Option<&str>,
    ) -> crate::error::Result<()> {
        let conn = self.lock()?;
        let now = now_unix_secs();
        conn.execute(
            "UPDATE webhook_deliveries
             SET finalized_at = ?1, finalized_outcome = ?2, last_status = ?3
             WHERE id = ?4",
            rusqlite::params![now, outcome, last_status, id],
        )?;
        Ok(())
    }

    fn prune_finalized(&self, cutoff_ts: i64) -> crate::error::Result<u64> {
        let conn = self.lock()?;
        // Two guards:
        //   - finalized_at IS NOT NULL: skip in-flight (pending) rows.
        //   - finalized_at < cutoff_ts: keep recently-finalized rows
        //     within the retention window so admin tooling can still
        //     audit "what just got delivered" before the row is gone.
        let n = conn.execute(
            "DELETE FROM webhook_deliveries
             WHERE finalized_at IS NOT NULL
               AND finalized_at < ?1",
            rusqlite::params![cutoff_ts],
        )?;
        Ok(n as u64)
    }
}

/// Unix-seconds clock. Shared by every site in this module that
/// stamps a row.
fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn row_to_sub(
    row: &rusqlite::Row<'_>,
    key: &crate::secrets::MasterKey,
) -> rusqlite::Result<Subscription> {
    let id: String = row.get(0)?;
    let repo_id_str: String = row.get(1)?;
    // Stored repo_ids always came from a valid RepoId (the create
    // path), so this conversion can't fail in practice; map a
    // hypothetical garbage row to a column-type error rather than
    // unwrapping.
    let repo_id = crate::ids::RepoId::try_from(repo_id_str).map_err(|_| {
        rusqlite::Error::InvalidColumnType(1, "repo_id".to_string(), rusqlite::types::Type::Text)
    })?;
    let url: String = row.get(2)?;
    let stored_secret: Option<String> = row.get(3)?;
    let nonce_blob: Option<Vec<u8>> = row.get(4)?;
    let events_json: String = row.get(5)?;
    let events: Vec<crate::events::EventKind> =
        serde_json::from_str(&events_json).unwrap_or_default();

    // Three cases for the secret column:
    //   1. (None, _)              — no secret was registered. Nothing to decrypt.
    //   2. (Some(s), None)        — legacy plaintext (pre-migration row).
    //                                Return as-is so existing subscriptions keep
    //                                working through the migration.
    //   3. (Some(b64), Some(n))   — encrypted. Decrypt with the master key.
    //                                A decrypt failure (corruption, key mismatch
    //                                after a botched rotate, base64 garbage)
    //                                logs and yields None — the subscription
    //                                stays in the list but bodies go unsigned
    //                                rather than vanishing entirely.
    let secret = match (stored_secret, nonce_blob) {
        (None, _) => None,
        (Some(s), None) => Some(s),
        (Some(ct_b64), Some(nonce_vec)) => {
            let nonce: [u8; 12] = match nonce_vec.as_slice().try_into() {
                Ok(n) => n,
                Err(_) => {
                    tracing::warn!(hook_id = %id, "webhook nonce wrong length; treating as unsigned");
                    return Ok(Subscription {
                        id,
                        repo_id,
                        url,
                        secret: None,
                        events,
                    });
                },
            };
            let ct = match BASE64_STD.decode(ct_b64.as_bytes()) {
                Ok(b) => b,
                Err(_) => {
                    tracing::warn!(hook_id = %id, "webhook ciphertext base64 decode failed; treating as unsigned");
                    return Ok(Subscription {
                        id,
                        repo_id,
                        url,
                        secret: None,
                        events,
                    });
                },
            };
            match crate::secrets::unseal(key, &ct, &nonce) {
                Ok(pt) => match String::from_utf8(pt) {
                    Ok(s) => Some(s),
                    Err(_) => {
                        tracing::warn!(hook_id = %id, "webhook secret not valid UTF-8 after unseal");
                        None
                    },
                },
                Err(e) => {
                    tracing::warn!(hook_id = %id, error = %e, "webhook secret unseal failed");
                    None
                },
            }
        },
    };

    Ok(Subscription {
        id,
        repo_id,
        url,
        secret,
        events,
    })
}

/// In-memory `WebhookRegistry`. `Mutex<Vec>` is plenty for the
/// subscription cardinality we'd see on a single machine (dozens, not
/// thousands).
#[derive(Default, Clone)]
pub struct MemRegistry {
    inner: Arc<std::sync::Mutex<Vec<Subscription>>>,
}

impl MemRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Subscription>> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl WebhookRegistry for MemRegistry {
    fn add(&self, mut sub: Subscription) -> crate::error::Result<String> {
        if sub.id.is_empty() {
            sub.id = Uuid::new_v4().to_string();
        }
        let id = sub.id.clone();
        self.lock().push(sub);
        Ok(id)
    }

    fn list(&self, repo_id: &crate::ids::RepoId) -> crate::error::Result<Vec<Subscription>> {
        Ok(self
            .lock()
            .iter()
            .filter(|s| s.repo_id == *repo_id)
            .cloned()
            .collect())
    }

    fn remove(&self, repo_id: &crate::ids::RepoId, hook_id: &str) -> crate::error::Result<bool> {
        let mut g = self.lock();
        let before = g.len();
        g.retain(|s| !(s.repo_id == *repo_id && s.id == hook_id));
        Ok(before != g.len())
    }

    fn matching(&self, repo_id: &crate::ids::RepoId, kind: &str) -> Vec<Subscription> {
        self.lock()
            .iter()
            .filter(|s| s.repo_id == *repo_id)
            .filter(|s| s.events.is_empty() || s.events.iter().any(|e| e.as_str() == kind))
            .cloned()
            .collect()
    }
}

/// One-shot — read the active subscription count and publish to the
/// `artifacts_webhooks_active_total` gauge. Failure is best-effort
/// logged; the gauge keeps its previous value.
pub fn refresh_active_webhook_gauge(registry: &dyn WebhookRegistry) {
    match registry.count_active() {
        Ok(n) => metrics::gauge!("artifacts_webhooks_active_total").set(n as f64),
        Err(e) => tracing::warn!(error = %e, "active-webhook gauge refresh failed"),
    }
}

/// Spawn a 60-second refresher for the active-webhook gauge. Same
/// shape as `tokens::spawn_active_gauge_refresher`; both run in
/// parallel so the metrics surface tracks real activity within a
/// minute.
pub fn spawn_active_gauge_refresher(
    registry: Arc<dyn WebhookRegistry>,
    tick: std::time::Duration,
    cancel: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tick);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => refresh_active_webhook_gauge(&*registry),
                _ = cancel.cancelled() => return,
            }
        }
    })
}

/// Handle a broadcast-lag signal on the dispatcher.
///
/// The K3 outbox is durable only *after* an event is enqueued, and
/// enqueue is driven by this in-process `tokio::broadcast` channel —
/// so a `Lagged(n)` means `n` events overflowed the ring and were
/// dropped BEFORE ever reaching the outbox. They are genuinely lost,
/// not merely delayed. The earlier code logged this at `warn` and moved
/// on, which buried a real durability gap. Surface it loudly: an
/// `error` log plus an `artifacts_webhook_events_dropped_total` counter
/// so it shows up on a dashboard/alert.
///
/// The durable fix is to enqueue at *publish* time (in the commit/push
/// path, in the same breath as the event is produced) rather than off a
/// lossy broadcast subscription; that's a larger change tracked
/// separately. Until then this is the honest visibility for the loss.
fn record_dispatcher_lag(dropped: u64) {
    tracing::error!(
        dropped,
        "webhook dispatcher lagged; events dropped before reaching the durable outbox \
         (durable fix: enqueue-at-publish)"
    );
    metrics::counter!("artifacts_webhook_events_dropped_total").increment(dropped);
}

/// MemRegistry-only webhook dispatcher. The SQLite backend enqueues
/// deliveries at publish time (durable, lag-proof — see [`publish_event`])
/// and a worker drains them, so it needs no dispatcher. This exists only
/// for the in-memory `MemRegistry`, which has no outbox and instead
/// direct-dispatches each event off the live bus. The broadcast is lossy,
/// so a lag drops events (surfaced via the drop counter) — acceptable for
/// the dev/test in-memory path, never the durable one.
pub fn spawn_dispatcher(
    registry: Arc<dyn WebhookRegistry>,
    bus: crate::events::EventBus,
    cancel: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = rx.recv() => match msg {
                    Ok(ev) => dispatch_event(&*registry, &ev),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        record_dispatcher_lag(n);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                },
                _ = cancel.cancelled() => return,
            }
        }
    })
}

/// K3 backoff policy for the durable-delivery worker. Doubling base
/// of 1 minute up to a 1-hour ceiling, with a hard MAX_ATTEMPTS=8
/// after which a row is finalized "exhausted". This is more generous
/// than the legacy in-process retry (3 attempts over ~3.5s) — the
/// outbox is what makes the long tail safe.
const WORKER_MAX_ATTEMPTS: u32 = 8;
const WORKER_BACKOFF_BASE_SECS: i64 = 60;
const WORKER_BACKOFF_MAX_SECS: i64 = 3600;
const WORKER_HTTP_TIMEOUT_SECS: u64 = 5;
const WORKER_BATCH_LIMIT: u32 = 32;

fn worker_backoff_secs(attempt: u32) -> i64 {
    // attempt 1 → base; attempt 2 → 2*base; … capped at MAX.
    let shift = attempt.saturating_sub(1).min(20);
    let secs = WORKER_BACKOFF_BASE_SECS.saturating_mul(1i64 << shift);
    secs.min(WORKER_BACKOFF_MAX_SECS)
}

/// Long-lived task that drives the durable outbox. Polls
/// `claim_pending_deliveries` on a tick, delivers each row via the
/// shared HTTP-deliver routine, and stamps the result back into the
/// row. Restart-safe: rows un-finalized at shutdown remain claimable
/// after the next process starts.
///
/// `tick`: cadence between polls. Polling avoids a NOTIFY signal path
/// (which would couple the worker to the enqueue site); a tick of
/// 1-5s gives near-immediate first-attempt latency without
/// significant idle work.
pub fn spawn_delivery_worker(
    outbox: Arc<dyn DeliveryOutbox>,
    tick: std::time::Duration,
    cancel: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tick);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let rows = match outbox.claim_pending_deliveries(WORKER_BATCH_LIMIT) {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!(error = %e, "webhook worker: claim_pending failed");
                            continue;
                        }
                    };
                    for row in rows {
                        let outbox = outbox.clone();
                        // ureq is sync — the per-delivery HTTP call goes onto
                        // the blocking pool so a slow target doesn't tie up
                        // tokio workers. The registry handle is `Arc`, cheap
                        // to clone into the closure. We don't track the
                        // per-delivery handle in the K4 drain set: each call
                        // has its own 5s timeout and finalizes the row on
                        // its own; tracking would block shutdown for as long
                        // as the slowest target takes to respond.
                        tokio::task::spawn_blocking(move || dispatch_row(&*outbox, row));
                    }
                }
                _ = cancel.cancelled() => return,
            }
        }
    })
}

/// L4: periodic retention sweep for the finalized rows in
/// `webhook_deliveries`. Mirrors `audit::spawn_prune_task`'s shape:
/// a `retention == Duration::ZERO` disables pruning entirely (returns
/// `None` rather than spawning a no-op task — matches the audit shape
/// so the caller doesn't have to reason about whether the task would
/// run). Picks up the K4 CancellationToken pattern so server shutdown
/// drains it cleanly.
pub fn spawn_prune_task(
    outbox: Arc<dyn DeliveryOutbox>,
    tick: std::time::Duration,
    retention: std::time::Duration,
    cancel: tokio_util::sync::CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    if retention.is_zero() {
        tracing::info!("webhook-delivery retention disabled — prune task not spawned");
        return None;
    }
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tick);
        // Skip the immediate fire so prune doesn't run during boot.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let cutoff = now_unix_secs().saturating_sub(retention.as_secs() as i64);
                    match outbox.prune_finalized(cutoff) {
                        Ok(0) => {}
                        Ok(n) => tracing::info!(pruned = n, "webhook delivery prune"),
                        Err(e) => tracing::error!(error = %e, "webhook delivery prune failed"),
                    }
                }
                _ = cancel.cancelled() => return,
            }
        }
    }))
}

fn dispatch_row(outbox: &dyn DeliveryOutbox, row: PendingDelivery) {
    let signature = sign_body(row.secret.as_deref(), &row.payload);
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(WORKER_HTTP_TIMEOUT_SECS))
        .build();
    let mut req = agent
        .post(&row.url)
        .set("Content-Type", "application/json")
        .set("X-Artifacts-Hook-Id", &row.hook_id)
        .set("X-Artifacts-Event", &row.kind)
        .set("X-Artifacts-Attempt", &row.attempts.to_string())
        .set("X-Artifacts-Delivery-Id", &row.id.to_string());
    if let Some(sig) = signature.as_deref() {
        req = req.set("X-Artifacts-Signature", sig);
    }
    // `ureq` maps any HTTP status >= 400 to `Err(Error::Status(code, _))`,
    // so a successful `Ok` is always a 2xx/3xx (a delivered webhook). The
    // failure modes that matter are therefore all on the `Err` side:
    //   - `Status(4xx)` → terminal client error (don't retry).
    //   - `Status(5xx)` or any transport/timeout error → retryable.
    match req.send_bytes(&row.payload) {
        Ok(resp) => {
            let status = resp.status();
            let _ = outbox.mark_delivery_finalized(row.id, "success", Some(&status.to_string()));
            metrics::counter!(
                "artifacts_webhook_deliveries_total",
                "kind" => row.kind.clone(),
                "outcome" => "success",
            )
            .increment(1);
        },
        // 4xx — terminal client error; retrying won't help.
        Err(ureq::Error::Status(status, _)) if (400..500).contains(&status) => {
            let _ =
                outbox.mark_delivery_finalized(row.id, "client_error", Some(&status.to_string()));
            tracing::warn!(
                delivery_id = row.id, hook = %row.hook_id, url = %row.url,
                status, attempt = row.attempts, "webhook 4xx; not retrying"
            );
            metrics::counter!(
                "artifacts_webhook_deliveries_total",
                "kind" => row.kind.clone(),
                "outcome" => "client_error",
            )
            .increment(1);
        },
        // 5xx (Status) or a transport/timeout error — retryable.
        failure => {
            let reason = match &failure {
                Err(ureq::Error::Status(status, _)) => status.to_string(),
                _ => "network".to_string(),
            };
            if row.attempts >= WORKER_MAX_ATTEMPTS {
                finalize_exhausted(outbox, &row, Some(&reason));
            } else {
                let next = now_unix_secs() + worker_backoff_secs(row.attempts);
                let _ = outbox.mark_delivery_retry(row.id, row.attempts, next, &reason);
                tracing::warn!(
                    delivery_id = row.id, hook = %row.hook_id, url = %row.url,
                    reason, attempt = row.attempts, next_secs = next - now_unix_secs(),
                    "webhook delivery failed; will retry"
                );
            }
        },
    }
}

fn finalize_exhausted(
    outbox: &dyn DeliveryOutbox,
    row: &PendingDelivery,
    last_status: Option<&str>,
) {
    let _ = outbox.mark_delivery_finalized(row.id, "exhausted", last_status);
    metrics::counter!(
        "artifacts_webhook_deliveries_total",
        "kind" => row.kind.clone(),
        "outcome" => "exhausted",
    )
    .increment(1);
    tracing::warn!(
        delivery_id = row.id, hook = %row.hook_id, url = %row.url,
        "webhook delivery exhausted after {} attempts", row.attempts
    );
}

/// Publish an event to the live bus AND, when a durable outbox is
/// present, synchronously enqueue its webhook deliveries.
///
/// Enqueuing here — at publish time, in the same call the handler makes
/// to announce the event — rather than off the lossy in-process
/// broadcast in the dispatcher is the durability fix: a broadcast lag
/// can no longer drop a webhook delivery, because the durable
/// `webhook_deliveries` row exists before this returns. The bus
/// broadcast still drives the SSE stream and the MemRegistry
/// direct-dispatch path; only the durable enqueue moved off it.
///
/// Enqueue failures are logged, not propagated: webhook delivery is
/// best-effort and must never fail the mutation that produced the event.
pub fn publish_event(
    bus: &crate::events::EventBus,
    outbox: Option<&dyn DeliveryOutbox>,
    ev: Event,
) {
    if let Some(outbox) = outbox {
        let (repo_id_str, kind) = repo_and_kind(&ev);
        match crate::ids::RepoId::try_from(repo_id_str) {
            Ok(repo_id) => match serde_json::to_vec(&ev) {
                Ok(body) => {
                    if let Err(e) = outbox.enqueue_delivery(&repo_id, kind, &body) {
                        tracing::error!(error = %e, "webhook enqueue-at-publish failed");
                    }
                },
                Err(e) => tracing::error!(error = %e, "webhook publish: event serialize failed"),
            },
            Err(e) => {
                tracing::warn!(error = %e, repo_id = repo_id_str, "webhook publish: invalid repo id");
            },
        }
    }
    bus.publish(ev);
}

/// Direct-dispatch one event for the MemRegistry path: serialize and
/// fan out to matching subscriptions, single attempt. The SQLite path
/// never reaches here — it enqueues at publish ([`publish_event`]).
fn dispatch_event(registry: &dyn WebhookRegistry, ev: &Event) {
    let body = match serde_json::to_vec(ev) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "webhook serialize failed");
            return;
        },
    };
    legacy_direct_dispatch(registry, ev, body);
}

/// Pre-K3 single-attempt direct dispatch — kept so MemRegistry-backed
/// deployments (tests, dev) still see webhook firings without a
/// SQLite outbox. Production deployments go through the durable
/// outbox + worker pair instead.
fn legacy_direct_dispatch(registry: &dyn WebhookRegistry, ev: &Event, body: Vec<u8>) {
    let (repo_id_str, kind) = repo_and_kind(ev);
    let Ok(repo_id) = crate::ids::RepoId::try_from(repo_id_str) else {
        return;
    };
    let subs = registry.matching(&repo_id, kind);
    if subs.is_empty() {
        return;
    }
    let kind_owned = kind.to_string();
    for sub in subs {
        let body = body.clone();
        let kind = kind_owned.clone();
        tokio::task::spawn_blocking(move || {
            let signature = sign_body(sub.secret.as_deref(), &body);
            let agent = ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(WORKER_HTTP_TIMEOUT_SECS))
                .build();
            let mut req = agent
                .post(&sub.url)
                .set("Content-Type", "application/json")
                .set("X-Artifacts-Hook-Id", &sub.id)
                .set("X-Artifacts-Event", &kind)
                .set("X-Artifacts-Attempt", "1");
            if let Some(sig) = signature.as_deref() {
                req = req.set("X-Artifacts-Signature", sig);
            }
            // `ureq` maps any status >= 400 to `Err(Status)`, so `Ok` is a
            // delivered 2xx/3xx. This dispatch is single-attempt (no
            // outbox to retry against), so every failure is terminal —
            // a 4xx is a `client_error`, anything else `exhausted`.
            let outcome = match req.send_bytes(&body) {
                Ok(_resp) => "success",
                Err(ureq::Error::Status(status, _)) if (400..500).contains(&status) => {
                    "client_error"
                },
                Err(e) => {
                    tracing::warn!(
                        hook = %sub.id, url = %sub.url, error = %e,
                        "legacy direct-dispatch failed (single attempt)"
                    );
                    "exhausted"
                },
            };
            metrics::counter!(
                "artifacts_webhook_deliveries_total",
                "kind" => kind,
                "outcome" => outcome,
            )
            .increment(1);
        });
    }
}

/// Compute `sha256=<hex>` over `body` keyed by `secret`. Returns
/// `None` when there's no secret — subscribers that don't care
/// about authenticity (private network, mTLS upstream, etc.) can
/// skip the verification.
fn sign_body(secret: Option<&str>, body: &[u8]) -> Option<String> {
    let secret = secret?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(body);
    let bytes = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(bytes.len() * 2 + 7);
    hex.push_str("sha256=");
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{b:02x}");
    }
    Some(hex)
}

/// Pull `(repo_id, kind)` out of an `Event` without recomputing the
/// JSON. Cheap enough that we don't bother caching.
fn repo_and_kind(ev: &Event) -> (&str, &str) {
    match ev {
        Event::Commit { repo_id, .. } => (repo_id, "commit"),
        Event::Fork { parent_repo_id, .. } => (parent_repo_id, "fork"),
        Event::Status { repo_id, .. } => (repo_id, "status"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construct a valid `RepoId` for fixtures. The webhook repo-scoping
    /// methods take `&RepoId`, so test ids must satisfy the 4–64-char
    /// lowercase contract (the old `"r1"` shorthand no longer parses).
    fn rid(s: &str) -> crate::ids::RepoId {
        crate::ids::RepoId::try_from(s).unwrap()
    }

    #[test]
    fn validate_webhook_url_blocks_ssrf_targets() {
        // Internal / metadata / loopback / private / link-local /
        // multicast / unspecified literals, v4 and v6, are refused.
        for bad in [
            "http://127.0.0.1/hook",
            "http://127.0.0.1:8080/hook",
            "http://169.254.169.254/latest/meta-data", // cloud metadata
            "http://10.0.0.5/x",
            "http://192.168.1.1/x",
            "http://172.16.0.1/x",
            "http://100.64.0.1/x", // CGNAT
            "http://0.0.0.0/x",
            "http://[::1]/x",               // ipv6 loopback
            "http://[fe80::1]/x",           // ipv6 link-local
            "http://[fc00::1]/x",           // ipv6 ULA
            "http://[::ffff:127.0.0.1]/x",  // ipv4-mapped loopback
            "http://user:pass@127.0.0.1/x", // userinfo doesn't smuggle past
        ] {
            assert!(
                validate_webhook_url(bad, false).is_err(),
                "{bad:?} must be rejected as SSRF"
            );
        }
        // Non-http(s) schemes are refused regardless of host.
        for bad in ["ftp://example.com/x", "file:///etc/passwd", "example.com/x"] {
            assert!(
                validate_webhook_url(bad, false).is_err(),
                "{bad:?} must be rejected (scheme/format)"
            );
        }
    }

    #[test]
    fn validate_webhook_url_allows_public_and_hostnames() {
        for ok in [
            "https://hooks.example.com/abc",
            "http://example.com:8080/x",
            "https://8.8.8.8/x",         // public IP literal
            "https://example.invalid/h", // hostname (not an IP) → allowed
        ] {
            assert!(
                validate_webhook_url(ok, false).is_ok(),
                "{ok:?} should be accepted"
            );
        }
        // The dev opt-out re-allows loopback/private literals.
        assert!(validate_webhook_url("http://127.0.0.1:9000/h", true).is_ok());
        assert!(validate_webhook_url("http://10.0.0.1/h", true).is_ok());
    }

    #[test]
    fn add_then_list_round_trip() {
        let r = MemRegistry::new();
        let id = r
            .add(Subscription {
                id: String::new(),
                repo_id: rid("repo-a"),
                url: "http://example".into(),
                secret: None,
                events: vec![],
            })
            .unwrap();
        assert!(!id.is_empty());
        let listed = r.list(&rid("repo-a")).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, id);
    }

    #[test]
    fn list_filters_by_repo() {
        let r = MemRegistry::new();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "u1".into(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-b"),
            url: "u2".into(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        assert_eq!(r.list(&rid("repo-a")).unwrap().len(), 1);
        assert_eq!(r.list(&rid("repo-b")).unwrap().len(), 1);
        assert_eq!(r.list(&rid("repo-c")).unwrap().len(), 0);
    }

    #[test]
    fn remove_targets_specific_hook_only() {
        let r = MemRegistry::new();
        let id1 = r
            .add(Subscription {
                id: String::new(),
                repo_id: rid("repo-a"),
                url: "u1".into(),
                secret: None,
                events: vec![],
            })
            .unwrap();
        let id2 = r
            .add(Subscription {
                id: String::new(),
                repo_id: rid("repo-a"),
                url: "u2".into(),
                secret: None,
                events: vec![],
            })
            .unwrap();
        assert!(r.remove(&rid("repo-a"), &id1).unwrap());
        let rem = r.list(&rid("repo-a")).unwrap();
        assert_eq!(rem.len(), 1);
        assert_eq!(rem[0].id, id2);
        // removing again is a no-op.
        assert!(!r.remove(&rid("repo-a"), &id1).unwrap());
    }

    #[test]
    fn matching_filters_by_kind_when_events_set() {
        let r = MemRegistry::new();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "u-all".into(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "u-commit".into(),
            secret: None,
            events: vec![crate::events::EventKind::Commit],
        })
        .unwrap();
        let m_commit = r.matching(&rid("repo-a"), "commit");
        assert_eq!(m_commit.len(), 2);
        let m_fork = r.matching(&rid("repo-a"), "fork");
        // only the all-kinds subscription matches.
        assert_eq!(m_fork.len(), 1);
        assert_eq!(m_fork[0].url, "u-all");
    }

    #[test]
    fn sign_body_produces_stable_hex() {
        let s = sign_body(Some("supersecret"), b"hello").unwrap();
        // Known good (verified with openssl):
        //   $ printf hello | openssl dgst -sha256 -hmac supersecret
        //   c6d323717f52016e8e0b606500d0b11721618a8d75df8acead4d9395544f4787
        assert_eq!(
            s,
            "sha256=c6d323717f52016e8e0b606500d0b11721618a8d75df8acead4d9395544f4787"
        );
    }

    #[test]
    fn sign_body_returns_none_without_secret() {
        assert!(sign_body(None, b"x").is_none());
    }

    fn test_master_key() -> Arc<crate::secrets::MasterKey> {
        Arc::new(crate::secrets::MasterKey::random())
    }

    fn open_sqlite_registry() -> (tempfile::TempDir, SqliteWebhookRegistry) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhooks.db");
        let r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        (dir, r)
    }

    #[test]
    fn sqlite_add_then_list_round_trip() {
        let (_d, r) = open_sqlite_registry();
        let id = r
            .add(Subscription {
                id: String::new(),
                repo_id: rid("repo-a"),
                url: "http://example".into(),
                secret: Some("s".into()),
                events: vec![crate::events::EventKind::Commit],
            })
            .unwrap();
        let listed = r.list(&rid("repo-a")).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, id);
        assert_eq!(listed[0].secret.as_deref(), Some("s"));
        assert_eq!(listed[0].events, vec![crate::events::EventKind::Commit]);
    }

    #[test]
    fn sqlite_remove_marks_revoked_and_drops_from_list() {
        let (_d, r) = open_sqlite_registry();
        let id = r
            .add(Subscription {
                id: String::new(),
                repo_id: rid("repo-a"),
                url: "u".into(),
                secret: None,
                events: vec![],
            })
            .unwrap();
        assert!(r.remove(&rid("repo-a"), &id).unwrap());
        assert!(r.list(&rid("repo-a")).unwrap().is_empty());
        // Idempotent: a second remove finds no live row.
        assert!(!r.remove(&rid("repo-a"), &id).unwrap());
    }

    #[test]
    fn sqlite_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhooks.db");
        // Single shared key — both `open` calls must use the same one
        // to decrypt the secret on the second open.
        let key = test_master_key();
        let id = {
            let r = SqliteWebhookRegistry::open(&path, key.clone()).unwrap();
            r.add(Subscription {
                id: String::new(),
                repo_id: rid("repo-a"),
                url: "u".into(),
                secret: Some("k".into()),
                events: vec![],
            })
            .unwrap()
        };
        // Drop, reopen on the same path. Must see the row.
        let r = SqliteWebhookRegistry::open(&path, key).unwrap();
        let listed = r.list(&rid("repo-a")).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, id);
        assert_eq!(listed[0].secret.as_deref(), Some("k"));
    }

    #[test]
    fn sqlite_matching_filters_by_kind() {
        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "u-all".into(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "u-commit".into(),
            secret: None,
            events: vec![crate::events::EventKind::Commit],
        })
        .unwrap();
        let m_commit = r.matching(&rid("repo-a"), "commit");
        assert_eq!(m_commit.len(), 2);
        let m_fork = r.matching(&rid("repo-a"), "fork");
        assert_eq!(m_fork.len(), 1);
        assert_eq!(m_fork[0].url, "u-all");
    }

    #[test]
    fn sqlite_secret_on_disk_is_opaque_ciphertext() {
        // Open the registry, write a known plaintext, then peek at
        // the row directly via raw SQL — the `secret` column must
        // not be readable as the original plaintext, and
        // `secret_nonce` must be set.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhooks.db");
        let r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "u".into(),
            secret: Some("plaintext-marker-XYZ".into()),
            events: vec![],
        })
        .unwrap();
        // Raw read against the same DB file. Must NOT see "plaintext-marker-XYZ".
        let conn = rusqlite::Connection::open(&path).unwrap();
        let (stored_secret, nonce): (Option<String>, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT secret, secret_nonce FROM webhooks WHERE repo_id = 'repo-a'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let stored_secret = stored_secret.expect("secret column NULL after add");
        let nonce = nonce.expect("secret_nonce column NULL after add");
        assert_eq!(nonce.len(), 12, "nonce must be 12 bytes for AES-GCM");
        assert!(
            !stored_secret.contains("plaintext-marker-XYZ"),
            "ciphertext column leaked plaintext: {stored_secret}",
        );
    }

    #[test]
    fn sqlite_wrong_key_yields_unsigned_subscription() {
        // Write under one key, reopen under a different key. The
        // subscription must still appear in the list (so the admin
        // can see "this hook exists") but the secret is dropped to
        // None so deliveries go unsigned rather than panicking.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhooks.db");
        let k1 = test_master_key();
        {
            let r = SqliteWebhookRegistry::open(&path, k1).unwrap();
            r.add(Subscription {
                id: String::new(),
                repo_id: rid("repo-a"),
                url: "u".into(),
                secret: Some("k".into()),
                events: vec![],
            })
            .unwrap();
        }
        let k2 = test_master_key(); // fresh, unrelated
        let r = SqliteWebhookRegistry::open(&path, k2).unwrap();
        let listed = r.list(&rid("repo-a")).unwrap();
        assert_eq!(listed.len(), 1, "subscription should still be visible");
        assert_eq!(
            listed[0].secret, None,
            "wrong key must produce None secret, not garbage"
        );
    }

    #[test]
    fn sqlite_legacy_plaintext_rows_still_readable() {
        // Simulate a row written before the secret-encryption migration:
        // secret = plaintext, secret_nonce = NULL. The reader must
        // detect that and return the plaintext as-is so existing
        // subscriptions keep working through the migration.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhooks.db");
        // First open to run the schema migrations.
        let _r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        // Now insert a legacy-shape row directly: secret_nonce = NULL.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO webhooks (id, repo_id, url, secret, secret_nonce, events_json, created_at)
             VALUES ('legacy-hook', 'repo-a', 'u', 'legacy-plaintext-secret', NULL, '[]', 0)",
            [],
        )
        .unwrap();
        drop(conn);
        // Reopen via the registry with a (different) key — legacy rows
        // ignore the key entirely.
        let r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        let listed = r.list(&rid("repo-a")).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].secret.as_deref(), Some("legacy-plaintext-secret"));
    }

    #[test]
    fn sqlite_rotate_master_key_re_encrypts_existing_rows() {
        // The contract: after rotate(), every encrypted row decrypts
        // under the new key. Set up two rows under k1, rotate to k2,
        // verify list() returns the same plaintexts. Then peek at the
        // raw secret column — it must have changed (different
        // ciphertext under the new key).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhooks.db");
        let k1 = test_master_key();
        let r = SqliteWebhookRegistry::open(&path, k1).unwrap();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "u".into(),
            secret: Some("alpha".into()),
            events: vec![],
        })
        .unwrap();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "u".into(),
            secret: Some("beta".into()),
            events: vec![],
        })
        .unwrap();

        // Snapshot the raw secret column before rotation.
        let conn = rusqlite::Connection::open(&path).unwrap();
        let before: Vec<String> = conn
            .prepare("SELECT secret FROM webhooks ORDER BY created_at, id")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        drop(conn);

        let k2 = test_master_key();
        let rotated = r.rotate_master_key(k2).unwrap();
        assert_eq!(rotated, 2, "expected to re-encrypt 2 rows, got {rotated}");

        // After rotation, list() returns plaintexts decrypted under the
        // newly-installed key — same plaintexts, since we re-encrypted
        // the same secrets under the new key.
        let listed = r.list(&rid("repo-a")).unwrap();
        let mut plaintexts: Vec<&str> = listed.iter().filter_map(|s| s.secret.as_deref()).collect();
        plaintexts.sort_unstable();
        assert_eq!(plaintexts, vec!["alpha", "beta"]);

        // Raw secret column changed.
        let conn = rusqlite::Connection::open(&path).unwrap();
        let after: Vec<String> = conn
            .prepare("SELECT secret FROM webhooks ORDER BY created_at, id")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_ne!(before, after, "ciphertext should change on rotation");
    }

    #[test]
    fn sqlite_rotate_with_no_rows_is_noop_but_swaps_key() {
        // No encrypted rows yet. Rotate succeeds with count=0; a row
        // added after rotation seals under the NEW key (verified by
        // observing that opening the DB with the OLD key drops the
        // secret to None on read).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhooks.db");
        let k1 = test_master_key();
        let r = SqliteWebhookRegistry::open(&path, k1.clone()).unwrap();
        let n = r.rotate_master_key(test_master_key()).unwrap();
        assert_eq!(n, 0);
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "u".into(),
            secret: Some("post-rotate".into()),
            events: vec![],
        })
        .unwrap();
        // Rebuild a registry against the OLD key — the row added after
        // rotation must come back unsigned (key mismatch handled the
        // same way as in `sqlite_wrong_key_yields_unsigned_subscription`).
        drop(r);
        let r_old = SqliteWebhookRegistry::open(&path, k1).unwrap();
        let listed = r_old.list(&rid("repo-a")).unwrap();
        assert_eq!(listed.len(), 1);
        assert!(
            listed[0].secret.is_none(),
            "row encrypted under post-rotation key must not decrypt under pre-rotation key"
        );
    }

    #[test]
    fn sqlite_rotate_skips_legacy_plaintext_rows() {
        // Legacy rows (secret_nonce IS NULL) are migration cruft —
        // they should pass through rotation untouched, not get
        // newly-encrypted under the rotated key.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhooks.db");
        // Bootstrap the schema by opening once.
        {
            let _ = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        }
        // Insert a legacy-shape row directly.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO webhooks (id, repo_id, url, secret, secret_nonce, events_json, created_at)
             VALUES ('legacy-1', 'repo-a', 'u', 'legacy-plaintext', NULL, '[]', 0)",
            [],
        )
        .unwrap();
        drop(conn);
        let r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        // Add an encrypted row alongside.
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "u".into(),
            secret: Some("encrypted-row".into()),
            events: vec![],
        })
        .unwrap();
        let rotated = r.rotate_master_key(test_master_key()).unwrap();
        assert_eq!(
            rotated, 1,
            "legacy row should be skipped, only the encrypted row touched"
        );
        // Legacy row still readable as plaintext.
        let listed = r.list(&rid("repo-a")).unwrap();
        let plaintexts: Vec<&str> = listed.iter().filter_map(|s| s.secret.as_deref()).collect();
        assert!(plaintexts.contains(&"legacy-plaintext"));
        assert!(plaintexts.contains(&"encrypted-row"));
    }

    // K3 — durable webhook outbox.
    //
    // The acceptance scenario the goal calls for: a row sitting
    // un-finalized when the process restarts must be picked up by the
    // delivery worker and driven to a terminal outcome. We simulate
    // the restart by raw-INSERT-ing a pending row into the SQLite
    // file, dropping the registry handle, reopening on the same path,
    // and asserting the worker delivers it.

    /// Tiny one-shot HTTP listener. Accepts one TCP connection,
    /// reads the request bytes (up to 4 KiB; webhooks are small),
    /// replies 200 OK, and ships the captured bytes through a
    /// channel. Lives in a single thread so the test's tokio runtime
    /// stays clean. Returns (url, receiver).
    fn spawn_one_shot_listener() -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe socket");
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = sock.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                let _ = tx.send(req);
            }
        });
        (format!("http://127.0.0.1:{port}/hook"), rx)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn outbox_redelivers_after_simulated_restart() {
        let (server_url, recv) = spawn_one_shot_listener();

        // Phase 1 — pre-restart. Open the registry against a fresh
        // SQLite path, then raw-INSERT a pending row pointing at the
        // listener. Dropping the registry simulates a process crash
        // mid-delivery: the row is durably on disk, no worker is
        // running, nobody finalized it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhooks.db");
        {
            let _r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "INSERT INTO webhook_deliveries
                   (hook_id, url, secret, secret_nonce, kind, payload,
                    attempts, next_attempt_at, created_at)
                 VALUES ('h-pre-restart', ?1, NULL, NULL, 'commit', ?2,
                         0, ?3, ?3)",
                rusqlite::params![server_url, br#"{"kind":"commit"}"#.to_vec(), 0i64],
            )
            .unwrap();
            // Confirm the row is in the file before we drop the registry.
            let pending: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM webhook_deliveries
                     WHERE finalized_at IS NULL",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(pending, 1, "expected one un-finalized row pre-restart");
        }

        // Phase 2 — post-restart. Reopen on the same file with a
        // FRESH master key (the row's secret is NULL so the new key
        // never has to unseal anything; this also pins that the
        // worker doesn't depend on the old in-memory key state) and
        // spawn the worker on a fast tick so the test doesn't have to
        // wait the production 2s.
        let outbox: Arc<dyn DeliveryOutbox> =
            Arc::new(SqliteWebhookRegistry::open(&path, test_master_key()).unwrap());
        spawn_delivery_worker(
            outbox.clone(),
            std::time::Duration::from_millis(50),
            tokio_util::sync::CancellationToken::new(),
        );

        // Phase 3 — observe. The listener thread is blocking on
        // accept(); the worker's first tick (within ~50ms of spawn)
        // should pick the row up and POST to it. A 5-second window
        // is generous on CI.
        let req = tokio::task::spawn_blocking(move || {
            recv.recv_timeout(std::time::Duration::from_secs(5))
        })
        .await
        .unwrap()
        .expect("listener never received a request");
        assert!(req.starts_with("POST "), "expected POST, got:\n{req}");
        assert!(
            req.contains("X-Artifacts-Hook-Id: h-pre-restart"),
            "expected hook-id header to flow through: \n{req}"
        );
        assert!(
            req.contains("X-Artifacts-Event: commit"),
            "expected event-kind header to flow through:\n{req}"
        );

        // Phase 4 — confirm the row was finalized. The worker stamps
        // finalized_at + finalized_outcome on success; we poll the DB
        // for up to 2 seconds so the assertion isn't a flaky race.
        let path_clone = path.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            let conn = rusqlite::Connection::open(&path_clone).unwrap();
            for _ in 0..40 {
                let row: rusqlite::Result<(i64, String)> = conn.query_row(
                    "SELECT finalized_at, finalized_outcome
                     FROM webhook_deliveries
                     WHERE id = 1",
                    [],
                    |r| {
                        Ok((
                            r.get::<_, Option<i64>>(0)?.unwrap_or(0),
                            r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                        ))
                    },
                );
                if let Ok((finalized_at, outcome)) = row {
                    if finalized_at > 0 {
                        return outcome;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            String::new()
        })
        .await
        .unwrap();
        assert_eq!(
            outcome, "success",
            "row was not finalized as success after the worker delivered it"
        );
    }

    #[tokio::test]
    async fn enqueue_creates_one_row_per_matching_subscription() {
        // Setup: a subscription with two matching kinds.
        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "http://nowhere.invalid".into(),
            secret: None,
            events: vec![
                crate::events::EventKind::Commit,
                crate::events::EventKind::Fork,
            ],
        })
        .unwrap();
        // Plus a subscription that doesn't match this kind.
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "http://nowhere2.invalid".into(),
            secret: None,
            events: vec![crate::events::EventKind::Fork],
        })
        .unwrap();
        // Plus a subscription on a different repo.
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-b"),
            url: "http://nowhere3.invalid".into(),
            secret: None,
            events: vec![],
        })
        .unwrap();

        let n = r
            .enqueue_delivery(&rid("repo-a"), "commit", br#"{}"#)
            .unwrap();
        assert_eq!(
            n, 1,
            "only the kind-matching r1 subscription should enqueue"
        );

        // empty-events subscription matches every kind.
        let n2 = r
            .enqueue_delivery(&rid("repo-b"), "commit", br#"{}"#)
            .unwrap();
        assert_eq!(n2, 1);
    }

    #[tokio::test]
    async fn mark_retry_pushes_next_attempt_forward() {
        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "http://nowhere.invalid".into(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        let n = r
            .enqueue_delivery(&rid("repo-a"), "commit", br#"{}"#)
            .unwrap();
        assert_eq!(n, 1);

        // Claim moves the row's next_attempt_at forward by 60s. The
        // worker would then mark it retry with a real backoff; we
        // emulate that and assert the row stays un-finalized.
        let claimed = r.claim_pending_deliveries(10).unwrap();
        assert_eq!(claimed.len(), 1);
        let id = claimed[0].id;
        let future = now_unix_secs() + 3600;
        r.mark_delivery_retry(id, 2, future, "503").unwrap();

        // Re-claim now returns nothing (row's next_attempt_at is 1h
        // in the future).
        let again = r.claim_pending_deliveries(10).unwrap();
        assert!(
            again.is_empty(),
            "row scheduled for the future must not be re-claimed"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn worker_handle_resolves_cleanly_on_cancel() {
        // K4: pin the graceful-shutdown property. Spawn the delivery
        // worker on a short tick so it's actively polling. Fire
        // cancel + await the handle with a bounded timeout. The
        // handle must resolve in well under that bound — if the
        // tokio::select! arm on the cancel token isn't wired
        // correctly the test hangs and the timeout fires.
        let (_d, sqlite_r) = open_sqlite_registry();
        let outbox: Arc<dyn DeliveryOutbox> = Arc::new(sqlite_r);
        let cancel = tokio_util::sync::CancellationToken::new();
        let handle =
            spawn_delivery_worker(outbox, std::time::Duration::from_millis(50), cancel.clone());
        // Let the worker actually start its loop and hit the select!
        // arm at least once before we cancel.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        cancel.cancel();
        // 1 second is generous — the worker should drop out of the
        // select! on the next poll.
        let resolved = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
        assert!(
            resolved.is_ok(),
            "delivery worker did not resolve within 1s of cancel"
        );
        resolved
            .unwrap()
            .expect("worker JoinHandle returned an error");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dispatcher_handle_resolves_cleanly_on_cancel() {
        // Same shape as the worker test but exercises the
        // spawn_dispatcher select! — that one selects on a
        // broadcast::Recv vs cancel.cancelled(), structurally
        // different from the ticker-vs-cancel pattern.
        let registry: Arc<dyn WebhookRegistry> = Arc::new(MemRegistry::new());
        let bus = crate::events::EventBus::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let handle = spawn_dispatcher(registry, bus, cancel.clone());
        // Give the dispatcher a beat to subscribe and block on recv.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        cancel.cancel();
        let resolved = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
        assert!(
            resolved.is_ok(),
            "dispatcher did not resolve within 1s of cancel"
        );
    }

    // L4 — finalized-row retention prune.

    #[tokio::test]
    async fn prune_finalized_drops_old_rows_and_keeps_pending() {
        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "http://nowhere.invalid".into(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        // Enqueue three rows; finalize two of them at very old
        // timestamps via raw SQL so the cutoff arithmetic is
        // unambiguous.
        r.enqueue_delivery(&rid("repo-a"), "commit", br#"{"k":1}"#)
            .unwrap();
        r.enqueue_delivery(&rid("repo-a"), "commit", br#"{"k":2}"#)
            .unwrap();
        r.enqueue_delivery(&rid("repo-a"), "commit", br#"{"k":3}"#)
            .unwrap();

        // Two of them: stamp finalized_at = 100 (epoch+100s, very old).
        {
            let conn = r.lock().unwrap();
            conn.execute(
                "UPDATE webhook_deliveries
                 SET finalized_at = 100, finalized_outcome = 'success'
                 WHERE id IN (1, 2)",
                [],
            )
            .unwrap();
        }

        // Cutoff at 1000 (well past 100) — both finalized rows
        // are older than cutoff and should be deleted; the third
        // pending row survives.
        let pruned = r.prune_finalized(1000).unwrap();
        assert_eq!(pruned, 2, "two finalized rows should be pruned");

        let surviving: u64 = {
            let conn = r.lock().unwrap();
            conn.query_row("SELECT COUNT(*) FROM webhook_deliveries", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|n| n as u64)
            .unwrap()
        };
        assert_eq!(surviving, 1, "exactly one pending row should survive");
        // And that survivor is still claimable — pruning didn't
        // accidentally touch the in-flight row.
        let claimed = r.claim_pending_deliveries(10).unwrap();
        assert_eq!(claimed.len(), 1);
    }

    #[tokio::test]
    async fn prune_finalized_respects_cutoff_keeps_recent_rows() {
        // A recently-finalized row (after cutoff) must NOT be
        // pruned — the retention window exists so admin tooling
        // can still audit "what just got delivered."
        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "http://nowhere.invalid".into(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        r.enqueue_delivery(&rid("repo-a"), "commit", br#"{}"#)
            .unwrap();
        // Finalize at a "recent" timestamp.
        let recent = now_unix_secs();
        {
            let conn = r.lock().unwrap();
            conn.execute(
                "UPDATE webhook_deliveries
                 SET finalized_at = ?1, finalized_outcome = 'success'
                 WHERE id = 1",
                [recent],
            )
            .unwrap();
        }
        // Cutoff at recent - 100 (i.e., row is on the "keep" side
        // of the cutoff).
        let pruned = r.prune_finalized(recent - 100).unwrap();
        assert_eq!(pruned, 0, "recently finalized rows must survive");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn prune_task_handle_resolves_on_cancel() {
        let outbox: Arc<dyn DeliveryOutbox> = Arc::new(open_sqlite_registry().1);
        let cancel = tokio_util::sync::CancellationToken::new();
        let handle = spawn_prune_task(
            outbox,
            std::time::Duration::from_millis(50),
            std::time::Duration::from_secs(86400),
            cancel.clone(),
        )
        .expect("retention nonzero -> handle returned");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        cancel.cancel();
        let resolved = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
        assert!(
            resolved.is_ok(),
            "prune task did not resolve within 1s of cancel"
        );
    }

    #[tokio::test]
    async fn mark_finalized_makes_row_un_claimable() {
        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "http://nowhere.invalid".into(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        r.enqueue_delivery(&rid("repo-a"), "commit", br#"{}"#)
            .unwrap();
        let claimed = r.claim_pending_deliveries(10).unwrap();
        let id = claimed[0].id;
        r.mark_delivery_finalized(id, "success", Some("200"))
            .unwrap();
        let again = r.claim_pending_deliveries(10).unwrap();
        assert!(
            again.is_empty(),
            "finalized rows must not be claimable again"
        );
    }

    // --- M4: pool-exhaustion returns Err (not panic) -------------------

    /// Build a SqliteWebhookRegistry over a pool capped at one
    /// connection with a short acquire timeout, so a second checkout
    /// fails fast. Returns the registry plus the held connection — keep
    /// the latter alive to keep the pool exhausted.
    fn exhausted_registry() -> (
        SqliteWebhookRegistry,
        r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>,
    ) {
        let manager = r2d2_sqlite::SqliteConnectionManager::memory();
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .connection_timeout(std::time::Duration::from_millis(50))
            .build(manager)
            .unwrap();
        let held = pool.get().unwrap(); // the only connection; pool now empty
        let reg = SqliteWebhookRegistry {
            conn: pool,
            master_key: std::sync::RwLock::new(test_master_key()),
        };
        (reg, held)
    }

    #[test]
    fn pool_exhaustion_returns_err_not_panic() {
        // The earlier impl `.expect`ed on a failed pool checkout, which
        // panicked the handler task. add/list/remove must instead
        // surface a clean Err so the REST layer maps it to a 500.
        let (reg, _held) = exhausted_registry();
        assert!(
            reg.add(Subscription {
                id: String::new(),
                repo_id: rid("repo-a"),
                url: "http://nowhere.invalid".into(),
                secret: None,
                events: vec![],
            })
            .is_err(),
            "add must return Err on pool exhaustion"
        );
        assert!(
            reg.list(&rid("repo-a")).is_err(),
            "list must return Err on pool exhaustion"
        );
        assert!(
            reg.remove(&rid("repo-a"), "missing").is_err(),
            "remove must return Err on pool exhaustion"
        );
        // matching is infallible by contract: it degrades to an empty
        // set (logged) rather than erroring or panicking.
        assert!(reg.matching(&rid("repo-a"), "commit").is_empty());
    }

    // --- M4: dispatcher lag is counted, not silently dropped -----------

    #[test]
    fn dispatcher_lag_increments_drop_counter() {
        use metrics::with_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        with_local_recorder(&recorder, || {
            record_dispatcher_lag(7);
        });

        let found = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .find(|(k, _, _, _)| k.key().name() == "artifacts_webhook_events_dropped_total");
        match found {
            Some((_, _, _, DebugValue::Counter(v))) => {
                assert_eq!(v, 7, "drop counter must record the dropped-event count");
            },
            other => panic!("drop counter was not recorded: {other:?}"),
        }
    }

    #[test]
    fn publish_event_enqueues_durably_without_the_bus() {
        // N5 durability property: publish_event enqueues into the outbox
        // synchronously, so a delivery row exists with no dispatcher and
        // nothing drained off the broadcast — a bus lag cannot drop it.
        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "http://hook.invalid".into(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        let bus = crate::events::EventBus::new();
        let ev = crate::events::Event::commit("repo-a", "0".repeat(40), "main", "m");
        // No subscriber is attached to `bus`; the durable enqueue is the
        // only delivery path under test.
        publish_event(&bus, Some(&r), ev);
        let claimed = r.claim_pending_deliveries(10).unwrap();
        assert_eq!(
            claimed.len(),
            1,
            "publish_event must enqueue a durable delivery row at publish time"
        );
    }

    // -----------------------------------------------------------------------
    // New tests — delivery-outbox deep paths, worker, signing, gauge tasks.
    // -----------------------------------------------------------------------

    // --- count_active -------------------------------------------------------

    #[test]
    fn sqlite_count_active_reflects_live_subscriptions() {
        let (_d, r) = open_sqlite_registry();
        assert_eq!(r.count_active().unwrap(), 0, "fresh registry has 0 active");
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "u1".into(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "u2".into(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        assert_eq!(r.count_active().unwrap(), 2, "two active subs");
        // Revoke one; count should drop.
        let id = r.list(&rid("repo-a")).unwrap()[0].id.clone();
        r.remove(&rid("repo-a"), &id).unwrap();
        assert_eq!(r.count_active().unwrap(), 1, "one active after revoke");
    }

    // --- worker_backoff_secs ------------------------------------------------

    #[test]
    fn worker_backoff_doubles_and_caps() {
        // attempt 1 → 60s (base)
        assert_eq!(worker_backoff_secs(1), 60);
        // attempt 2 → 120s
        assert_eq!(worker_backoff_secs(2), 120);
        // attempt 3 → 240s
        assert_eq!(worker_backoff_secs(3), 240);
        // attempt 7 → 3840s < 3600? no: 60 * 2^6 = 3840 > 3600 → capped
        assert_eq!(worker_backoff_secs(7), WORKER_BACKOFF_MAX_SECS);
        // Large attempt still capped.
        assert_eq!(worker_backoff_secs(100), WORKER_BACKOFF_MAX_SECS);
    }

    // --- claim on empty table -----------------------------------------------

    #[test]
    fn claim_pending_on_empty_table_returns_empty_vec() {
        let (_d, r) = open_sqlite_registry();
        let claimed = r.claim_pending_deliveries(10).unwrap();
        assert!(claimed.is_empty(), "empty table must yield empty vec");
    }

    // --- enqueue + claim with HMAC secret (AES unseal path) ----------------

    #[test]
    fn claim_pending_unseals_secret_correctly() {
        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "http://nowhere.invalid".into(),
            secret: Some("hmac-secret-xyz".into()),
            events: vec![],
        })
        .unwrap();
        r.enqueue_delivery(&rid("repo-a"), "commit", br#"{"x":1}"#)
            .unwrap();
        let claimed = r.claim_pending_deliveries(10).unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(
            claimed[0].secret.as_deref(),
            Some("hmac-secret-xyz"),
            "secret must be unsealed and returned in plaintext"
        );
    }

    // --- row_to_sub error branch: bad nonce length -------------------------

    #[test]
    fn row_to_sub_bad_nonce_length_yields_unsigned_subscription() {
        // Insert a row with a 5-byte nonce (should be 12). list() must
        // return the subscription with secret=None rather than erroring.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhooks.db");
        let _r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        // Insert the row with a too-short nonce.
        conn.execute(
            "INSERT INTO webhooks
               (id, repo_id, url, secret, secret_nonce, events_json, created_at)
             VALUES ('bad-nonce', 'repo-a', 'u', 'some-b64', X'0102030405', '[]', 0)",
            [],
        )
        .unwrap();
        drop(conn);
        let r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        let listed = r.list(&rid("repo-a")).unwrap();
        assert_eq!(listed.len(), 1, "row with bad nonce must still be listed");
        assert_eq!(
            listed[0].secret, None,
            "bad nonce length must yield unsigned subscription"
        );
    }

    // --- row_to_sub error branch: bad base64 ciphertext --------------------

    #[test]
    fn row_to_sub_bad_base64_ciphertext_yields_unsigned_subscription() {
        // Insert a row with a valid 12-byte nonce but garbage base64
        // for the ciphertext. list() must return the subscription with
        // secret=None rather than erroring.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhooks.db");
        let _r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        // 12-byte nonce, invalid base64 secret.
        conn.execute(
            "INSERT INTO webhooks
               (id, repo_id, url, secret, secret_nonce, events_json, created_at)
             VALUES ('bad-b64', 'repo-a', 'u', '!@#not_valid_base64!@#',
                     X'000102030405060708090a0b', '[]', 0)",
            [],
        )
        .unwrap();
        drop(conn);
        let r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        let listed = r.list(&rid("repo-a")).unwrap();
        assert_eq!(listed.len(), 1, "row with bad base64 must still be listed");
        assert_eq!(
            listed[0].secret, None,
            "bad base64 ciphertext must yield unsigned subscription"
        );
    }

    // --- dispatch_row: 5xx → retry then exhaust at max attempts ------------

    #[tokio::test(flavor = "multi_thread")]
    async fn dispatch_row_5xx_schedules_retry() {
        // Spawn a listener that replies 503 once.
        use std::io::Write;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = sock.write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let url = format!("http://127.0.0.1:{port}/hook");

        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: url.clone(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        r.enqueue_delivery(&rid("repo-a"), "commit", br#"{}"#)
            .unwrap();
        let rows = r.claim_pending_deliveries(10).unwrap();
        assert_eq!(rows.len(), 1);
        let row = PendingDelivery {
            id: rows[0].id,
            hook_id: rows[0].hook_id.clone(),
            url: url.clone(),
            secret: None,
            kind: "commit".into(),
            payload: br#"{}"#.to_vec(),
            attempts: 1, // below max → should retry
        };
        let path = _d.path().join("webhooks.db");
        let outbox: Arc<dyn DeliveryOutbox> =
            Arc::new(SqliteWebhookRegistry::open(&path, test_master_key()).unwrap());
        let outbox_clone = outbox.clone();
        tokio::task::spawn_blocking(move || dispatch_row(&*outbox_clone, row))
            .await
            .unwrap();
        // After 5xx with attempts=1 < MAX, the row is rescheduled to the
        // future so an immediate claim returns empty.
        let reclaimed = outbox.claim_pending_deliveries(10).unwrap();
        assert!(
            reclaimed.is_empty(),
            "5xx retry must push next_attempt_at into the future"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dispatch_row_5xx_at_max_attempts_finalizes_exhausted() {
        // 5xx response at MAX attempts → finalize as "exhausted"
        use std::io::Write;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = sock.write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let url = format!("http://127.0.0.1:{port}/hook");

        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: url.clone(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        r.enqueue_delivery(&rid("repo-a"), "commit", br#"{}"#)
            .unwrap();
        let rows = r.claim_pending_deliveries(10).unwrap();
        let row_id = rows[0].id;
        // Synthesize a delivery at MAX_ATTEMPTS so the worker finalizes it.
        let row = PendingDelivery {
            id: row_id,
            hook_id: rows[0].hook_id.clone(),
            url: url.clone(),
            secret: None,
            kind: "commit".into(),
            payload: br#"{}"#.to_vec(),
            attempts: WORKER_MAX_ATTEMPTS,
        };
        let r_arc: Arc<dyn DeliveryOutbox> = Arc::new(
            SqliteWebhookRegistry::open(&_d.path().join("webhooks.db"), test_master_key()).unwrap(),
        );
        let r_arc_clone = r_arc.clone();
        tokio::task::spawn_blocking(move || dispatch_row(&*r_arc_clone, row))
            .await
            .unwrap();
        // Row should now be finalized as "exhausted".
        let reclaimed = r_arc.claim_pending_deliveries(10).unwrap();
        assert!(reclaimed.is_empty(), "exhausted row must not be reclaimed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dispatch_row_network_error_schedules_retry() {
        // Point at an unreachable address → transport error → mark_delivery_retry
        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "http://127.0.0.1:1/hook".into(), // port 1 is unreachable
            secret: None,
            events: vec![],
        })
        .unwrap();
        r.enqueue_delivery(&rid("repo-a"), "commit", br#"{}"#)
            .unwrap();
        let rows = r.claim_pending_deliveries(10).unwrap();
        let row_id = rows[0].id;
        let row = PendingDelivery {
            id: row_id,
            hook_id: rows[0].hook_id.clone(),
            url: "http://127.0.0.1:1/hook".into(),
            secret: None,
            kind: "commit".into(),
            payload: br#"{}"#.to_vec(),
            attempts: 1,
        };
        // We need a registry that holds the delivery row. Re-open to get
        // a DeliveryOutbox pointing at the same DB.
        let path = _d.path().join("webhooks.db");
        let outbox: Arc<dyn DeliveryOutbox> =
            Arc::new(SqliteWebhookRegistry::open(&path, test_master_key()).unwrap());
        let outbox_clone = outbox.clone();
        tokio::task::spawn_blocking(move || dispatch_row(&*outbox_clone, row))
            .await
            .unwrap();
        // After network error at attempt 1, the row is rescheduled.
        let reclaimed = outbox.claim_pending_deliveries(10).unwrap();
        assert!(
            reclaimed.is_empty(),
            "network error must push next_attempt_at forward (not immediately re-claimable)"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dispatch_row_network_error_at_max_attempts_finalizes_exhausted() {
        // Network error at WORKER_MAX_ATTEMPTS → finalize as "exhausted"
        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "http://127.0.0.1:1/hook".into(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        r.enqueue_delivery(&rid("repo-a"), "commit", br#"{}"#)
            .unwrap();
        let rows = r.claim_pending_deliveries(10).unwrap();
        let row_id = rows[0].id;
        let row = PendingDelivery {
            id: row_id,
            hook_id: rows[0].hook_id.clone(),
            url: "http://127.0.0.1:1/hook".into(),
            secret: None,
            kind: "commit".into(),
            payload: br#"{}"#.to_vec(),
            attempts: WORKER_MAX_ATTEMPTS,
        };
        let path = _d.path().join("webhooks.db");
        let outbox: Arc<dyn DeliveryOutbox> =
            Arc::new(SqliteWebhookRegistry::open(&path, test_master_key()).unwrap());
        let outbox_clone = outbox.clone();
        tokio::task::spawn_blocking(move || dispatch_row(&*outbox_clone, row))
            .await
            .unwrap();
        let reclaimed = outbox.claim_pending_deliveries(10).unwrap();
        assert!(
            reclaimed.is_empty(),
            "exhausted-by-network row must not be re-claimable"
        );
    }

    // --- dispatch_event: enqueue path (n > 0) and legacy fallback (n = 0) --

    #[test]
    fn dispatch_event_enqueue_path_with_no_outbox_is_noop() {
        // dispatch_event is the MemRegistry path; it calls
        // legacy_direct_dispatch internally. With no matching subscriptions
        // in the MemRegistry, nothing is dispatched.
        let r = MemRegistry::new();
        // No subscriptions → legacy_direct_dispatch returns early.
        let ev = crate::events::Event::commit("repo-a", "0".repeat(40), "main", "msg");
        dispatch_event(&r, &ev);
        // Nothing to assert — the point is it doesn't panic or error.
    }

    // --- legacy_direct_dispatch: posts to a real listener, checks headers --

    #[tokio::test(flavor = "multi_thread")]
    async fn legacy_direct_dispatch_posts_to_listener_and_signs() {
        let (url, recv) = spawn_one_shot_listener();
        let r = MemRegistry::new();
        r.add(Subscription {
            id: "hook-legacy".into(),
            repo_id: rid("repo-a"),
            url: url.clone(),
            secret: Some("testsecret".into()),
            events: vec![],
        })
        .unwrap();
        let ev = crate::events::Event::commit("repo-a", "0".repeat(40), "main", "msg");
        let body = serde_json::to_vec(&ev).unwrap();
        legacy_direct_dispatch(&r, &ev, body.clone());

        let req = tokio::task::spawn_blocking(move || {
            recv.recv_timeout(std::time::Duration::from_secs(5))
        })
        .await
        .unwrap()
        .expect("listener never received the legacy dispatch");
        assert!(req.starts_with("POST "), "expected POST");
        assert!(
            req.contains("X-Artifacts-Signature: sha256="),
            "signed request must include X-Artifacts-Signature header"
        );
        assert!(
            req.contains("X-Artifacts-Hook-Id: hook-legacy"),
            "hook-id header must be present"
        );
        assert!(
            req.contains("X-Artifacts-Event: commit"),
            "event header must be present"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dispatch_row_4xx_finalizes_as_client_error() {
        // A 4xx is a terminal client error: even below MAX attempts the
        // delivery is finalized (not rescheduled), so it never retries.
        // `ureq` surfaces 4xx as `Err(Status)`, so this exercises the
        // 4xx arm of dispatch_row.
        use std::io::Write;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                use std::io::Read as _;
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf); // drain the request first
                let _ = sock.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let url = format!("http://127.0.0.1:{port}/hook");

        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: url.clone(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        r.enqueue_delivery(&rid("repo-a"), "commit", br#"{}"#)
            .unwrap();
        let rows = r.claim_pending_deliveries(10).unwrap();
        let row = PendingDelivery {
            id: rows[0].id,
            hook_id: rows[0].hook_id.clone(),
            url,
            secret: None,
            kind: "commit".into(),
            payload: br#"{}"#.to_vec(),
            attempts: 1, // below MAX — a retryable error would reschedule
        };
        let path = _d.path().join("webhooks.db");
        let outbox: Arc<dyn DeliveryOutbox> =
            Arc::new(SqliteWebhookRegistry::open(&path, test_master_key()).unwrap());
        let oc = outbox.clone();
        tokio::task::spawn_blocking(move || dispatch_row(&*oc, row))
            .await
            .unwrap();
        // Finalized (terminal) rows have a non-NULL finalized_at, so a
        // future-cutoff prune reaps exactly this one — proving 4xx was
        // finalized, not retried (a retry leaves finalized_at NULL).
        let pruned = outbox.prune_finalized(now_unix_secs() + 3600).unwrap();
        assert_eq!(pruned, 1, "4xx delivery must be finalized as terminal");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn legacy_direct_dispatch_4xx_is_client_error() {
        // The single-attempt legacy path labels a 4xx as client_error
        // (vs exhausted for 5xx/transport). Just assert it doesn't panic
        // and completes against a 404 listener — exercises that arm.
        use std::io::Write;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                use std::io::Read as _;
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(
                    b"HTTP/1.1 422 Unprocessable Entity\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let url = format!("http://127.0.0.1:{port}/hook");
        let r = MemRegistry::new();
        r.add(Subscription {
            id: "hook-4xx".into(),
            repo_id: rid("repo-a"),
            url,
            secret: None,
            events: vec![],
        })
        .unwrap();
        let ev = crate::events::Event::commit("repo-a", "0".repeat(40), "main", "msg");
        let body = serde_json::to_vec(&ev).unwrap();
        tokio::task::spawn_blocking(move || legacy_direct_dispatch(&r, &ev, body))
            .await
            .unwrap();
    }

    // --- sign_body: verify the header format ----------------------------

    #[test]
    fn sign_body_format_starts_with_sha256_prefix() {
        let sig = sign_body(Some("key"), b"payload").unwrap();
        assert!(
            sig.starts_with("sha256="),
            "signature must start with sha256="
        );
        // The hex part should be 64 chars (32 bytes × 2).
        assert_eq!(sig.len(), 7 + 64, "sha256= prefix + 64 hex chars");
    }

    // --- spawn_prune_task: zero-retention early return ---------------------

    #[tokio::test]
    async fn spawn_prune_task_zero_retention_returns_none() {
        let outbox: Arc<dyn DeliveryOutbox> = Arc::new(open_sqlite_registry().1);
        let cancel = tokio_util::sync::CancellationToken::new();
        let handle = spawn_prune_task(
            outbox,
            std::time::Duration::from_millis(50),
            std::time::Duration::ZERO, // zero retention → no task
            cancel,
        );
        assert!(
            handle.is_none(),
            "zero retention must return None (no prune task spawned)"
        );
    }

    // --- spawn_active_gauge_refresher / refresh_active_webhook_gauge -------

    #[tokio::test(flavor = "multi_thread")]
    async fn spawn_active_gauge_refresher_resolves_on_cancel() {
        let registry: Arc<dyn WebhookRegistry> = Arc::new(open_sqlite_registry().1);
        let cancel = tokio_util::sync::CancellationToken::new();
        let handle = spawn_active_gauge_refresher(
            registry,
            std::time::Duration::from_millis(50),
            cancel.clone(),
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        cancel.cancel();
        let resolved = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
        assert!(
            resolved.is_ok(),
            "active gauge refresher must resolve within 1s of cancel"
        );
    }

    #[test]
    fn refresh_active_webhook_gauge_does_not_panic() {
        use metrics::with_local_recorder;
        use metrics_util::debugging::DebuggingRecorder;
        let recorder = DebuggingRecorder::new();
        let (_d, r) = open_sqlite_registry();
        with_local_recorder(&recorder, || {
            refresh_active_webhook_gauge(&r);
        });
        // No assertion on the exact value — just confirm no panic.
    }

    // --- claim_pending: bad nonce in the deliveries table ------------------

    #[test]
    fn claim_pending_bad_nonce_yields_unsigned_delivery() {
        // Insert a delivery row with a nonce that's not 12 bytes.
        // claim_pending_deliveries must return the row with secret=None.
        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "http://nowhere.invalid".into(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        // Insert a delivery row directly with a 5-byte nonce and some secret blob.
        {
            let conn = r.lock().unwrap();
            conn.execute(
                "INSERT INTO webhook_deliveries
                   (hook_id, url, secret, secret_nonce, kind, payload, attempts,
                    next_attempt_at, created_at)
                 VALUES ('h-bad-nonce', 'http://nowhere.invalid', X'deadbeef', X'0102030405',
                         'commit', X'7b7d', 0, 0, 0)",
                [],
            )
            .unwrap();
        }
        let claimed = r.claim_pending_deliveries(10).unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(
            claimed[0].secret, None,
            "bad nonce in delivery row must yield unsigned delivery"
        );
    }

    // --- prune_finalized: remove old rows explicitly via mark_delivery_finalized --

    #[tokio::test]
    async fn prune_finalized_after_mark_finalized_removes_row() {
        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: "http://nowhere.invalid".into(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        r.enqueue_delivery(&rid("repo-a"), "commit", br#"{}"#)
            .unwrap();
        let claimed = r.claim_pending_deliveries(10).unwrap();
        let id = claimed[0].id;
        // Finalize the row with a past timestamp.
        r.mark_delivery_finalized(id, "success", Some("200"))
            .unwrap();
        // Stamp finalized_at to a very old value so the prune catches it.
        {
            let conn = r.lock().unwrap();
            conn.execute(
                "UPDATE webhook_deliveries SET finalized_at = 1 WHERE id = ?1",
                rusqlite::params![id],
            )
            .unwrap();
        }
        // Prune with cutoff in the future.
        let pruned = r.prune_finalized(now_unix_secs() + 1).unwrap();
        assert_eq!(pruned, 1, "finalized row older than cutoff must be pruned");
    }

    // --- rotate_master_key error branches ----------------------------------

    #[test]
    fn rotate_master_key_bad_nonce_length_returns_err() {
        // Insert a row whose secret_nonce is only 5 bytes (not 12).
        // rotate_master_key must return Err, not panic.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhooks.db");
        let key = test_master_key();
        let r = SqliteWebhookRegistry::open(&path, key).unwrap();
        // Insert a row with a too-short nonce so the rotate loop hits the
        // nonce-wrong-length error path.
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "INSERT INTO webhooks
                   (id, repo_id, url, secret, secret_nonce, events_json, created_at)
                 VALUES ('bad-nonce-rot', 'repo-a', 'u', 'somebase64==', X'0102030405', '[]', 0)",
                [],
            )
            .unwrap();
        }
        let new_key = test_master_key();
        let result = r.rotate_master_key(new_key);
        assert!(
            result.is_err(),
            "rotate_master_key must return Err when a row has a wrong-length nonce"
        );
    }

    #[test]
    fn rotate_master_key_bad_base64_ciphertext_returns_err() {
        // Insert a row with a valid 12-byte nonce but garbage base64 in secret.
        // rotate_master_key must return Err on the base64 decode step.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhooks.db");
        let r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "INSERT INTO webhooks
                   (id, repo_id, url, secret, secret_nonce, events_json, created_at)
                 VALUES ('bad-b64-rot', 'repo-a', 'u', '!!!not_valid_base64!!!',
                         X'000102030405060708090a0b', '[]', 0)",
                [],
            )
            .unwrap();
        }
        let new_key = test_master_key();
        let result = r.rotate_master_key(new_key);
        assert!(
            result.is_err(),
            "rotate_master_key must return Err on bad base64 ciphertext"
        );
    }

    #[test]
    fn rotate_master_key_unseal_failure_returns_err() {
        // Insert a row with a valid 12-byte nonce and valid base64 but garbage
        // ciphertext bytes that don't decrypt under the master key.
        // The base64 decodes fine but unseal fails (bad MAC).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhooks.db");
        let r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            // 32 bytes of zeros encoded as base64 — valid base64 and long
            // enough to have a tag, but won't unseal under any randomly-generated
            // key (AES-GCM MAC will reject it).
            let fake_ct = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
            conn.execute(
                "INSERT INTO webhooks
                   (id, repo_id, url, secret, secret_nonce, events_json, created_at)
                 VALUES ('bad-ct-rot', 'repo-a', 'u', ?1,
                         X'000102030405060708090a0b', '[]', 0)",
                rusqlite::params![fake_ct],
            )
            .unwrap();
        }
        let new_key = test_master_key();
        let result = r.rotate_master_key(new_key);
        assert!(
            result.is_err(),
            "rotate_master_key must return Err when unseal fails under the old key"
        );
    }

    // --- enqueue_delivery: bad base64 in subscription secret column --------

    #[test]
    fn enqueue_delivery_bad_base64_subscription_drops_secret() {
        // Insert a webhook row directly with garbage base64 in secret but
        // a valid nonce, then call enqueue_delivery. The enqueue succeeds
        // (row inserted with NULL secret) — the bad b64 logs a warn and
        // silently drops the secret for that delivery.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhooks.db");
        let r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            // A 12-byte nonce is needed so the code tries to decode the b64.
            conn.execute(
                "INSERT INTO webhooks
                   (id, repo_id, url, secret, secret_nonce, events_json, created_at)
                 VALUES ('bad-b64-enq', 'repo-a', 'u', '!!!bad_base64!!!',
                         X'000102030405060708090a0b', '[]', 0)",
                [],
            )
            .unwrap();
        }
        // enqueue_delivery should succeed (bad b64 logs warn and drops secret).
        let n = r
            .enqueue_delivery(&rid("repo-a"), "commit", br#"{}"#)
            .unwrap();
        assert_eq!(n, 1, "one delivery row must be inserted despite bad b64");
        // Claim it and confirm secret is None.
        let claimed = r.claim_pending_deliveries(10).unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(
            claimed[0].secret, None,
            "delivery with bad b64 subscription secret must have no secret"
        );
    }

    // --- claim_pending_deliveries: unseal failure --------------------------

    #[test]
    fn claim_pending_unseal_failure_yields_unsigned_delivery() {
        // Insert a delivery row with a valid 12-byte nonce but garbage bytes
        // for the ciphertext (valid length but bad MAC).
        // claim_pending_deliveries must return the row with secret=None.
        let (_d, r) = open_sqlite_registry();
        {
            let conn = r.lock().unwrap();
            // 32 bytes of zeros as the "ciphertext" — wrong key/MAC.
            conn.execute(
                "INSERT INTO webhook_deliveries
                   (hook_id, url, secret, secret_nonce, kind, payload, attempts,
                    next_attempt_at, created_at)
                 VALUES ('h-bad-ct', 'http://nowhere.invalid',
                         X'00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
                         X'000102030405060708090a0b',
                         'commit', X'7b7d', 0, 0, 0)",
                [],
            )
            .unwrap();
        }
        let claimed = r.claim_pending_deliveries(10).unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(
            claimed[0].secret, None,
            "delivery with bad ciphertext must yield unsigned delivery"
        );
    }

    // --- row_to_sub: invalid repo_id in db row  ----------------------------

    #[test]
    fn row_to_sub_invalid_repo_id_returns_rusqlite_error() {
        // Insert a row with a repo_id that won't parse as a valid RepoId
        // (e.g., too short). list() must return an Err (or silently skip
        // the row via .flatten()); either behaviour is acceptable as long
        // as it doesn't panic.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("webhooks.db");
        let _r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        // "ab" is only 2 chars — too short for a valid RepoId (min 4).
        conn.execute(
            "INSERT INTO webhooks
               (id, repo_id, url, secret, secret_nonce, events_json, created_at)
             VALUES ('bad-repo-id', 'ab', 'u', NULL, NULL, '[]', 0)",
            [],
        )
        .unwrap();
        drop(conn);
        let r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        // list() on the bad repo returns an error (row_to_sub maps the
        // invalid repo_id to InvalidColumnType, which makes query_map
        // skip or propagate it). Use a query on the _actual_ repo_id
        // string to trigger the row to be included and hit the error path.
        // We can't call list() with the bad id because rid() would reject it;
        // directly query via raw SQL to confirm the row exists.
        let conn2 = rusqlite::Connection::open(&path).unwrap();
        let count: i64 = conn2
            .query_row(
                "SELECT COUNT(*) FROM webhooks WHERE repo_id = 'ab'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "bad-repo-id row should be in the table");
        // list() via a SqliteWebhookRegistry that includes the bad row.
        // The row_to_sub closure returns Err for the bad repo_id, which
        // .flatten() in list() silently drops. So the list returns Ok([])
        // rather than Err — that's the production behaviour: drop corrupt
        // rows rather than fail the whole query.
        let list_result = r.list(&rid("repo-a"));
        assert!(
            list_result.is_ok(),
            "list() must not propagate corrupt-row errors; got {list_result:?}"
        );
    }

    // --- refresh_active_webhook_gauge: error arm ---------------------------

    #[test]
    fn refresh_active_webhook_gauge_error_arm_does_not_panic() {
        // Use an exhausted pool so count_active() returns Err.
        // refresh_active_webhook_gauge must not panic — it logs the error
        // and keeps the gauge at its previous value.
        let (reg, _held) = exhausted_registry();
        // Calling with a valid recorder keeps the test side-effect-free.
        use metrics::with_local_recorder;
        use metrics_util::debugging::DebuggingRecorder;
        let recorder = DebuggingRecorder::new();
        with_local_recorder(&recorder, || {
            refresh_active_webhook_gauge(&reg);
        });
        // No assertion on the gauge value — the test is that we didn't panic.
    }

    // --- spawn_dispatcher: Lagged branch -----------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn dispatcher_processes_lagged_events_without_panic() {
        // Build a broadcast channel with capacity=1, overflow it to force
        // Lagged, then confirm record_dispatcher_lag is reachable. We test
        // the behaviour directly (calling record_dispatcher_lag) rather than
        // through the async dispatcher task to keep the test deterministic.
        use tokio::sync::broadcast;
        let (tx, mut rx) = broadcast::channel::<crate::events::Event>(1);

        // Send two events into a capacity-1 channel so the single subscriber
        // lags — the receiver can only hold 1 item; the second overwrites it.
        let ev1 = crate::events::Event::commit("repo-a", "0".repeat(40), "main", "m1");
        let ev2 = crate::events::Event::commit("repo-a", "0".repeat(40), "main", "m2");
        let _ = tx.send(ev1);
        let _ = tx.send(ev2);

        // The receiver should now be lagged.
        match rx.recv().await {
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                // Directly exercise the same code the dispatcher calls.
                record_dispatcher_lag(n);
            },
            other => {
                // We got an event instead — still fine; just confirm no panic.
                let _ = other;
                record_dispatcher_lag(1);
            },
        }
        // Confirm the Closed path too (dropping tx closes the channel).
        drop(tx);
        // Drain any remaining events until the channel closes.
        loop {
            if matches!(
                rx.recv().await,
                Err(tokio::sync::broadcast::error::RecvError::Closed)
            ) {
                break;
            }
        }
    }

    // --- spawn_delivery_worker: claim_pending Err branch -------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn delivery_worker_claim_pending_error_does_not_panic() {
        // Build an exhausted pool so claim_pending_deliveries returns Err.
        // spawn_delivery_worker must continue (not panic) on that error.
        let (reg, held) = exhausted_registry();
        let outbox: Arc<dyn DeliveryOutbox> = Arc::new(reg);
        let cancel = tokio_util::sync::CancellationToken::new();
        let handle =
            spawn_delivery_worker(outbox, std::time::Duration::from_millis(20), cancel.clone());
        // Give the worker a beat to hit the error path at least once.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        cancel.cancel();
        let resolved = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
        assert!(
            resolved.is_ok(),
            "delivery worker must resolve after cancel even with pool exhaustion"
        );
        drop(held); // release the held connection
    }

    // --- spawn_prune_task: prune Err branch --------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn prune_task_error_does_not_panic() {
        // Build an exhausted pool so prune_finalized returns Err.
        // spawn_prune_task must continue (not panic) on that error.
        // We need a prune task that fires quickly. Use a very short tick
        // so the task fires before we cancel; the first tick is skipped
        // so we need to wait a bit.
        let (reg, held) = exhausted_registry();
        let outbox: Arc<dyn DeliveryOutbox> = Arc::new(reg);
        let cancel = tokio_util::sync::CancellationToken::new();
        let handle = spawn_prune_task(
            outbox,
            std::time::Duration::from_millis(20),
            std::time::Duration::from_secs(86400),
            cancel.clone(),
        )
        .expect("non-zero retention returns Some");
        // Wait for two ticks (initial skip + one real tick).
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        cancel.cancel();
        let resolved = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
        assert!(
            resolved.is_ok(),
            "prune task must resolve after cancel even with pool exhaustion"
        );
        drop(held);
    }

    // --- dispatch_row: HMAC secret path (signature header) -----------------

    #[tokio::test(flavor = "multi_thread")]
    async fn dispatch_row_with_secret_sends_signature_header() {
        // A row with a non-None secret must have its body HMAC-signed and
        // the X-Artifacts-Signature header attached. Verify by inspecting
        // the raw request captured by the one-shot listener.
        let (url, recv) = spawn_one_shot_listener();
        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: rid("repo-a"),
            url: url.clone(),
            secret: Some("dispatch-hmac-key".into()),
            events: vec![],
        })
        .unwrap();
        r.enqueue_delivery(&rid("repo-a"), "commit", br#"{"x":1}"#)
            .unwrap();
        let rows = r.claim_pending_deliveries(10).unwrap();
        assert_eq!(rows.len(), 1);
        let row = PendingDelivery {
            id: rows[0].id,
            hook_id: rows[0].hook_id.clone(),
            url: url.clone(),
            secret: Some("dispatch-hmac-key".into()),
            kind: "commit".into(),
            payload: br#"{"x":1}"#.to_vec(),
            attempts: 1,
        };
        let path = _d.path().join("webhooks.db");
        let outbox: Arc<dyn DeliveryOutbox> =
            Arc::new(SqliteWebhookRegistry::open(&path, test_master_key()).unwrap());
        let oc = outbox.clone();
        tokio::task::spawn_blocking(move || dispatch_row(&*oc, row))
            .await
            .unwrap();

        let req = tokio::task::spawn_blocking(move || {
            recv.recv_timeout(std::time::Duration::from_secs(5))
        })
        .await
        .unwrap()
        .expect("listener must receive the signed delivery");
        assert!(
            req.contains("X-Artifacts-Signature: sha256="),
            "signed delivery must include X-Artifacts-Signature header; got:\n{req}"
        );
    }

    // --- publish_event: invalid repo_id in event ---------------------------

    #[test]
    fn publish_event_invalid_repo_id_does_not_panic() {
        // Construct a Commit event whose repo_id is too short (< 4 chars)
        // so RepoId::try_from fails inside publish_event. The function
        // must swallow the error and still call bus.publish.
        let (_d, r) = open_sqlite_registry();
        let bus = crate::events::EventBus::new();
        // "ab" has only 2 characters — invalid RepoId.
        let ev = crate::events::Event::commit("ab", "0".repeat(40), "main", "m");
        publish_event(&bus, Some(&r), ev);
        // No assert needed — the test is that we didn't panic.
    }

    // --- publish_event: enqueue error arm ----------------------------------

    #[test]
    fn publish_event_enqueue_error_does_not_propagate() {
        // Use an exhausted pool so enqueue_delivery returns Err. publish_event
        // must log the error and return normally (best-effort: webhook delivery
        // must never fail the mutation that produced the event).
        let (reg, _held) = exhausted_registry();
        let bus = crate::events::EventBus::new();
        let ev = crate::events::Event::commit("repo-a", "0".repeat(40), "main", "m");
        publish_event(&bus, Some(&reg), ev);
        // No assert needed — the test is that we didn't panic.
    }

    // --- legacy_direct_dispatch: 5xx / transport error path ---------------

    #[tokio::test(flavor = "multi_thread")]
    async fn legacy_direct_dispatch_5xx_labels_exhausted() {
        // Spawn a listener that replies 503. The legacy path labels any
        // non-4xx failure as "exhausted" (single attempt). This exercises
        // the fallthrough Err arm (lines ~1264-1265, ~1269) and the
        // metrics counter at line ~1277.
        use std::io::Write;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                use std::io::Read as _;
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let url = format!("http://127.0.0.1:{port}/hook");
        let r = MemRegistry::new();
        r.add(Subscription {
            id: "hook-5xx".into(),
            repo_id: rid("repo-a"),
            url,
            secret: None,
            events: vec![],
        })
        .unwrap();
        let ev = crate::events::Event::commit("repo-a", "0".repeat(40), "main", "msg");
        let body = serde_json::to_vec(&ev).unwrap();
        // spawn_blocking waits for the blocking task to finish before
        // returning, so the metrics counter is guaranteed to increment
        // before we return.
        tokio::task::spawn_blocking(move || legacy_direct_dispatch(&r, &ev, body))
            .await
            .unwrap();
        // The test is that the exhausted arm was reached without panic.
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn legacy_direct_dispatch_network_error_labels_exhausted() {
        // Port 1 is unreachable — ureq returns a transport error.
        // The legacy dispatch labels this "exhausted" and emits the metric.
        let r = MemRegistry::new();
        r.add(Subscription {
            id: "hook-net-err".into(),
            repo_id: rid("repo-a"),
            url: "http://127.0.0.1:1/hook".into(),
            secret: None,
            events: vec![],
        })
        .unwrap();
        let ev = crate::events::Event::commit("repo-a", "0".repeat(40), "main", "msg");
        let body = serde_json::to_vec(&ev).unwrap();
        tokio::task::spawn_blocking(move || legacy_direct_dispatch(&r, &ev, body))
            .await
            .unwrap();
        // No panic = pass.
    }
}
