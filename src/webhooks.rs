//! Outbound webhook delivery.
//!
//! What this is: subscribers register a URL + secret with a repo,
//! and we POST a JSON event body to that URL whenever an event fires
//! for that repo on the in-process bus. Each delivery is signed with
//! HMAC-SHA256 over the body, with the digest in
//! `X-Artifacts-Signature: sha256=<hex>` so subscribers can verify
//! authenticity without trusting the network path.
//!
//! ## What this is *not*
//!
//! - Durable. Subscriptions live in memory; restarting the process
//!   loses them. The store is behind the `WebhookRegistry` trait so a
//!   future SQLite impl drops in without touching the rest of the
//!   plumbing — same shape as `TokenStore` / `OwnershipStore`.
//! - Reliable. Each delivery is best-effort: one HTTP attempt, no
//!   retries, no dead-letter queue. Subscribers that need
//!   exactly-once should poll `/v1/events` SSE instead. M6-deliver
//!   adds retries with exponential backoff.
//! - Observable beyond stderr. Per-delivery status lives in the
//!   `tracing` log only; a future commit can plumb counts through
//!   the Prometheus exporter.
//!
//! ## Threading
//!
//! Delivery runs on a dedicated `tokio::spawn_blocking` per-event so
//! that a slow webhook target can't tie up axum's request workers.
//! `ureq` is sync, which suits this use case — the spawn_blocking
//! call sleeps the blocking-pool thread, never the tokio reactor.

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
    pub repo_id: String,
    pub url: String,
    /// HMAC-SHA256 secret. Stored in plaintext today (no DB to hash
    /// against); when the SQLite-backed registry lands it should be
    /// stored hashed the same way TokenStore does.
    #[serde(skip_serializing)]
    pub secret: Option<String>,
    /// Subset of event kinds to fire on. Empty = all kinds.
    pub events: Vec<String>,
}

/// The registry contract. In-memory `MemRegistry` is the only impl
/// today; SQLite-backed comes when subscriptions need to survive a
/// restart.
pub trait WebhookRegistry: Send + Sync {
    fn add(&self, sub: Subscription) -> String;
    fn list(&self, repo_id: &str) -> Vec<Subscription>;
    fn remove(&self, repo_id: &str, hook_id: &str) -> bool;
    fn matching(&self, repo_id: &str, kind: &str) -> Vec<Subscription>;

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
    conn: Arc<std::sync::Mutex<rusqlite::Connection>>,
    /// Symmetric key used to seal/unseal `secret`. Wrapped in
    /// `RwLock<Arc<…>>` so `rotate_master_key` can swap it
    /// in-process. Reads (every `add` / `list`) clone the `Arc`
    /// under the read lock and drop the lock immediately, so a
    /// rotation only blocks readers for the brief swap window.
    master_key: std::sync::RwLock<Arc<crate::secrets::MasterKey>>,
}

const MIGRATIONS: [crate::db_migrate::Migration; 2] = [
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
];

impl SqliteWebhookRegistry {
    pub fn open(
        path: &std::path::Path,
        master_key: Arc<crate::secrets::MasterKey>,
    ) -> crate::error::Result<Self> {
        let conn = crate::db_migrate::open_with_migrations(path, "webhooks", &MIGRATIONS)?;
        Ok(Self {
            conn: Arc::new(std::sync::Mutex::new(conn)),
            master_key: std::sync::RwLock::new(master_key),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, rusqlite::Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
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
    fn add(&self, mut sub: Subscription) -> String {
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
                }
            },
            None => (None, None),
        };

        let _ = self.lock().execute(
            "INSERT INTO webhooks (id, repo_id, url, secret, secret_nonce, events_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                sub.id,
                sub.repo_id,
                sub.url,
                secret_b64,
                nonce_blob,
                events,
                now
            ],
        );
        sub.id
    }

    fn list(&self, repo_id: &str) -> Vec<Subscription> {
        let conn = self.lock();
        let mut stmt = match conn.prepare_cached(
            "SELECT id, repo_id, url, secret, secret_nonce, events_json
             FROM webhooks
             WHERE repo_id = ?1 AND revoked_at IS NULL",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let key = self.current_key();
        let rows = stmt.query_map(rusqlite::params![repo_id], move |row| row_to_sub(row, &key));
        let rows = match rows {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        rows.flatten().collect()
    }

    fn remove(&self, repo_id: &str, hook_id: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let conn = self.lock();
        let n = conn
            .execute(
                "UPDATE webhooks SET revoked_at = ?1
                 WHERE id = ?2 AND repo_id = ?3 AND revoked_at IS NULL",
                rusqlite::params![now, hook_id, repo_id],
            )
            .unwrap_or(0);
        n > 0
    }

    fn matching(&self, repo_id: &str, kind: &str) -> Vec<Subscription> {
        // Filter in Rust rather than embed the JSON LIKE in SQL so
        // we don't depend on JSON1 being compiled in. Subscription
        // counts per repo are small (dozens at most), so this is
        // fine.
        self.list(repo_id)
            .into_iter()
            .filter(|s| s.events.is_empty() || s.events.iter().any(|e| e == kind))
            .collect()
    }

    fn count_active(&self) -> crate::error::Result<u64> {
        let conn = self.lock();
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
        let mut conn = self.lock();
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

fn row_to_sub(
    row: &rusqlite::Row<'_>,
    key: &crate::secrets::MasterKey,
) -> rusqlite::Result<Subscription> {
    let id: String = row.get(0)?;
    let repo_id: String = row.get(1)?;
    let url: String = row.get(2)?;
    let stored_secret: Option<String> = row.get(3)?;
    let nonce_blob: Option<Vec<u8>> = row.get(4)?;
    let events_json: String = row.get(5)?;
    let events: Vec<String> = serde_json::from_str(&events_json).unwrap_or_default();

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
                }
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
                }
            };
            match crate::secrets::unseal(key, &ct, &nonce) {
                Ok(pt) => match String::from_utf8(pt) {
                    Ok(s) => Some(s),
                    Err(_) => {
                        tracing::warn!(hook_id = %id, "webhook secret not valid UTF-8 after unseal");
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!(hook_id = %id, error = %e, "webhook secret unseal failed");
                    None
                }
            }
        }
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
    fn add(&self, mut sub: Subscription) -> String {
        if sub.id.is_empty() {
            sub.id = Uuid::new_v4().to_string();
        }
        let id = sub.id.clone();
        self.lock().push(sub);
        id
    }

    fn list(&self, repo_id: &str) -> Vec<Subscription> {
        self.lock()
            .iter()
            .filter(|s| s.repo_id == repo_id)
            .cloned()
            .collect()
    }

    fn remove(&self, repo_id: &str, hook_id: &str) -> bool {
        let mut g = self.lock();
        let before = g.len();
        g.retain(|s| !(s.repo_id == repo_id && s.id == hook_id));
        before != g.len()
    }

    fn matching(&self, repo_id: &str, kind: &str) -> Vec<Subscription> {
        self.lock()
            .iter()
            .filter(|s| s.repo_id == repo_id)
            .filter(|s| s.events.is_empty() || s.events.iter().any(|e| e == kind))
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
pub fn spawn_active_gauge_refresher(registry: Arc<dyn WebhookRegistry>, tick: std::time::Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tick);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            refresh_active_webhook_gauge(&*registry);
        }
    });
}

/// Long-lived task that subscribes to the event bus and dispatches
/// each event to every matching subscription. Owns its own broadcast
/// receiver; the registry handle is shared with the REST endpoints
/// so add/list/remove see the same set the dispatcher walks.
pub fn spawn_dispatcher(registry: Arc<dyn WebhookRegistry>, bus: crate::events::EventBus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(ev) => dispatch_event(&*registry, &ev).await,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(dropped = n, "webhook dispatcher lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

async fn dispatch_event(registry: &dyn WebhookRegistry, ev: &Event) {
    let (repo_id, kind) = repo_and_kind(ev);
    let subs = registry.matching(repo_id, kind);
    if subs.is_empty() {
        return;
    }
    let body = match serde_json::to_vec(ev) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "webhook serialize failed");
            return;
        }
    };
    for sub in subs {
        let body = body.clone();
        // ureq is sync — push it onto the blocking pool so a slow
        // webhook target can't stall the tokio runtime. We retry
        // up to MAX_ATTEMPTS times with exponential backoff so a
        // brief receiver outage doesn't drop events; permanent
        // failures still log and give up.
        tokio::task::spawn_blocking(move || {
            const MAX_ATTEMPTS: u32 = 3;
            // 0.5s, 1s, 2s — total worst-case wall time ~3.5s
            // on top of per-attempt timeout. Picked low because a
            // running event bus shouldn't queue events behind a
            // single dead subscription for a minute+.
            const BACKOFF_BASE_MS: u64 = 500;

            let signature = sign_body(sub.secret.as_deref(), &body);
            let kind = kind_str(&body);
            for attempt in 1..=MAX_ATTEMPTS {
                let agent = ureq::AgentBuilder::new()
                    .timeout(std::time::Duration::from_secs(5))
                    .build();
                let mut req = agent
                    .post(&sub.url)
                    .set("Content-Type", "application/json")
                    .set("X-Artifacts-Hook-Id", &sub.id)
                    .set("X-Artifacts-Event", &kind)
                    .set("X-Artifacts-Attempt", &attempt.to_string());
                if let Some(sig) = signature.as_deref() {
                    req = req.set("X-Artifacts-Signature", sig);
                }
                let outcome = match req.send_bytes(&body) {
                    Ok(resp) => {
                        let status = resp.status();
                        if (200..400).contains(&status) {
                            metrics::counter!(
                                "artifacts_webhook_deliveries_total",
                                "kind" => kind.clone(),
                                "outcome" => "success",
                            )
                            .increment(1);
                            return;
                        }
                        // Treat 5xx as retryable, 4xx as terminal —
                        // the receiver is telling us the request is
                        // wrong, retrying won't help. Mirrors what
                        // most webhook frameworks do.
                        if (500..600).contains(&status) {
                            tracing::warn!(
                                hook = %sub.id, url = %sub.url, status, attempt,
                                "webhook 5xx; will retry"
                            );
                            "retry"
                        } else {
                            tracing::warn!(
                                hook = %sub.id, url = %sub.url, status, attempt,
                                "webhook 4xx; not retrying"
                            );
                            metrics::counter!(
                                "artifacts_webhook_deliveries_total",
                                "kind" => kind.clone(),
                                "outcome" => "client_error",
                            )
                            .increment(1);
                            return;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            hook = %sub.id, url = %sub.url, attempt, error = %e,
                            "webhook delivery failed; will retry"
                        );
                        "retry"
                    }
                };

                if attempt < MAX_ATTEMPTS && outcome == "retry" {
                    let delay_ms = BACKOFF_BASE_MS * (1u64 << (attempt - 1));
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                }
            }
            metrics::counter!(
                "artifacts_webhook_deliveries_total",
                "kind" => kind.clone(),
                "outcome" => "exhausted",
            )
            .increment(1);
            tracing::warn!(
                hook = %sub.id, url = %sub.url,
                "webhook delivery gave up after {} attempts", MAX_ATTEMPTS,
            );
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

/// Read the `kind` value out of the already-serialized event body.
/// Used to set the `X-Artifacts-Event` header without re-borrowing
/// the typed Event after we've moved the body into a blocking task.
fn kind_str(body: &[u8]) -> String {
    let s = std::str::from_utf8(body).unwrap_or("");
    if let Some(start) = s.find("\"kind\":\"") {
        let after = &s[start + 8..];
        if let Some(end) = after.find('"') {
            return after[..end].to_string();
        }
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_then_list_round_trip() {
        let r = MemRegistry::new();
        let id = r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "http://example".into(),
            secret: None,
            events: vec![],
        });
        assert!(!id.is_empty());
        let listed = r.list("r1");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, id);
    }

    #[test]
    fn list_filters_by_repo() {
        let r = MemRegistry::new();
        r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "u1".into(),
            secret: None,
            events: vec![],
        });
        r.add(Subscription {
            id: String::new(),
            repo_id: "r2".into(),
            url: "u2".into(),
            secret: None,
            events: vec![],
        });
        assert_eq!(r.list("r1").len(), 1);
        assert_eq!(r.list("r2").len(), 1);
        assert_eq!(r.list("r3").len(), 0);
    }

    #[test]
    fn remove_targets_specific_hook_only() {
        let r = MemRegistry::new();
        let id1 = r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "u1".into(),
            secret: None,
            events: vec![],
        });
        let id2 = r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "u2".into(),
            secret: None,
            events: vec![],
        });
        assert!(r.remove("r1", &id1));
        let rem = r.list("r1");
        assert_eq!(rem.len(), 1);
        assert_eq!(rem[0].id, id2);
        // removing again is a no-op.
        assert!(!r.remove("r1", &id1));
    }

    #[test]
    fn matching_filters_by_kind_when_events_set() {
        let r = MemRegistry::new();
        r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "u-all".into(),
            secret: None,
            events: vec![],
        });
        r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "u-commit".into(),
            secret: None,
            events: vec!["commit".into()],
        });
        let m_commit = r.matching("r1", "commit");
        assert_eq!(m_commit.len(), 2);
        let m_fork = r.matching("r1", "fork");
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

    #[test]
    fn kind_str_extracts_the_kind_key() {
        let body = br#"{"kind":"commit","repoId":"r1"}"#;
        assert_eq!(kind_str(body), "commit");
    }

    #[test]
    fn kind_str_returns_unknown_on_garbage() {
        assert_eq!(kind_str(b"not json"), "unknown");
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
        let id = r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "http://example".into(),
            secret: Some("s".into()),
            events: vec!["commit".into()],
        });
        let listed = r.list("r1");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, id);
        assert_eq!(listed[0].secret.as_deref(), Some("s"));
        assert_eq!(listed[0].events, vec!["commit".to_string()]);
    }

    #[test]
    fn sqlite_remove_marks_revoked_and_drops_from_list() {
        let (_d, r) = open_sqlite_registry();
        let id = r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "u".into(),
            secret: None,
            events: vec![],
        });
        assert!(r.remove("r1", &id));
        assert!(r.list("r1").is_empty());
        // Idempotent: a second remove finds no live row.
        assert!(!r.remove("r1", &id));
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
                repo_id: "r1".into(),
                url: "u".into(),
                secret: Some("k".into()),
                events: vec![],
            })
        };
        // Drop, reopen on the same path. Must see the row.
        let r = SqliteWebhookRegistry::open(&path, key).unwrap();
        let listed = r.list("r1");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, id);
        assert_eq!(listed[0].secret.as_deref(), Some("k"));
    }

    #[test]
    fn sqlite_matching_filters_by_kind() {
        let (_d, r) = open_sqlite_registry();
        r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "u-all".into(),
            secret: None,
            events: vec![],
        });
        r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "u-commit".into(),
            secret: None,
            events: vec!["commit".into()],
        });
        let m_commit = r.matching("r1", "commit");
        assert_eq!(m_commit.len(), 2);
        let m_fork = r.matching("r1", "fork");
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
            repo_id: "r1".into(),
            url: "u".into(),
            secret: Some("plaintext-marker-XYZ".into()),
            events: vec![],
        });
        // Raw read against the same DB file. Must NOT see "plaintext-marker-XYZ".
        let conn = rusqlite::Connection::open(&path).unwrap();
        let (stored_secret, nonce): (Option<String>, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT secret, secret_nonce FROM webhooks WHERE repo_id = 'r1'",
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
                repo_id: "r1".into(),
                url: "u".into(),
                secret: Some("k".into()),
                events: vec![],
            });
        }
        let k2 = test_master_key(); // fresh, unrelated
        let r = SqliteWebhookRegistry::open(&path, k2).unwrap();
        let listed = r.list("r1");
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
             VALUES ('legacy-hook', 'r1', 'u', 'legacy-plaintext-secret', NULL, '[]', 0)",
            [],
        )
        .unwrap();
        drop(conn);
        // Reopen via the registry with a (different) key — legacy rows
        // ignore the key entirely.
        let r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        let listed = r.list("r1");
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
            repo_id: "r1".into(),
            url: "u".into(),
            secret: Some("alpha".into()),
            events: vec![],
        });
        r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "u".into(),
            secret: Some("beta".into()),
            events: vec![],
        });

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
        let listed = r.list("r1");
        let mut plaintexts: Vec<&str> = listed.iter().filter_map(|s| s.secret.as_deref()).collect();
        plaintexts.sort();
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
            repo_id: "r1".into(),
            url: "u".into(),
            secret: Some("post-rotate".into()),
            events: vec![],
        });
        // Rebuild a registry against the OLD key — the row added after
        // rotation must come back unsigned (key mismatch handled the
        // same way as in `sqlite_wrong_key_yields_unsigned_subscription`).
        drop(r);
        let r_old = SqliteWebhookRegistry::open(&path, k1).unwrap();
        let listed = r_old.list("r1");
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
             VALUES ('legacy-1', 'r1', 'u', 'legacy-plaintext', NULL, '[]', 0)",
            [],
        )
        .unwrap();
        drop(conn);
        let r = SqliteWebhookRegistry::open(&path, test_master_key()).unwrap();
        // Add an encrypted row alongside.
        r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "u".into(),
            secret: Some("encrypted-row".into()),
            events: vec![],
        });
        let rotated = r.rotate_master_key(test_master_key()).unwrap();
        assert_eq!(
            rotated, 1,
            "legacy row should be skipped, only the encrypted row touched"
        );
        // Legacy row still readable as plaintext.
        let listed = r.list("r1");
        let plaintexts: Vec<&str> = listed.iter().filter_map(|s| s.secret.as_deref()).collect();
        assert!(plaintexts.contains(&"legacy-plaintext"));
        assert!(plaintexts.contains(&"encrypted-row"));
    }
}
