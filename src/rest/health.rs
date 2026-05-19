//! Liveness and readiness probes.
//!
//! `/v1/health` is a cheap "the process is up" check.
//! `/v1/health/ready` exercises the SQLite stores so an orchestrator
//! catches a server that's running but can't serve traffic.

use super::RestState;
use crate::{
    audit::AuditStore,
    ownership::OwnershipStore,
    tokens::TokenStore,
};
use axum::{extract::State, Json};

/// GET /v1/health
pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

/// `GET /v1/health/ready`
///
/// Readiness probe — distinct from `/v1/health` (the cheap liveness
/// probe). Exercises the SQLite stores so k8s / systemd / load
/// balancers catch a server that's running but can't actually serve
/// traffic (DB file unreadable, schema drift, disk full, …).
///
/// Returns 200 with `{ok:true, components:{tokens:"ok", audit:"ok",
/// ownership:"ok"}}` when every store responds. Returns 503 with
/// `ok:false` and the failing component(s) flagged when any store
/// errors out — k8s then refuses to route traffic to the pod.
///
/// Each component check has a 1-second deadline. Slow-but-not-broken
/// stores fail closed rather than blocking the probe; an indefinitely
/// hung probe is worse than one that flags a problem and lets the
/// orchestrator decide.
///
/// No auth — same as `/v1/health`. Probe traffic shouldn't need
/// credentials.
pub async fn health_ready(
    State(state): State<RestState>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    if let Some(resp) = drain_response_if_draining(&state.runtime.draining) {
        return resp;
    }
    probe_stores(&*state.authn.tokens, &*state.observ.audit, &*state.data.ownership).await
}

/// Pure helper: short-circuit readiness with `503 + {draining: true}`
/// when the shared drain flag is set. Returning `Some` skips the
/// store probes entirely so a draining process responds fast even
/// if the stores are themselves under load. Lifted out of
/// `health_ready` so the contract is unit-testable without
/// constructing a full `RestState`.
pub(crate) fn drain_response_if_draining(
    draining: &std::sync::atomic::AtomicBool,
) -> Option<(axum::http::StatusCode, Json<serde_json::Value>)> {
    use std::sync::atomic::Ordering;
    if draining.load(Ordering::Relaxed) {
        Some((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "ok": false,
                "draining": true,
            })),
        ))
    } else {
        None
    }
}

/// Run the store-health probes that back the readiness response.
/// Each probe runs against a 1s deadline so a stuck SQLite write
/// doesn't make the response itself stuck. Lifted out of
/// `health_ready` so it can be unit-tested with stub stores
/// without standing up a full `RestState`.
async fn probe_stores(
    tokens: &dyn TokenStore,
    audit: &dyn AuditStore,
    ownership: &dyn OwnershipStore,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    use axum::http::StatusCode;
    use std::time::Duration;
    let deadline = Duration::from_secs(1);
    let tokens_ok = matches!(
        tokio::time::timeout(deadline, tokens.lookup("__health_ready_probe__")).await,
        Ok(Ok(_))
    );
    let audit_ok = matches!(
        tokio::time::timeout(deadline, audit.count()).await,
        Ok(Ok(_))
    );
    let ownership_ok = matches!(
        tokio::time::timeout(deadline, ownership.count_all()).await,
        Ok(Ok(_))
    );
    let all_ok = tokens_ok && audit_ok && ownership_ok;
    let body = serde_json::json!({
        "ok": all_ok,
        "components": {
            "tokens":    if tokens_ok    { "ok" } else { "fail" },
            "audit":     if audit_ok     { "ok" } else { "fail" },
            "ownership": if ownership_ok { "ok" } else { "fail" },
        }
    });
    let status = if all_ok {
        StatusCode::OK
    } else {
        tracing::warn!(
            tokens_ok, audit_ok, ownership_ok,
            "/v1/health/ready failing — orchestrator should refuse traffic"
        );
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body))
}

#[cfg(test)]
mod tests {
    //! Pin the readiness-probe contract:
    //!   - drain flag short-circuits to 503 + `{draining: true}`,
    //!     skipping the store probes entirely
    //!   - probe-store success → 200 + `{ok: true, components: ...}`
    //!   - one failing store → 503 + that component flagged `fail`
    //!
    //! The smoke test exercises this against a real server, but the
    //! contract is small enough that pinning it as a unit test
    //! catches refactor regressions earlier than a 30s smoke run.
    use super::*;
    use crate::audit::{AuditEvent, AuditQuery, AuditStore, NoopAuditStore};
    use crate::error::{Error, Result};
    use crate::ownership::{OwnershipStore, RepoRow};
    use crate::tokens::{Scope, TokenRecord, TokenStore};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// Minimal `TokenStore` whose `lookup` outcome is configurable.
    /// Every other trait method either has a default impl or panics
    /// (we never exercise them from `health_ready`).
    struct StubTokenStore {
        lookup_succeeds: bool,
    }

    #[async_trait]
    impl TokenStore for StubTokenStore {
        async fn mint(&self, _: &str, _: Scope, _: Option<Duration>, _: Option<&str>) -> Result<String> {
            unreachable!("health_ready does not mint")
        }
        async fn lookup(&self, _: &str) -> Result<Option<TokenRecord>> {
            if self.lookup_succeeds {
                Ok(None)
            } else {
                Err(Error::Other(anyhow::anyhow!("simulated tokens-store failure")))
            }
        }
        async fn revoke(&self, _: &str) -> Result<bool> {
            unreachable!("health_ready does not revoke")
        }
    }

    /// `AuditStore` whose `count` returns Err. Pairs with
    /// `NoopAuditStore` (which returns Ok(0)) to cover both paths.
    struct FailingAuditStore;

    #[async_trait]
    impl AuditStore for FailingAuditStore {
        async fn record(&self, _: AuditEvent) -> Result<()> {
            Ok(())
        }
        async fn list(&self, _: AuditQuery) -> Result<Vec<AuditEvent>> {
            Ok(Vec::new())
        }
        async fn count(&self) -> Result<u64> {
            Err(Error::Other(anyhow::anyhow!("simulated audit-store failure")))
        }
        async fn prune_older_than(&self, _: i64) -> Result<u64> {
            Ok(0)
        }
    }

    /// `OwnershipStore` whose `count_all` outcome is configurable.
    /// Other methods panic — `health_ready` only ever calls `count_all`.
    struct StubOwnershipStore {
        count_succeeds: bool,
    }

    #[async_trait]
    impl OwnershipStore for StubOwnershipStore {
        async fn record_owner(&self, _: &str, _: Option<&str>) -> Result<()> {
            unreachable!("health_ready does not record")
        }
        async fn get_owner(&self, _: &str) -> Result<Option<Option<String>>> {
            unreachable!("health_ready does not get_owner")
        }
        async fn delete(&self, _: &str) -> Result<()> {
            unreachable!("health_ready does not delete")
        }
        async fn count_by_owner(&self, _: &str) -> Result<u64> {
            unreachable!("health_ready does not count_by_owner")
        }
        async fn list_all(&self) -> Result<Vec<RepoRow>> {
            unreachable!("health_ready does not list_all")
        }
        async fn count_all(&self) -> Result<u64> {
            if self.count_succeeds {
                Ok(0)
            } else {
                Err(Error::Other(anyhow::anyhow!(
                    "simulated ownership-store failure"
                )))
            }
        }
        async fn list_by_owner(&self, _: &str) -> Result<Vec<RepoRow>> {
            unreachable!("health_ready does not list_by_owner")
        }
        async fn get_row(&self, _: &str) -> Result<Option<RepoRow>> {
            unreachable!("health_ready does not get_row")
        }
    }

    #[test]
    fn drain_response_returns_none_when_flag_clear() {
        let flag = AtomicBool::new(false);
        assert!(drain_response_if_draining(&flag).is_none());
    }

    #[test]
    fn drain_response_short_circuits_when_flag_set() {
        let flag = AtomicBool::new(true);
        let (status, body) =
            drain_response_if_draining(&flag).expect("expected Some response");
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0["ok"], serde_json::json!(false));
        assert_eq!(body.0["draining"], serde_json::json!(true));
    }

    #[test]
    fn drain_response_load_uses_relaxed_ordering_correctly() {
        // Belt-and-braces: a flag that flips between two reads
        // resolves consistently within one call. Not a stress test —
        // just verifies a basic store-then-load cycle, since the
        // production code uses Relaxed ordering and this is the
        // invariant we rely on.
        let flag = AtomicBool::new(false);
        flag.store(true, Ordering::Relaxed);
        assert!(drain_response_if_draining(&flag).is_some());
        flag.store(false, Ordering::Relaxed);
        assert!(drain_response_if_draining(&flag).is_none());
    }

    #[tokio::test]
    async fn probe_stores_returns_200_when_all_ok() {
        let tokens = StubTokenStore { lookup_succeeds: true };
        let audit = NoopAuditStore;
        let ownership = StubOwnershipStore { count_succeeds: true };
        let (status, body) = probe_stores(&tokens, &audit, &ownership).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body.0["ok"], serde_json::json!(true));
        assert_eq!(body.0["components"]["tokens"], serde_json::json!("ok"));
        assert_eq!(body.0["components"]["audit"], serde_json::json!("ok"));
        assert_eq!(body.0["components"]["ownership"], serde_json::json!("ok"));
    }

    #[tokio::test]
    async fn probe_stores_returns_503_when_tokens_fails() {
        let tokens = StubTokenStore { lookup_succeeds: false };
        let audit = NoopAuditStore;
        let ownership = StubOwnershipStore { count_succeeds: true };
        let (status, body) = probe_stores(&tokens, &audit, &ownership).await;
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0["ok"], serde_json::json!(false));
        assert_eq!(body.0["components"]["tokens"], serde_json::json!("fail"));
        assert_eq!(body.0["components"]["audit"], serde_json::json!("ok"));
        assert_eq!(body.0["components"]["ownership"], serde_json::json!("ok"));
    }

    #[tokio::test]
    async fn probe_stores_returns_503_when_audit_fails() {
        let tokens = StubTokenStore { lookup_succeeds: true };
        let audit = FailingAuditStore;
        let ownership = StubOwnershipStore { count_succeeds: true };
        let (status, body) = probe_stores(&tokens, &audit, &ownership).await;
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0["ok"], serde_json::json!(false));
        assert_eq!(body.0["components"]["tokens"], serde_json::json!("ok"));
        assert_eq!(body.0["components"]["audit"], serde_json::json!("fail"));
        assert_eq!(body.0["components"]["ownership"], serde_json::json!("ok"));
    }

    #[tokio::test]
    async fn probe_stores_returns_503_when_ownership_fails() {
        let tokens = StubTokenStore { lookup_succeeds: true };
        let audit = NoopAuditStore;
        let ownership = StubOwnershipStore { count_succeeds: false };
        let (status, body) = probe_stores(&tokens, &audit, &ownership).await;
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0["ok"], serde_json::json!(false));
        assert_eq!(body.0["components"]["tokens"], serde_json::json!("ok"));
        assert_eq!(body.0["components"]["audit"], serde_json::json!("ok"));
        assert_eq!(body.0["components"]["ownership"], serde_json::json!("fail"));
    }
}
