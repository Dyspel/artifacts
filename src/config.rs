use std::path::PathBuf;
use std::sync::RwLock;

#[derive(Debug)]
pub struct Config {
    pub data_dir: PathBuf,
    pub public_base_url: String,
    /// Process-wide admin token. Wrapped in `RwLock` so an admin
    /// rotation endpoint can swap it without restarting the server.
    /// Reads happen on every REST call but finish in microseconds (the
    /// lock is uncontended in practice; rotation is rare). Read via
    /// `Config::admin_token()`, replace via `Config::rotate_admin_token()`.
    admin_token: RwLock<String>,
    /// Shared secret for verifying JWTs on REST endpoints. `None`
    /// disables the JWT auth path entirely — only the admin token is
    /// accepted. Set initially via `--jwt-secret` /
    /// `ARTIFACTS_JWT_SECRET` (or autoloaded from
    /// `<data-dir>/jwt-key.bin` when the env var is unset). Rotated
    /// in-place via `POST /v1/admin/jwt-key/rotate`; reads happen on
    /// every REST call, so the RwLock keeps rotations from blocking
    /// the auth hot path beyond the brief swap window.
    jwt_secret: RwLock<Option<String>>,

    /// Expected JWT `aud` (audience) claim. When set, jwt::verify
    /// requires the token to carry an `aud` matching this value;
    /// when `None`, no `aud` check happens. Set via
    /// `--jwt-expected-aud` / `ARTIFACTS_JWT_EXPECTED_AUD`. Immutable
    /// after startup — the claim shape is a deployment property, not
    /// a key, so no rotation endpoint is exposed.
    jwt_expected_aud: Option<String>,

    /// Expected JWT `iss` (issuer) claim. Same shape as
    /// `jwt_expected_aud`. Set via `--jwt-expected-iss` /
    /// `ARTIFACTS_JWT_EXPECTED_ISS`.
    jwt_expected_iss: Option<String>,

    /// Maximum number of repos a single non-admin user may own. Applies
    /// to both `create_repo` and `fork_repo`. Admin bypasses. Set via
    /// `--max-repos-per-user`.
    pub max_repos_per_user: u64,

    /// Maximum size in bytes of any single file in a REST-side commit.
    /// Applies to both `content` and `contentBase64` bodies (the cap is
    /// on the decoded bytes). Big-blob uploads through this endpoint
    /// are always a red flag — the commits handler spawns `git
    /// hash-object` per file, which pins memory proportional to blob
    /// size during its run.
    pub max_commit_blob_bytes: usize,

    /// Maximum on-disk size of a single repo's bare git dir in bytes.
    /// Enforced on REST commits + receive-pack at the dispatch
    /// boundary. `0` means unlimited (default). Set via
    /// `--max-repo-bytes` / `ARTIFACTS_MAX_REPO_BYTES`.
    pub max_repo_bytes: u64,

    /// When `true` (default), `/v1/health/ready` exercises each
    /// SQLite store's write path via `probe_write` (transient
    /// INSERT/DELETE against a `_probe` table) alongside the
    /// existing cheap-SELECT probe. Catches a read-only filesystem
    /// or quota-full sqlite at the orchestrator's polling cadence
    /// instead of at the next real mutation. Set via
    /// `ARTIFACTS_READINESS_WRITE_CHECK=0` to opt out.
    pub readiness_write_check: bool,
}

impl Config {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        data_dir: PathBuf,
        public_base_url: String,
        admin_token: String,
        jwt_secret: Option<String>,
        jwt_expected_aud: Option<String>,
        jwt_expected_iss: Option<String>,
        max_repos_per_user: u64,
        max_commit_blob_bytes: usize,
        max_repo_bytes: u64,
        readiness_write_check: bool,
    ) -> Self {
        Self {
            data_dir,
            public_base_url,
            admin_token: RwLock::new(admin_token),
            jwt_secret: RwLock::new(jwt_secret),
            jwt_expected_aud,
            jwt_expected_iss,
            max_repos_per_user,
            max_commit_blob_bytes,
            max_repo_bytes,
            readiness_write_check,
        }
    }

    /// Snapshot the expected JWT `aud` claim, if configured. Returns
    /// `None` when `--jwt-expected-aud` is unset — jwt::verify then
    /// skips audience validation. Cheap clone (small string).
    pub fn jwt_expected_aud(&self) -> Option<&str> {
        self.jwt_expected_aud.as_deref()
    }

    /// Snapshot the expected JWT `iss` claim, if configured. Same
    /// shape as `jwt_expected_aud`.
    pub fn jwt_expected_iss(&self) -> Option<&str> {
        self.jwt_expected_iss.as_deref()
    }

    /// Snapshot the current JWT secret. Allocates — call once per
    /// REST request at the auth boundary, not in inner loops. `None`
    /// means JWT auth is disabled and only the admin token is
    /// accepted.
    pub fn jwt_secret(&self) -> Option<String> {
        // Poison recovery: the value behind the lock is a single
        // Option<String>; a panic during `rotate_jwt_secret` leaves
        // either the pre- or post-update value in place, both valid
        // states. Treating the lock as never-poisoned is correct
        // here and matches the pattern used by MemObjectStore,
        // SqliteWebhookRegistry, MemRefStore.
        self.jwt_secret
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Replace the in-process JWT signing secret. Subsequent REST
    /// requests verify against the new value; any JWT signed under
    /// the old one stops authorizing immediately. Pass `None` to
    /// disable JWT auth altogether (no clients can present any JWT
    /// after this).
    pub fn rotate_jwt_secret(&self, new: Option<String>) {
        *self.jwt_secret.write().unwrap_or_else(|p| p.into_inner()) = new;
    }

    pub fn repos_dir(&self) -> PathBuf {
        self.data_dir.join("repos")
    }

    /// Snapshot the current admin token. Allocates — call once per
    /// REST request at the auth boundary, not in inner loops.
    pub fn admin_token(&self) -> String {
        // Same poison-recovery rationale as `jwt_secret`: single
        // value behind the lock, atomic swap on rotate.
        self.admin_token
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Replace the in-process admin token. Subsequent REST requests
    /// authorize against the new value; the old one stops working
    /// immediately. Idempotent — rotating to the same value is a no-op
    /// from the caller's perspective.
    pub fn rotate_admin_token(&self, new: String) {
        *self.admin_token.write().unwrap_or_else(|p| p.into_inner()) = new;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(token: &str) -> Config {
        Config::new(
            PathBuf::from("/tmp/x"),
            "http://x".to_string(),
            token.to_string(),
            None,
            None,
            None,
            16,
            1024,
            0,
            true,
        )
    }

    #[test]
    fn admin_token_returns_initial_value() {
        let c = cfg("alpha");
        assert_eq!(c.admin_token(), "alpha");
    }

    #[test]
    fn rotate_replaces_admin_token_atomically() {
        let c = cfg("alpha");
        c.rotate_admin_token("beta".to_string());
        assert_eq!(c.admin_token(), "beta");
        c.rotate_admin_token("gamma".to_string());
        assert_eq!(c.admin_token(), "gamma");
    }

    #[test]
    fn rotate_to_same_value_is_observable_no_op() {
        let c = cfg("alpha");
        c.rotate_admin_token("alpha".to_string());
        assert_eq!(c.admin_token(), "alpha");
    }

    #[test]
    fn concurrent_reads_dont_block_each_other() {
        // Sanity-check that the chosen lock type doesn't surprise us
        // under concurrent reads. Spawn N readers that each snapshot
        // the token a few times — they should all see the same value
        // and all finish quickly.
        use std::sync::Arc;
        use std::thread;

        let c = Arc::new(cfg("shared"));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let c = c.clone();
                thread::spawn(move || {
                    for _ in 0..100 {
                        assert_eq!(c.admin_token(), "shared");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }
}
