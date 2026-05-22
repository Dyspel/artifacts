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
}

impl Config {
    pub fn new(
        data_dir: PathBuf,
        public_base_url: String,
        admin_token: String,
        jwt_secret: Option<String>,
        max_repos_per_user: u64,
        max_commit_blob_bytes: usize,
        max_repo_bytes: u64,
    ) -> Self {
        Self {
            data_dir,
            public_base_url,
            admin_token: RwLock::new(admin_token),
            jwt_secret: RwLock::new(jwt_secret),
            max_repos_per_user,
            max_commit_blob_bytes,
            max_repo_bytes,
        }
    }

    /// Snapshot the current JWT secret. Allocates — call once per
    /// REST request at the auth boundary, not in inner loops. `None`
    /// means JWT auth is disabled and only the admin token is
    /// accepted.
    pub fn jwt_secret(&self) -> Option<String> {
        self.jwt_secret
            .read()
            .expect("jwt_secret lock poisoned")
            .clone()
    }

    /// Replace the in-process JWT signing secret. Subsequent REST
    /// requests verify against the new value; any JWT signed under
    /// the old one stops authorizing immediately. Pass `None` to
    /// disable JWT auth altogether (no clients can present any JWT
    /// after this).
    pub fn rotate_jwt_secret(&self, new: Option<String>) {
        *self.jwt_secret.write().expect("jwt_secret lock poisoned") = new;
    }

    pub fn repos_dir(&self) -> PathBuf {
        self.data_dir.join("repos")
    }

    /// Snapshot the current admin token. Allocates — call once per
    /// REST request at the auth boundary, not in inner loops.
    pub fn admin_token(&self) -> String {
        self.admin_token
            .read()
            .expect("admin_token lock poisoned")
            .clone()
    }

    /// Replace the in-process admin token. Subsequent REST requests
    /// authorize against the new value; the old one stops working
    /// immediately. Idempotent — rotating to the same value is a no-op
    /// from the caller's perspective.
    pub fn rotate_admin_token(&self, new: String) {
        *self.admin_token.write().expect("admin_token lock poisoned") = new;
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
            16,
            1024,
            0,
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
