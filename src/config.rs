use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub public_base_url: String,
    pub admin_token: String,
    /// Shared secret for verifying JWTs on REST endpoints. `None`
    /// disables the JWT auth path entirely — only the admin token is
    /// accepted. Set via `--jwt-secret` / `ARTIFACTS_JWT_SECRET`.
    pub jwt_secret: Option<String>,

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
}

impl Config {
    pub fn repos_dir(&self) -> PathBuf {
        self.data_dir.join("repos")
    }
}
