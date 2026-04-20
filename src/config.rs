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
}

impl Config {
    pub fn repos_dir(&self) -> PathBuf {
        self.data_dir.join("repos")
    }
}
