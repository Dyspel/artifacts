use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub public_base_url: String,
    pub admin_token: String,
}

impl Config {
    pub fn repos_dir(&self) -> PathBuf {
        self.data_dir.join("repos")
    }
}
