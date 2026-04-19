//! In-memory token store for M0.
//!
//! A token authorizes access to a single repo at a given scope. Tokens are
//! opaque random strings; clients present them via HTTP Basic with username
//! `x` (matching how `git clone https://x:TOKEN@host/...` sends them).
//!
//! This lives entirely in RAM and is wiped on restart. M4 replaces it with a
//! real issuer (short-lived JWTs or signed tokens) backed by a KV.

use dashmap::DashMap;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Read,
    Write,
}

#[derive(Debug, Clone)]
pub struct TokenRecord {
    pub repo_id: String,
    pub scope: Scope,
}

#[derive(Debug, Clone, Default)]
pub struct TokenStore {
    inner: Arc<DashMap<String, TokenRecord>>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mint(&self, repo_id: &str, scope: Scope) -> String {
        let token = random_token();
        self.inner.insert(
            token.clone(),
            TokenRecord { repo_id: repo_id.to_string(), scope },
        );
        token
    }

    pub fn lookup(&self, token: &str) -> Option<TokenRecord> {
        self.inner.get(token).map(|v| v.clone())
    }
}

fn random_token() -> String {
    // 32 bytes of entropy, base64url without padding. 43 chars.
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
