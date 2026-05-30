//! At-rest encryption for round-trippable secrets.
//!
//! The webhook subscription table stores HMAC-SHA256 keys that have to
//! be retrievable in plaintext at delivery time (so the dispatcher can
//! sign the body). A simple hash won't work — we need symmetric
//! encryption with a key the server holds in memory.
//!
//! This module provides:
//!
//! - `MasterKey`: a 32-byte AES-256 key wrapped in `Zeroizing`.
//! - `seal` / `unseal`: AES-256-GCM encrypt + decrypt, with a fresh
//!   12-byte nonce per encryption (the standard recommendation —
//!   AES-GCM is catastrophic on nonce reuse).
//! - `MasterKey::load_or_generate`: env-first, file-fallback, generate
//!   on first run with a stern-warning log line. The generated key
//!   lives next to `tokens.db` / `audit.db` so a `cp -r data/` backup
//!   captures it; in production the env-var path should be used so
//!   the key isn't co-located with the ciphertext.
//!
//! ## What this defends against
//!
//! - **Targeted DB exfil**: someone walks off with `tokens.db` (the
//!   webhooks live there now). Without the key file or env var, the
//!   secret column is opaque.
//! - **Backup-tape leak**: same shape — DB without key is unreadable.
//!
//! ## What it does *not* defend against
//!
//! - **Full-disk compromise**: if the attacker has the data dir, they
//!   have the key file too. The env-var deployment shape is what
//!   raises the bar here.
//! - **Live process memory dump**: the key sits in `Zeroizing<[u8; 32]>`
//!   while the server runs. Memory-dump compromise of a running
//!   process exposes everything anyway; this isn't a defense for it.
//!
//! Honest framing: this is the prototype-grade KMS swap. M6-deliver-secrets
//! tracks the move to a real KMS (sealing key referenced by KMS ID,
//! KMS does the unwrap on each delivery). The trait shape stays the
//! same; the impl swaps.

use crate::error::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use std::path::Path;

/// 256-bit symmetric key. Drops via `zeroize` so a key swap doesn't
/// leave residue on the heap. Construct via `MasterKey::load_or_generate`
/// at startup; treat as immutable for the process lifetime.
pub struct MasterKey {
    bytes: [u8; 32],
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        // Best-effort scrub. `core::ptr::write_volatile` survives
        // dead-store elimination; a plain assignment can be optimized
        // away. We don't pull in the `zeroize` crate just for this —
        // a single 32-byte volatile write is enough.
        for b in &mut self.bytes {
            // SAFETY: `b` is a `&mut u8` yielded by iterating `&mut`, so the
            // pointer is non-null, properly aligned, and valid for a
            // single-byte write for the duration of this call. The
            // value written (`0`) has no destructor and there is no
            // aliasing. `write_volatile` is used solely so the compiler
            // cannot elide the scrub as a dead store.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
    }
}

impl MasterKey {
    /// 32 raw bytes. Caller is responsible for ensuring sufficient
    /// entropy (use `MasterKey::random` if generating fresh).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Generate a fresh key with `rand::thread_rng()` (OS-seeded).
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self::from_bytes(bytes)
    }

    /// Decode a base64-encoded 32-byte key (URL-safe or standard
    /// alphabet, either works). Anything that doesn't decode to
    /// exactly 32 bytes is rejected.
    pub fn from_base64(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        // Try standard then URL-safe alphabet.
        let raw = B64
            .decode(trimmed)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
            .map_err(|e| Error::Other(anyhow::anyhow!("invalid base64 webhook key: {e}")))?;
        if raw.len() != 32 {
            return Err(Error::Other(anyhow::anyhow!(
                "webhook key must be 32 bytes (got {})",
                raw.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw);
        Ok(Self::from_bytes(bytes))
    }

    pub fn to_base64(&self) -> String {
        B64.encode(self.bytes)
    }

    /// Resolution order:
    ///   1. `ARTIFACTS_WEBHOOK_KEY` env var (base64-encoded 32 bytes).
    ///   2. The given `key_path` file (base64-encoded 32 bytes).
    ///   3. Generate fresh, write to `key_path` with 0600 perms,
    ///      log a warning explaining how to pin via env for prod.
    ///
    /// This mirrors the admin-token shape: env-first for production,
    /// auto-generate-and-warn for dev. The on-disk fallback is so a
    /// developer doesn't get a fresh key (and unreadable webhook
    /// secrets) on every restart.
    pub fn load_or_generate(key_path: &Path) -> Result<Self> {
        if let Ok(raw) = std::env::var("ARTIFACTS_WEBHOOK_KEY") {
            tracing::info!("webhook master key loaded from ARTIFACTS_WEBHOOK_KEY env");
            return Self::from_base64(&raw);
        }
        if key_path.exists() {
            let raw = std::fs::read_to_string(key_path).map_err(Error::from)?;
            tracing::info!(path = %key_path.display(), "webhook master key loaded from file");
            return Self::from_base64(&raw);
        }
        let key = Self::random();
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent).map_err(Error::from)?;
        }
        write_key_file_0600(key_path, &key.to_base64())?;
        tracing::warn!(
            path = %key_path.display(),
            "webhook master key auto-generated; \
             pin via ARTIFACTS_WEBHOOK_KEY env to decouple from disk"
        );
        Ok(key)
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(&self.bytes).expect("32-byte key is the AES-256-GCM contract")
    }
}

/// Encrypt `plaintext` under `key`. Returns `(ciphertext, nonce)`.
/// Nonce is fresh-random — never reuse one with the same key, that's
/// a catastrophic AES-GCM failure.
pub fn seal(key: &MasterKey, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = key
        .cipher()
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::Other(anyhow::anyhow!("aes-gcm seal failed: {e}")))?;
    Ok((ciphertext, nonce_bytes))
}

/// Decrypt `ciphertext` under `key` + `nonce`. Returns the original
/// plaintext or an error if the tag check fails (tampering, wrong key,
/// wrong nonce, truncation). The error path doesn't leak which of
/// those conditions actually failed — AES-GCM gives one error.
pub fn unseal(key: &MasterKey, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let nonce = Nonce::from_slice(nonce);
    key.cipher()
        .decrypt(nonce, ciphertext)
        .map_err(|e| Error::Other(anyhow::anyhow!("aes-gcm unseal failed: {e}")))
}

#[cfg(unix)]
fn write_key_file_0600(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(Error::from)?;
    f.write_all(contents.as_bytes()).map_err(Error::from)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_key_file_0600(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn seal_unseal_round_trips() {
        let key = MasterKey::random();
        let pt = b"super-secret-hmac-key-bytes";
        let (ct, nonce) = seal(&key, pt).unwrap();
        // Ciphertext is plaintext + 16-byte tag.
        assert_eq!(ct.len(), pt.len() + 16);
        let recovered = unseal(&key, &ct, &nonce).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let key = MasterKey::random();
        let (ct, nonce) = seal(&key, b"").unwrap();
        let pt = unseal(&key, &ct, &nonce).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn each_seal_uses_unique_nonce() {
        // Two seals of the same plaintext under the same key must
        // produce different ciphertexts (because the nonce is fresh).
        // This is the sanity check for "we're not deterministically
        // re-encrypting under a static nonce".
        let key = MasterKey::random();
        let (ct1, n1) = seal(&key, b"x").unwrap();
        let (ct2, n2) = seal(&key, b"x").unwrap();
        assert_ne!(ct1, ct2, "ciphertexts collided — nonce reuse?");
        assert_ne!(n1, n2, "nonce reuse — would compromise GCM");
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = MasterKey::random();
        let (mut ct, nonce) = seal(&key, b"hello").unwrap();
        ct[0] ^= 0x01;
        assert!(unseal(&key, &ct, &nonce).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let k1 = MasterKey::random();
        let k2 = MasterKey::random();
        let (ct, nonce) = seal(&k1, b"hello").unwrap();
        assert!(unseal(&k2, &ct, &nonce).is_err());
    }

    #[test]
    fn wrong_nonce_rejected() {
        let key = MasterKey::random();
        let (ct, _) = seal(&key, b"hello").unwrap();
        let bad = [0u8; 12];
        assert!(unseal(&key, &ct, &bad).is_err());
    }

    #[test]
    fn from_base64_round_trips_the_key_value() {
        let k = MasterKey::random();
        let b64 = k.to_base64();
        let k2 = MasterKey::from_base64(&b64).unwrap();
        // Equality via roundtrip through encryption.
        let (ct, n) = seal(&k, b"x").unwrap();
        assert_eq!(unseal(&k2, &ct, &n).unwrap(), b"x");
    }

    #[test]
    fn from_base64_rejects_wrong_length() {
        // 16 bytes = 24 base64 chars (with padding); valid b64 but wrong size.
        let too_short = B64.encode([0u8; 16]);
        assert!(MasterKey::from_base64(&too_short).is_err());
        // Garbage.
        assert!(MasterKey::from_base64("not-valid-base64-!@#").is_err());
    }

    #[test]
    fn load_or_generate_creates_key_file_when_absent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("webhook-key.bin");
        assert!(!path.exists());
        let _ = MasterKey::load_or_generate(&path).unwrap();
        assert!(path.exists(), "expected key file to be written");
        // 32 bytes encoded as base64 with padding = 44 chars.
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk.trim().len(), 44);
    }

    #[test]
    fn load_or_generate_reuses_existing_key_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("webhook-key.bin");
        let k1 = MasterKey::load_or_generate(&path).unwrap();
        let k2 = MasterKey::load_or_generate(&path).unwrap();
        // Roundtrip via encryption confirms the same key.
        let (ct, n) = seal(&k1, b"x").unwrap();
        assert_eq!(unseal(&k2, &ct, &n).unwrap(), b"x");
    }

    #[cfg(unix)]
    #[test]
    fn generated_key_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("webhook-key.bin");
        let _ = MasterKey::load_or_generate(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file perms must be 0600, got {mode:o}");
    }
}
