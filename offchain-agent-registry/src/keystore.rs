//! Encrypted local keystore for ArthNeura agent identities.
//!
//! Persists an agent's ML-DSA65 signing key seed to disk, encrypted at
//! rest with ChaCha20Poly1305 (AEAD), keyed by an Argon2id-derived key
//! from a user-supplied passphrase. Without this, every `register_agent`
//! call generates a throwaway keypair that cannot be reconstructed after
//! the process exits -- meaning an agent can never re-sign as itself,
//! and its on-chain DID + reserved deposit become permanently orphaned.
//!
//! Threat model: protects key material at rest against anyone who reads
//! the keystore file (disk theft, backup leak, misconfigured
//! permissions) but who does NOT know the passphrase. It does NOT
//! protect against a compromised running process (the key is decrypted
//! into process memory to sign transactions) or a keylogger capturing
//! the passphrase as it's typed. File permissions (0600, unix) are set
//! as defense-in-depth on top of encryption, not a substitute for it.
//!
//! Known limitation: `register_or_load_agent` (see `lib.rs`) trusts the
//! local file's DID once decrypted -- it does not cross-check on-chain
//! that the DID is still registered or that the controller matches.
//! That would need a verified subxt dynamic-storage read, deferred
//! pending API verification against the installed subxt 0.38 source.

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::Did;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12; // ChaCha20Poly1305 standard nonce size
const DERIVED_KEY_LEN: usize = 32;

/// Argon2id parameters. Deliberately heavier than the crate's RFC 9106
/// "low-memory" default (19 MiB) -- these keys guard an agent's on-chain
/// identity and reserved deposit, and key load/save is a cold-path
/// operation (once per process start), so the extra CPU/memory cost is
/// cheap insurance against offline passphrase-guessing on a stolen file.
const ARGON2_MEM_COST_KIB: u32 = 65536; // 64 MiB
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("decryption failed -- wrong passphrase or corrupted/tampered file")]
    DecryptionFailed,
    #[error("identity label '{0}' already exists at {1} -- refusing to overwrite")]
    AlreadyExists(String, String),
    #[error("identity label '{0}' not found at {1}")]
    NotFound(String, String),
    #[error(
        "invalid label '{0}' -- labels must be non-empty and contain only ASCII alphanumerics, '-', or '_'"
    )]
    InvalidLabel(String),
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    version: u8,
    did_hex: String,
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

/// A decrypted identity loaded from the keystore. `signing_key_bytes`
/// is wrapped in `Zeroizing` -- it is overwritten with zeros when this
/// value is dropped, so the raw key material doesn't linger in process
/// memory longer than needed.
pub struct StoredIdentity {
    pub did: Did,
    pub signing_key_bytes: Zeroizing<Vec<u8>>,
}

/// Default keystore directory: `~/.arthneura/keys`. Created with `0700`
/// permissions (unix) on first use if it doesn't exist.
pub fn default_keystore_dir() -> Result<PathBuf, KeyStoreError> {
    let home = std::env::var("HOME")
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "HOME environment variable not set"))?;
    Ok(PathBuf::from(home).join(".arthneura").join("keys"))
}

fn validate_label(label: &str) -> Result<(), KeyStoreError> {
    let valid = !label.is_empty()
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if valid {
        Ok(())
    } else {
        Err(KeyStoreError::InvalidLabel(label.to_string()))
    }
}

fn key_file_path(dir: &Path, label: &str) -> Result<PathBuf, KeyStoreError> {
    validate_label(label)?;
    Ok(dir.join(format!("{label}.json")))
}

fn random_bytes<const N: usize>() -> Result<[u8; N], KeyStoreError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| KeyStoreError::Kdf(format!("OS RNG failure: {e}")))?;
    Ok(buf)
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; DERIVED_KEY_LEN]>, KeyStoreError> {
    let params = argon2::Params::new(
        ARGON2_MEM_COST_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(DERIVED_KEY_LEN),
    )
    .map_err(|e| KeyStoreError::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut out = Zeroizing::new([0u8; DERIVED_KEY_LEN]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut_slice())
        .map_err(|e| KeyStoreError::Kdf(e.to_string()))?;
    Ok(out)
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// Encrypts and persists `signing_key_bytes` under `label` in `dir`.
/// Refuses to overwrite an existing file for the same label -- call
/// `identity_exists` first, or delete the file manually, if
/// intentional replacement is needed.
pub fn save_identity(
    dir: &Path,
    label: &str,
    did: Did,
    signing_key_bytes: &[u8],
    passphrase: &str,
) -> Result<(), KeyStoreError> {
    let path = key_file_path(dir, label)?;
    if path.exists() {
        return Err(KeyStoreError::AlreadyExists(
            label.to_string(),
            path.display().to_string(),
        ));
    }

    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }

    let salt = random_bytes::<SALT_LEN>()?;
    let nonce_bytes = random_bytes::<NONCE_LEN>()?;

    let derived_key = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(derived_key.as_slice()));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, signing_key_bytes)
        .map_err(|_| KeyStoreError::Kdf("AEAD encryption failed".to_string()))?;

    let key_file = KeyFile {
        version: 1,
        did_hex: hex::encode(did),
        salt_b64: base64_encode(&salt),
        nonce_b64: base64_encode(&nonce_bytes),
        ciphertext_b64: base64_encode(&ciphertext),
    };

    let json = serde_json::to_string_pretty(&key_file)?;
    fs::write(&path, json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Loads and decrypts the identity stored under `label` in `dir`.
pub fn load_identity(dir: &Path, label: &str, passphrase: &str) -> Result<StoredIdentity, KeyStoreError> {
    let path = key_file_path(dir, label)?;
    if !path.exists() {
        return Err(KeyStoreError::NotFound(
            label.to_string(),
            path.display().to_string(),
        ));
    }

    let json = fs::read_to_string(&path)?;
    let key_file: KeyFile = serde_json::from_str(&json)?;

    let salt = base64_decode(&key_file.salt_b64).ok_or(KeyStoreError::DecryptionFailed)?;
    let nonce_bytes = base64_decode(&key_file.nonce_b64).ok_or(KeyStoreError::DecryptionFailed)?;
    let ciphertext = base64_decode(&key_file.ciphertext_b64).ok_or(KeyStoreError::DecryptionFailed)?;

    let derived_key = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(derived_key.as_slice()));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| KeyStoreError::DecryptionFailed)?;

    let did_vec = hex::decode(&key_file.did_hex).map_err(|_| KeyStoreError::DecryptionFailed)?;
    let did: Did = did_vec.try_into().map_err(|_| KeyStoreError::DecryptionFailed)?;

    Ok(StoredIdentity {
        did,
        signing_key_bytes: Zeroizing::new(plaintext),
    })
}

/// Returns `true` if an identity file exists for `label` in `dir` --
/// does not attempt decryption or validate the passphrase.
pub fn identity_exists(dir: &Path, label: &str) -> bool {
    key_file_path(dir, label).map(|p| p.exists()).unwrap_or(false)
}
