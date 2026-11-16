use crate::error::ScchError;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce, aead::consts::U12};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

const FILENAME_AAD: &[u8] = b"vault-filename";
const SCRYPT_LOG_N: u8 = 15; // 2**15 = 32768
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Derives a 32-byte key from password and salt using Scrypt.
pub fn key_from(pw: &str, salt: &[u8]) -> Result<[u8; 32], ScchError> {
    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)
        .map_err(|e| ScchError::Crypto(format!("Invalid scrypt parameters: {e}")))?;
    let mut key = [0u8; 32];
    scrypt::scrypt(pw.as_bytes(), salt, &params, &mut key)
        .map_err(|e| ScchError::Crypto(format!("Scrypt derivation failed: {e}")))?;
    Ok(key)
}

/// Encrypts an original filename/stem into a base64url-encoded token.
pub fn enc_stem(stem: &str, pw: &str) -> Result<String, ScchError> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce_bytes);

    let key = key_from(pw, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| ScchError::Crypto(format!("AES-GCM key init failed: {e}")))?;
    let nonce: Nonce<U12> = nonce_bytes.into();

    let payload = Payload {
        msg: stem.as_bytes(),
        aad: FILENAME_AAD,
    };

    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| ScchError::Crypto(format!("Stem encryption failed: {e}")))?;

    let mut raw = Vec::with_capacity(16 + 12 + ciphertext.len());
    raw.extend_from_slice(&salt);
    raw.extend_from_slice(&nonce_bytes);
    raw.extend_from_slice(&ciphertext);

    let token = URL_SAFE_NO_PAD.encode(&raw);
    if token.len() > 200 {
        return Err(ScchError::Validation(
            "Encrypted filename exceeds filesystem length limits".to_string(),
        ));
    }
    Ok(token)
}

/// Decrypts a base64url-encoded token back into the original filename/stem.
pub fn dec_stem(token: &str, pw: &str) -> Result<String, ScchError> {
    let trimmed = token.trim_end_matches('=');
    let raw = URL_SAFE_NO_PAD
        .decode(trimmed)
        .map_err(|e| ScchError::Crypto(format!("Invalid base64 token: {e}")))?;

    if raw.len() < 16 + 12 + 16 {
        return Err(ScchError::Crypto("Encrypted token is too short".to_string()));
    }

    let salt = &raw[..16];
    let nonce_bytes = &raw[16..28];
    let ciphertext = &raw[28..];

    let key = key_from(pw, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| ScchError::Crypto(format!("AES-GCM key init failed: {e}")))?;
    let nonce: Nonce<U12> = nonce_bytes.try_into()
        .map_err(|_| ScchError::Crypto("Invalid nonce length".to_string()))?;

    let payload = Payload {
        msg: ciphertext,
        aad: FILENAME_AAD,
    };

    let plaintext = cipher
        .decrypt(&nonce, payload)
        .map_err(|e| ScchError::Crypto(format!("Failed to decrypt original filename (wrong password or corrupted name): {e}")))?;

    String::from_utf8(plaintext)
        .map_err(|e| ScchError::Crypto(format!("Decrypted filename is not valid UTF-8: {e}")))
}

/// Computes the SHA-256 digest of a file in hex format.
pub fn compute_sha256(path: &Path) -> Result<String, ScchError> {
    let mut file = File::open(path)
        .map_err(|e| ScchError::Io(std::io::Error::new(e.kind(), format!("{}: {}", path.display(), e))))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let digest = hasher.finalize();
    Ok(hex_encode(&digest))
}

/// Creates a `.sha256` sidecar file next to `path`.
pub fn write_sha256_sidecar(path: &Path) -> Result<PathBuf, ScchError> {
    let hash = compute_sha256(path)?;
    let sidecar_path = PathBuf::from(format!("{}.sha256", path.display()));
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("archive");

    let content = format!("{hash}  {filename}\n");
    let mut file = File::create(&sidecar_path)?;
    file.write_all(content.as_bytes())?;
    file.flush()?;
    Ok(sidecar_path)
}

/// Verifies a file against its `.sha256` sidecar.
pub fn verify_sha256_sidecar(path: &Path) -> Result<bool, ScchError> {
    let sidecar_path = PathBuf::from(format!("{}.sha256", path.display()));
    if !sidecar_path.exists() {
        return Err(ScchError::Validation(format!(
            "Missing SHA-256 sidecar file: {}",
            sidecar_path.display()
        )));
    }

    let content = std::fs::read_to_string(&sidecar_path)?;
    let expected_hash = content
        .split_whitespace()
        .next()
        .ok_or_else(|| ScchError::Validation("Empty or invalid .sha256 file".to_string()))?
        .to_ascii_lowercase();

    let actual_hash = compute_sha256(path)?.to_ascii_lowercase();
    if expected_hash != actual_hash {
        return Err(ScchError::ChecksumMismatch {
            file: path.display().to_string(),
            expected: expected_hash,
            actual: actual_hash,
        });
    }

    Ok(true)
}

/// Verifies legacy `.hmac` sidecar files (from `vault.py`).
pub fn verify_hmac_sidecar(path: &Path, pw: &str) -> Result<bool, ScchError> {
    let sidecar_path = PathBuf::from(format!("{}.hmac", path.display()));
    if !sidecar_path.exists() {
        return Err(ScchError::Validation(format!(
            "Missing HMAC sidecar file: {}",
            sidecar_path.display()
        )));
    }

    let content = std::fs::read_to_string(&sidecar_path)?;
    let trimmed = content.trim();
    let (salt_hex, expected_mac) = trimmed
        .split_once(':')
        .ok_or_else(|| ScchError::Validation("Malformed .hmac sidecar file".to_string()))?;

    let salt = (0..salt_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&salt_hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| ScchError::Validation(format!("Invalid hex in HMAC salt: {e}")))?;

    let key = key_from(pw, &salt)?;
    let mut mac = HmacSha256::new_from_slice(&key)
        .map_err(|e| ScchError::Crypto(format!("HMAC init failed: {e}")))?;

    let mut file = File::open(path)?;
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        mac.update(&buffer[..n]);
    }

    let actual_mac = hex_encode(&mac.finalize().into_bytes());
    if actual_mac != expected_mac {
        return Err(ScchError::ChecksumMismatch {
            file: path.display().to_string(),
            expected: expected_mac.to_string(),
            actual: actual_mac,
        });
    }

    Ok(true)
}

/// Verifies either `.sha256` or `.hmac` sidecar for an archive part.
pub fn verify_archive_sidecar(path: &Path, pw: Option<&str>) -> Result<(), ScchError> {
    let sha256_sidecar = PathBuf::from(format!("{}.sha256", path.display()));
    let hmac_sidecar = PathBuf::from(format!("{}.hmac", path.display()));

    if sha256_sidecar.exists() {
        verify_sha256_sidecar(path)?;
        Ok(())
    } else if hmac_sidecar.exists() {
        if let Some(password) = pw {
            verify_hmac_sidecar(path, password)?;
            Ok(())
        } else {
            Err(ScchError::Validation(format!(
                "Password required to verify legacy .hmac sidecar for {}",
                path.display()
            )))
        }
    } else {
        Err(ScchError::Validation(format!(
            "No checksum sidecar (.sha256 or .hmac) found for {}",
            path.display()
        )))
    }
}
