//! 7z AES-256 encryption — Phase 1 wrapper around RustCrypto primitives.
//!
//! ## 7z AES codec topology (encrypt direction)
//!
//! When writing an AES-encrypted archive, the caller provides plaintext and a
//! password. This module produces:
//! 1. `ciphertext` — the AES-256-CBC encrypted bytes (padded to a multiple of 16)
//! 2. `props` — the AES properties blob to store in the 7z container
//!
//! ## Properties format produced
//!
//! We always generate:
//! - `num_cycles_power = 19` (7zz default; 2^19 = 524288 SHA-256 rounds)
//! - No salt (salt_size = 0)
//! - A random 16-byte IV
//!
//! The properties blob produced:
//! ```text
//! byte 0: 19 | 0x40 = 0x53  (NumCyclesPower=19, has_iv=1, has_salt=0)
//! byte 1: 0x0F              (ivSize = 0x0F+1 = 16)
//! bytes 2..18: IV (16 random bytes)
//! ```

use crate::decrypt::derive_key;
use crate::error::{LockzippyError, LockzippyResult};

use aes::Aes256;
use cbc::Encryptor;
use cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};

/// The number of KDF rounds 7zz uses by default: `2^19 = 524288`.
const DEFAULT_NUM_CYCLES_POWER: u8 = 19;

// ── IV generation ─────────────────────────────────────────────────────────────

/// Generate a fresh random 16-byte AES IV using the system CSPRNG.
fn random_iv() -> LockzippyResult<[u8; 16]> {
    let mut iv = [0u8; 16];
    getrandom::getrandom(&mut iv).map_err(|e| {
        LockzippyError::Io(std::io::Error::other(format!(
            "failed to generate random IV: {e}"
        )))
    })?;
    Ok(iv)
}

// ── Encryption ────────────────────────────────────────────────────────────────

/// Encrypt a buffer with AES-256-CBC (no PKCS#7 padding).
///
/// `plaintext` is padded with zeros to the next multiple of 16.
/// The caller must trim the decrypted output to the original length (the 7z
/// container stores the uncompressed size, which the caller tracks separately).
///
/// Returns the ciphertext (same length as the padded plaintext).
///
/// # Errors
///
/// Returns [`LockzippyError::Io`] if the CSPRNG fails.
pub fn encrypt_aes256_cbc(
    plaintext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16],
) -> LockzippyResult<Vec<u8>> {
    // Pad plaintext to a multiple of 16 bytes with zeros (7z convention).
    let block_count = plaintext.len().div_ceil(16);
    let padded_len = block_count * 16;
    let mut buf = vec![0u8; padded_len];
    buf[..plaintext.len()].copy_from_slice(plaintext);

    Encryptor::<Aes256>::new(key.into(), iv.into())
        .encrypt_padded_mut::<NoPadding>(&mut buf, padded_len)
        .map_err(|e| LockzippyError::DecryptError(format!("AES encrypt error: {e}")))?;

    Ok(buf)
}

/// Build the AES properties blob matching the format 7zz expects.
///
/// Format:
/// - `byte[0]` = `num_cycles_power | 0x40` (has_iv=1, has_salt=0)
/// - `byte[1]` = `0x0F` (iv_size = 16)
/// - `bytes[2..18]` = IV
fn build_props(num_cycles_power: u8, iv: &[u8; 16]) -> Vec<u8> {
    let mut props = Vec::with_capacity(18);
    props.push(num_cycles_power | 0x40); // has_iv=1, has_salt=0
    props.push(0x0F); // ivSize = 0x0F + 1 = 16
    props.extend_from_slice(iv);
    props
}

/// Encrypt result containing both the ciphertext and the AES properties blob.
///
/// Store `props` in the 7z coder properties and `ciphertext` as the packed stream.
#[derive(Debug, Clone)]
pub struct EncryptResult {
    /// The AES-256-CBC encrypted bytes (padded to a multiple of 16).
    pub ciphertext: Vec<u8>,
    /// The AES properties blob to store in the 7z container's coder entry.
    pub props: Vec<u8>,
}

/// All-in-one: generate a random IV, derive key from password, and encrypt.
///
/// Uses `num_cycles_power = 19` (7zz default). The returned [`EncryptResult`]
/// contains both the ciphertext and the properties blob.
///
/// # Errors
///
/// Returns an error if the CSPRNG fails (very unlikely in practice).
pub fn encrypt_7z(plaintext: &[u8], password: &str) -> LockzippyResult<EncryptResult> {
    let iv = random_iv()?;
    let key = derive_key(password, &[], DEFAULT_NUM_CYCLES_POWER);
    let ciphertext = encrypt_aes256_cbc(plaintext, &key, &iv)?;
    let props = build_props(DEFAULT_NUM_CYCLES_POWER, &iv);
    Ok(EncryptResult { ciphertext, props })
}

/// Round-trip helper: encrypt then decrypt with the same password.
///
/// Returns the decrypted bytes (which may have zero-padding at the end if
/// `plaintext.len()` was not a multiple of 16). The caller should trim to
/// the original length.
pub fn encrypt_then_decrypt(plaintext: &[u8], password: &str) -> LockzippyResult<Vec<u8>> {
    use crate::decrypt::decrypt_7z;
    let result = encrypt_7z(plaintext, password)?;
    decrypt_7z(&result.ciphertext, &result.props, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::decrypt_7z;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let plaintext = b"hello, AES-256 encryption in lockzippy!";
        let password = "test1234";

        let result = encrypt_7z(plaintext, password).expect("encrypt_7z failed");
        let decrypted =
            decrypt_7z(&result.ciphertext, &result.props, password).expect("decrypt_7z failed");

        // Decrypted may have zero-padding; trim to original length.
        let trimmed = &decrypted[..plaintext.len()];
        assert_eq!(trimmed, plaintext, "round-trip mismatch");
    }

    #[test]
    fn wrong_password_produces_garbage() {
        let plaintext = b"secret data";
        let result = encrypt_7z(plaintext, "correct_password").expect("encrypt failed");
        let decrypted = decrypt_7z(&result.ciphertext, &result.props, "wrong_password")
            .expect("decrypt did not error (AES-CBC with wrong key produces garbage output)");

        // Decrypted bytes will not match plaintext.
        let trimmed = &decrypted[..plaintext.len()];
        assert_ne!(
            trimmed, plaintext,
            "wrong password should produce different output"
        );
    }

    #[test]
    fn each_call_produces_different_ciphertext() {
        // Two encrypts of the same data must produce different ciphertext (random IV).
        let plaintext = b"same plaintext";
        let r1 = encrypt_7z(plaintext, "pass").expect("first encrypt failed");
        let r2 = encrypt_7z(plaintext, "pass").expect("second encrypt failed");
        assert_ne!(r1.ciphertext, r2.ciphertext, "random IV must differ");
    }

    #[test]
    fn props_has_correct_format() {
        let result = encrypt_7z(b"test", "pass").expect("encrypt failed");
        let props = &result.props;
        // byte 0: NumCyclesPower=19 (0x13) | 0x40 (has_iv) = 0x53
        assert_eq!(
            props[0], 0x53,
            "byte 0 should be 0x53 (NumCyclesPower=19, has_iv)"
        );
        // byte 1: ivSize-1 = 15 = 0x0F
        assert_eq!(props[1], 0x0F, "byte 1 should be 0x0F (ivSize=16)");
        // props length = 2 + 16 = 18
        assert_eq!(props.len(), 18, "props should be 18 bytes");
    }

    #[test]
    fn round_trip_with_aes_properties_parse() {
        use crate::decrypt::AesProperties;
        // Verify the props we produce are parseable by AesProperties::parse.
        let plaintext = b"cross-module consistency check";
        let result = encrypt_7z(plaintext, "mypass").expect("encrypt failed");
        let parsed = AesProperties::parse(&result.props).expect("parse failed");
        assert_eq!(parsed.num_cycles_power, DEFAULT_NUM_CYCLES_POWER);
        assert_eq!(parsed.salt, Vec::<u8>::new());
    }
}
