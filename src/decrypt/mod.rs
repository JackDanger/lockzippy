//! 7z AES-256 decryption — Phase 1 wrapper around RustCrypto primitives.
//!
//! ## 7z AES codec topology
//!
//! In a 7z archive, the AES coder is always the outermost coder in a folder.
//! It wraps one inner coder (typically LZMA2):
//!
//! ```text
//! packed[0] → AES-256-CBC decrypt → inner coder (e.g. LZMA2) → decompressed bytes
//! ```
//!
//! ## Properties format
//!
//! The 7z codec properties for `[0x06, 0xF1, 0x07, 0x01]` (7zAES) are a
//! variable-length blob:
//!
//! ```text
//! byte 0: NumCyclesPower [bits 0..3]  |  saltSizeExtra [bits 4..7]
//! byte 1: ivSize         [bits 0..3]  |  saltSizeMSN   [bits 4..7]
//! byte 2..(2+saltSize):  salt bytes
//! byte (2+saltSize)..(2+saltSize+ivSize): IV bytes
//! ```
//!
//! Where `saltSize = saltSizeExtra + (saltSizeMSN << 4)`.
//!
//! ## Key derivation
//!
//! 7z's password-based KDF:
//!
//! 1. Encode the password as UTF-16LE.
//! 2. Build a "seed": `salt || password_utf16le` repeated for `2^NumCyclesPower` iterations.
//! 3. For each 64-byte block of seed output, accumulate SHA-256 state (process
//!    `2^NumCyclesPower` blocks total while keeping a running 8-byte counter
//!    appended to the salt+password in each block).
//! 4. The 32-byte SHA-256 digest is the AES-256 key.
//!
//! More precisely (from LZMA SDK `CPP/7zip/Crypto/7zAes.cpp`):
//!
//! ```text
//! sha := SHA-256()
//! for round in 0 .. (1 << NumCyclesPower):
//!     sha.update(salt)
//!     sha.update(password_utf16le)
//!     sha.update(round as u64 in little-endian)
//! key := sha.finalize()
//! ```

use crate::error::{LockzippyError, LockzippyResult};

use aes::Aes256;
use cbc::Decryptor;
use cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use sha2::{Digest, Sha256};

// ── Properties parsing ────────────────────────────────────────────────────────

/// Parsed AES codec properties from the 7z container.
#[derive(Debug, Clone)]
pub struct AesProperties {
    /// KDF iteration count = `1 << num_cycles_power`.
    pub num_cycles_power: u8,
    /// Salt used in key derivation (0–15 bytes; typically 0 bytes).
    pub salt: Vec<u8>,
    /// AES-CBC initialization vector (typically 16 bytes).
    pub iv: [u8; 16],
}

impl AesProperties {
    /// Parse an AES properties blob from the 7z container.
    ///
    /// The format is:
    /// - byte 0: bits [0:5] = NumCyclesPower, bit 6 = has_iv, bit 7 = has_salt
    /// - byte 1: lower nibble = ivSize−1 (when has_iv=1), upper nibble = saltSize−1 (when has_salt=1)
    /// - bytes 2..(2+saltSize): salt
    /// - bytes (2+saltSize)..(2+saltSize+ivSize): IV
    ///
    /// # Errors
    ///
    /// Returns [`LockzippyError::InvalidProperties`] if the blob is too short.
    pub fn parse(props: &[u8]) -> LockzippyResult<Self> {
        if props.len() < 2 {
            return Err(LockzippyError::InvalidProperties(props.len()));
        }

        let b0 = props[0];
        let b1 = props[1];

        // bits [0:5] of byte 0 = NumCyclesPower
        let num_cycles_power = b0 & 0x3F;

        // bit 6 of byte 0 = IV-present flag; bit 7 = salt-present flag
        let has_iv = (b0 >> 6) & 1 != 0;
        let has_salt = (b0 >> 7) & 1 != 0;

        // When present: salt_size = upper_nibble(b1) + 1, iv_size = lower_nibble(b1) + 1
        let salt_size: usize = if has_salt {
            (((b1 >> 4) & 0x0F) + 1) as usize
        } else {
            0
        };
        let iv_size: usize = if has_iv {
            ((b1 & 0x0F) + 1) as usize
        } else {
            0
        };

        let required = 2 + salt_size + iv_size;
        if props.len() < required {
            return Err(LockzippyError::InvalidProperties(props.len()));
        }

        let salt = props[2..2 + salt_size].to_vec();
        let iv_bytes = &props[2 + salt_size..2 + salt_size + iv_size];

        // IV is always treated as 16 bytes; pad with zeros if shorter.
        let mut iv = [0u8; 16];
        let copy_len = iv_bytes.len().min(16);
        iv[..copy_len].copy_from_slice(&iv_bytes[..copy_len]);

        Ok(AesProperties {
            num_cycles_power,
            salt,
            iv,
        })
    }
}

// ── Key derivation ────────────────────────────────────────────────────────────

/// Derive the 32-byte AES-256 key from a UTF-8 password using the 7z KDF.
///
/// The password is encoded as UTF-16LE before hashing.
///
/// # Algorithm
///
/// ```text
/// sha := SHA-256()
/// for round in 0 .. (1 << num_cycles_power):
///     sha.update(salt)
///     sha.update(password as UTF-16LE)
///     sha.update(round as u64 LE)
/// key := sha.finalize()
/// ```
pub fn derive_key(password: &str, salt: &[u8], num_cycles_power: u8) -> [u8; 32] {
    let pw_utf16le: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let num_rounds: u64 = 1u64 << num_cycles_power;
    let mut hasher = Sha256::new();

    for round in 0u64..num_rounds {
        hasher.update(salt);
        hasher.update(&pw_utf16le);
        hasher.update(round.to_le_bytes());
    }

    hasher.finalize().into()
}

// ── Decryption ────────────────────────────────────────────────────────────────

/// Decrypt a 7z AES-256-CBC encrypted stream.
///
/// The ciphertext must be a multiple of 16 bytes (AES block size). No PKCS#7
/// unpadding is performed — 7z does not add padding; the caller is responsible
/// for trimming to the expected uncompressed size.
///
/// # Arguments
///
/// - `ciphertext`: the raw encrypted bytes from the packed stream
/// - `key`: the 32-byte AES-256 key (from [`derive_key`])
/// - `iv`: the 16-byte initialization vector (from [`AesProperties`])
///
/// # Errors
///
/// Returns [`LockzippyError::InvalidCiphertextLength`] if `ciphertext.len()` is
/// not a multiple of 16.
pub fn decrypt_aes256_cbc(
    ciphertext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16],
) -> LockzippyResult<Vec<u8>> {
    if !ciphertext.len().is_multiple_of(16) {
        return Err(LockzippyError::InvalidCiphertextLength(ciphertext.len()));
    }

    let mut buf = ciphertext.to_vec();
    Decryptor::<Aes256>::new(key.into(), iv.into())
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(LockzippyError::decrypt)?;

    Ok(buf)
}

/// All-in-one: parse AES properties, derive key from password, and decrypt.
///
/// This is the main entry point for 7zippy's AES pipeline integration.
///
/// # Arguments
///
/// - `ciphertext`: the raw encrypted bytes from the packed stream
/// - `props`: the AES codec properties blob from the 7z container
/// - `password`: the archive password (UTF-8)
///
/// # Returns
///
/// The decrypted bytes. These may contain AES-block-alignment padding at the
/// end (up to 15 zeros); the caller should trim to the expected uncompressed
/// size.
pub fn decrypt_7z(ciphertext: &[u8], props: &[u8], password: &str) -> LockzippyResult<Vec<u8>> {
    let aes_props = AesProperties::parse(props)?;
    let key = derive_key(password, &aes_props.salt, aes_props.num_cycles_power);
    decrypt_aes256_cbc(ciphertext, &key, &aes_props.iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that AES-256-CBC round-trip works with a known key and IV.
    #[test]
    fn aes_cbc_round_trip() {
        use aes::Aes256;
        use cbc::Encryptor;
        use cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};

        let key = [0x42u8; 32];
        let iv = [0x13u8; 16];
        let plaintext = [0xABu8; 32]; // 2 blocks

        let mut enc_buf = plaintext;
        Encryptor::<Aes256>::new(&key.into(), &iv.into())
            .encrypt_padded_mut::<NoPadding>(&mut enc_buf, 32)
            .unwrap();

        let decrypted = decrypt_aes256_cbc(&enc_buf, &key, &iv).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Key derivation smoke test: two different passwords produce different keys.
    #[test]
    fn key_derivation_differs_by_password() {
        let k1 = derive_key("password1", &[], 6);
        let k2 = derive_key("password2", &[], 6);
        assert_ne!(k1, k2);
    }

    /// Key derivation is deterministic.
    #[test]
    fn key_derivation_is_deterministic() {
        let k1 = derive_key("test1234", &[], 19);
        let k2 = derive_key("test1234", &[], 19);
        assert_eq!(k1, k2);
    }

    /// Parse AES properties matching the 7zz output format (no salt, 16-byte IV).
    ///
    /// Format used by 7zz: b0 = NumCyclesPower | 0x40 (has_iv), b1 = ivSize-1 in lower nibble.
    /// For 19 KDF rounds, no salt, 16-byte IV:
    ///   b0 = 19 | 0x40 = 83 = 0x53
    ///   b1 = 15 = 0x0F   (ivSize = 15 + 1 = 16)
    #[test]
    fn parse_aes_props_no_salt() {
        let iv_bytes = [0xAAu8; 16];
        // b0 = 19 | (1 << 6) = 83 = 0x53  (NumCyclesPower=19, has_iv=1, has_salt=0)
        // b1 = 0x0F  (ivSize = 0x0F + 1 = 16)
        let mut props = vec![0x53u8, 0x0Fu8];
        props.extend_from_slice(&iv_bytes);

        let p = AesProperties::parse(&props).unwrap();
        assert_eq!(p.num_cycles_power, 19);
        assert_eq!(p.salt, Vec::<u8>::new());
        assert_eq!(p.iv, iv_bytes);
    }

    /// Verify empty props returns an error.
    #[test]
    fn parse_too_short_props() {
        let result = AesProperties::parse(&[42u8]);
        assert!(matches!(result, Err(LockzippyError::InvalidProperties(1))));
    }
}
