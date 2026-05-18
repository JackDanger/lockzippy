use std::fmt;
use thiserror::Error;

/// All errors produced by aeszippy.
#[derive(Error, Debug)]
pub enum AeszippyError {
    /// The ciphertext length is not a multiple of the AES block size (16 bytes).
    #[error("ciphertext length {0} is not a multiple of AES block size 16")]
    InvalidCiphertextLength(usize),

    /// The properties blob had an unexpected length (expected 32+2 = 34 bytes or similar).
    #[error("invalid AES properties length {0} (expected at least 2 bytes)")]
    InvalidProperties(usize),

    /// The NumCyclesPower value was out of range.
    #[error("invalid NumCyclesPower {0} (valid range 0..=24)")]
    InvalidNumCyclesPower(u8),

    /// AES-CBC unpadding failed (wrong password or corrupt data).
    #[error("AES-CBC decrypt/unpad error: {0}")]
    DecryptError(String),

    /// Wrapped IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl AeszippyError {
    /// Construct a decrypt error from any `Display` value.
    pub fn decrypt<T: fmt::Display>(msg: T) -> Self {
        AeszippyError::DecryptError(msg.to_string())
    }
}

/// Convenience alias used throughout aeszippy.
pub type AeszippyResult<T> = Result<T, AeszippyError>;
