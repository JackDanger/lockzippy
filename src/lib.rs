//! lockzippy — Pure-Rust AES-256 decryptor for 7z archives, part of the 8z umbrella.
//!
//! 7z uses AES-256-CBC with a SHA-256-based KDF. The codec method ID is
//! `[0x06, 0xF1, 0x07, 0x01]` (7zAES).
//!
//! ## Phase 1
//!
//! Phase 1 implements decryption only. Encryption is not yet implemented.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use lockzippy::decrypt::decrypt_7z;
//!
//! // props comes from the 7z container (AES codec properties blob).
//! // password is the archive password supplied by the user.
//! let ciphertext = vec![0u8; 16];
//! let props = vec![0x53u8, 0x0Fu8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
//!                  0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
//! let decrypted = decrypt_7z(&ciphertext, &props, "my_password").unwrap();
//! ```

#![deny(unsafe_op_in_unsafe_fn)]

pub mod decrypt;
pub mod error;

#[cfg(test)]
mod tests;
