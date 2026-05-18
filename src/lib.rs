//! aeszippy — Pure-Rust AES-256 encrypt/decrypt for 7z archives. Part of the [7-zippy](https://github.com/JackDanger/7zippy) family.
//!
//! 7z uses AES-256-CBC with a SHA-256-based KDF. The codec method ID is
//! `[0x06, 0xF1, 0x07, 0x01]` (7zAES).
//!
//! ## Usage: Decrypt
//!
//! ```rust,no_run
//! use aeszippy::decrypt::decrypt_7z;
//!
//! // props comes from the 7z container (AES codec properties blob).
//! // password is the archive password supplied by the user.
//! let ciphertext = vec![0u8; 16];
//! let props = vec![0x53u8, 0x0Fu8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
//!                  0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
//! let decrypted = decrypt_7z(&ciphertext, &props, "my_password").unwrap();
//! ```
//!
//! ## Usage: Encrypt
//!
//! ```rust,no_run
//! use aeszippy::encrypt::encrypt_7z;
//!
//! let plaintext = b"hello, encrypted world!";
//! let result = encrypt_7z(plaintext, "my_password").unwrap();
//! // result.ciphertext — store as packed stream in the 7z folder
//! // result.props      — store as AES coder properties in the 7z container
//! ```

#![deny(unsafe_op_in_unsafe_fn)]

pub mod decrypt;
pub mod encrypt;
pub mod error;

#[cfg(test)]
mod tests;
