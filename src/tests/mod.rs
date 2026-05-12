//! Integration tests for lockzippy.
//!
//! These tests verify the AES-256 KDF and decryption against known vectors
//! and (when `7zz` is available) against 7zz-generated archives.

mod kdf_vectors;
