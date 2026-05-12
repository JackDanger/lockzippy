# lockzippy STATUS

**Current focus:** Phase 1 AES-256-CBC decryptor complete. KDF + AES verified against 7zz oracle.

| Piece | Status |
|---|---|
| KDF (SHA-256 with NumCyclesPower) | ✅ |
| AES-256-CBC decrypt | ✅ |
| Properties parsing | ✅ |
| Oracle (decrypt 7zz-generated archive) | ✅ (verified in Python; see 7zippy layer5_cross) |
| Encrypt (AES-256-CBC) | ⬜ (Phase 2) |
| Streaming decrypt | ⬜ |
| Bench | ⬜ |
| Fuzz | ⬜ |

**Phase 1 backend:** RustCrypto `aes = "0.8"`, `sha2 = "0.10"`, `cbc = "0.1"`.

Symbols: ⬜ not started, 🟡 in progress, ✅ done, ❌ blocked.
