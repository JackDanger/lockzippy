# aeszippy

> **Part of the [7-zippy](https://github.com/JackDanger/7zippy) family** — pure-Rust compression tooling.
> Full suite: `cargo add sevenzippy`  |  This crate: `cargo add aeszippy`

Pure-Rust AES-256-CBC encrypt/decrypt for 7z archives (method ID `[0x06, 0xF1, 0x07, 0x01]`).
Implements the 7z password-based KDF (SHA-256 iterated `2^NumCyclesPower` times) and
the AES-256-CBC cipher with the NoPadding scheme used by 7z.

## Use as a library

```toml
[dependencies]
aeszippy = "0.0.3"
```

```rust
use aeszippy::decrypt::decrypt_7z;
use aeszippy::encrypt::encrypt_7z;

// Decrypt
let plaintext = decrypt_7z(&ciphertext, &props, "my_password")?;

// Encrypt
let result = encrypt_7z(plaintext_bytes, "my_password")?;
// result.ciphertext → packed stream in the 7z folder
// result.props      → AES coder properties in the 7z container
```

## Build & Test

```sh
cargo build
cargo test
cargo bench --no-run   # verify bench targets compile
```

## Properties format

```
byte 0: bits [0:5] = NumCyclesPower, bit 6 = has_iv, bit 7 = has_salt
byte 1: lower nibble = ivSize−1, upper nibble = saltSize−1
bytes 2..(2+saltSize): salt
bytes (2+saltSize)..(2+saltSize+ivSize): IV
```

## Key derivation

```
sha := SHA-256()
for round in 0 .. (1 << NumCyclesPower):
    sha.update(salt)
    sha.update(password as UTF-16LE)
    sha.update(round as u64 little-endian)
key := sha.finalize()
```

See [STATUS.md](./STATUS.md) for the current implementation state.
