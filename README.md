# lockzippy

Pure-Rust AES-256 decryptor for 7z archives, part of the
[8z](https://github.com/JackDanger/7zippy) umbrella of pure-Rust compression codecs.

7z uses AES-256-CBC with a SHA-256-based KDF (method ID `[0x06, 0xF1, 0x07, 0x01]`).
The KDF iterates SHA-256 over `salt || password_utf16le || round_counter`
for `2^NumCyclesPower` rounds.

See [STATUS.md](./STATUS.md) for the current implementation state.

## Build & Test

```sh
cargo build
cargo test
cargo bench --no-run   # verify bench targets compile
```

## Properties format

The 7z AES properties blob:

```
byte 0: bits [0:5] = NumCyclesPower, bit 6 = has_iv, bit 7 = has_salt
byte 1: lower nibble = ivSize−1 (when has_iv=1), upper nibble = saltSize−1 (when has_salt=1)
bytes 2..(2+saltSize): salt
bytes (2+saltSize)..(2+saltSize+ivSize): IV
```

## Key derivation

```text
sha := SHA-256()
for round in 0 .. (1 << NumCyclesPower):
    sha.update(salt)
    sha.update(password as UTF-16LE)
    sha.update(round as u64 little-endian)
key := sha.finalize()
```
