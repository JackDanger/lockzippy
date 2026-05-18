use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf");
    // 7zz default NumCyclesPower=19 ≈ 500k rounds; bench at 10 to keep it fast.
    group.bench_function("derive_key_power10", |b| {
        b.iter(|| {
            aeszippy::decrypt::derive_key(
                black_box("benchmark_password"),
                black_box(&[]),
                black_box(10),
            )
        });
    });
    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    use aeszippy::decrypt::derive_key;
    let key = derive_key("bench", &[], 10);
    let iv = [0u8; 16];
    // 64 KiB of fake ciphertext
    let ciphertext = vec![0xABu8; 65_536];

    let mut group = c.benchmark_group("decrypt");
    group.bench_function("aes256_cbc_64k", |b| {
        b.iter(|| {
            aeszippy::decrypt::decrypt_aes256_cbc(
                black_box(&ciphertext),
                black_box(&key),
                black_box(&iv),
            )
            .unwrap()
        });
    });
    group.finish();
}

criterion_group!(benches, bench_kdf, bench_decrypt);
criterion_main!(benches);
