use core_crypto_keystore::CryptoKeystore;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{random::OpenMlsRand, OpenMlsCryptoProvider};
use proteus::keys::{PreKey, PreKeyId};

fn benchmark_reads(c: &mut Criterion) {
    let store = CryptoKeystore::open_with_key("bench_write", "key").unwrap();
    let backend = OpenMlsRustCrypto::default();

    let mut group = c.benchmark_group("Writes");
    group.throughput(Throughput::Elements(1));

    group.bench_function("Writes", |b| {
        b.iter_batched(
            || {
                PreKey::new(PreKeyId::new(u16::from_le_bytes(
                    backend.rand().random_array::<2>().unwrap(),
                )))
            },
            |prekey| black_box(store.store_prekey(&prekey)),
            BatchSize::SmallInput,
        )
    });

    group.finish();
    store.delete_database_but_please_be_sure().unwrap();
}

criterion_group!(benches, benchmark_reads);
criterion_main!(benches);
