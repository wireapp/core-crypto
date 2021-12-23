use core_crypto_keystore::CryptoKeystore;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn benchmark_reads(c: &mut Criterion) {
    let mut store_cached = CryptoKeystore::open_with_key("bench_cached_read", "key").unwrap();
    let mut store_uncached = CryptoKeystore::open_with_key("bench_uncached_read", "key").unwrap();
    store_uncached.cache(false);

    let prekey_id = proteus::keys::PreKeyId::new(28273);
    let prekey = proteus::keys::PreKey::new(prekey_id);

    store_cached.store_prekey(&prekey).unwrap();
    store_uncached.store_prekey(&prekey).unwrap();

    let mut group = c.benchmark_group("Reads");
    group.throughput(Throughput::Elements(1));

    use proteus::session::PreKeyStore as _;
    group.bench_with_input(
        BenchmarkId::new("Cache", "enabled"),
        &prekey_id,
        |b, prekey_id| b.iter(|| black_box(store_cached.prekey(*prekey_id))),
    );

    group.bench_with_input(
        BenchmarkId::new("Cache", "disabled"),
        &prekey_id,
        |b, prekey_id| b.iter(|| black_box(store_uncached.prekey(*prekey_id))),
    );

    group.finish();

    store_cached.delete_database_but_please_be_sure().unwrap();
    store_uncached.delete_database_but_please_be_sure().unwrap();
}

criterion_group!(benches, benchmark_reads);
criterion_main!(benches);
