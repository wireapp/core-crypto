use core_crypto_keystore::CryptoKeystore;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use openmls::{
    ciphersuite::{ciphersuites::CiphersuiteName, Ciphersuite},
    credentials::{CredentialBundle, CredentialType},
    extensions::{Extension, KeyIdExtension},
    key_packages::KeyPackageBundle,
};
use openmls_rust_crypto_provider::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, OpenMlsCryptoProvider, random::OpenMlsRand};

fn benchmark_reads_proteus(c: &mut Criterion) {
    let mut store_cached = CryptoKeystore::open_with_key("bench_cached_read_proteus", "key").unwrap();
    let mut store_uncached = CryptoKeystore::open_with_key("bench_uncached_read_proteus", "key").unwrap();
    store_uncached.cache(false);

    let prekey_id = proteus::keys::PreKeyId::new(28273);
    let prekey = proteus::keys::PreKey::new(prekey_id);

    store_cached.store_prekey(&prekey).unwrap();
    store_uncached.store_prekey(&prekey).unwrap();

    let mut group = c.benchmark_group("Proteus Reads");
    group.throughput(Throughput::Elements(1));

    use proteus::session::PreKeyStore as _;
    group.bench_with_input(
        BenchmarkId::new("Reads", "cached"),
        &prekey_id,
        |b, prekey_id| b.iter(|| black_box(store_cached.prekey(*prekey_id))),
    );

    group.bench_with_input(
        BenchmarkId::new("Reads", "uncached"),
        &prekey_id,
        |b, prekey_id| b.iter(|| black_box(store_uncached.prekey(*prekey_id))),
    );

    group.finish();

    store_cached.delete_database_but_please_be_sure().unwrap();
    store_uncached.delete_database_but_please_be_sure().unwrap();
}

fn benchmark_reads_mls(c: &mut Criterion) {
    let store_cached = CryptoKeystore::open_with_key("bench_cached_read_mls", "key").unwrap();
    let store_uncached = CryptoKeystore::open_with_key("bench_uncached_read_mls", "key").unwrap();
    store_uncached.cache(false);

    let backend = OpenMlsRustCrypto::default();
    let uuid: [u8; 16] = backend.rand().random_array().unwrap();
    let ciphersuite = Ciphersuite::new(CiphersuiteName::default()).unwrap();

    let key_id = uuid::Uuid::from_bytes(uuid);

    let credentials = CredentialBundle::new(
        vec![1, 2, 3],
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        &backend,
    )
    .unwrap();

    let keypackage_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &credentials,
        &backend,
        vec![Extension::KeyPackageId(KeyIdExtension::new(
            key_id.as_bytes(),
        ))],
    )
    .unwrap();

    keypackage_bundle.key_package().verify(&backend).unwrap();

    let key = {
        let id = keypackage_bundle.key_package().key_id().unwrap();
        uuid::Uuid::from_slice(id).unwrap()
    };

    store_cached.store(&key, &keypackage_bundle).unwrap();
    store_uncached.store(&key, &keypackage_bundle).unwrap();

    let mut group = c.benchmark_group("MLS Reads");
    group.throughput(Throughput::Elements(1));

    group.bench_with_input(
        BenchmarkId::new("Reads", "cached"),
        &key,
        |b, key| b.iter(|| {
            let bundle: KeyPackageBundle = store_cached.read(&key).unwrap();
            black_box(bundle);
        }),
    );

    group.bench_with_input(
        BenchmarkId::new("Reads", "uncached"),
        &key,
        |b, key| b.iter(|| {
            let bundle: KeyPackageBundle = store_uncached.read(&key).unwrap();
            black_box(bundle);
        }),
    );

    group.finish();

    store_cached.delete_database_but_please_be_sure().unwrap();
    store_uncached.delete_database_but_please_be_sure().unwrap();
}

criterion_group!(benches, benchmark_reads_proteus, benchmark_reads_mls);
criterion_main!(benches);
