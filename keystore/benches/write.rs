use core_crypto_keystore::CryptoKeystore;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use openmls::{
    ciphersuite::{ciphersuites::CiphersuiteName, Ciphersuite},
    credentials::{CredentialBundle, CredentialType},
    extensions::{Extension, KeyIdExtension},
    key_packages::KeyPackageBundle,
};
use openmls_rust_crypto_provider::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, OpenMlsCryptoProvider, random::OpenMlsRand};
use proteus::keys::{PreKey, PreKeyId};

fn benchmark_writes_proteus(c: &mut Criterion) {
    let store = CryptoKeystore::open_with_key("bench_write", "key").unwrap();
    let backend = OpenMlsRustCrypto::default();

    let mut group = c.benchmark_group("Proteus Writes");
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

fn benchmark_writes_mls(c: &mut Criterion) {
    let store = CryptoKeystore::open_with_key("bench_write", "key").unwrap();
    let backend = OpenMlsRustCrypto::default();

    let mut group = c.benchmark_group("MLS Writes");
    group.throughput(Throughput::Elements(1));

    group.bench_function("Writes", |b| {
        b.iter_batched(
            || {
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

                (key, keypackage_bundle)
            },
            |(key, bundle)| black_box(store.store(&key, &bundle)),
            BatchSize::SmallInput,
        )
    });

    group.finish();
    store.delete_database_but_please_be_sure().unwrap();
}

criterion_group!(benches, benchmark_writes_proteus, benchmark_writes_mls);
criterion_main!(benches);
