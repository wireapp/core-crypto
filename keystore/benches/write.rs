#![cfg(not(target_family = "wasm"))]

use criterion::{
    BatchSize, Criterion, Throughput, async_executor::FuturesExecutor, black_box, criterion_group, criterion_main,
};
use openmls::prelude::Ciphersuite;
use openmls_traits::{OpenMlsCryptoProvider, key_store::OpenMlsKeyStore, random::OpenMlsRand};

use core_crypto_keystore::Connection as CryptoKeystore;
use futures_lite::future::block_on;
use mls_crypto_provider::MlsCryptoProvider;
use openmls_basic_credential::SignatureKeyPair;

#[cfg(feature = "proteus-keystore")]
fn benchmark_writes_proteus(c: &mut Criterion) {
    use core_crypto_keystore::CryptoKeystoreProteus as _;
    use proteus_wasm::keys::{PreKey, PreKeyId};
    use rand::Rng as _;

    let store = block_on(async { CryptoKeystore::open_with_key("bench_write", "key").await.unwrap() });
    let mut prng = rand::thread_rng();

    let mut group = c.benchmark_group("Proteus Writes");
    group.throughput(Throughput::Elements(1));

    group.bench_with_input("Writes", &store, |b, store| {
        b.to_async(FuturesExecutor).iter_batched(
            || {
                let pk = PreKey::new(PreKeyId::new(u16::from_le_bytes(prng.r#gen())));
                (pk.key_id.value(), pk.serialise().unwrap())
            },
            |(pk_id, pk_ser)| async move {
                store.proteus_store_prekey(pk_id, &pk_ser).await.unwrap();
                black_box(())
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
    block_on(async { store.wipe().await.unwrap() });
}

fn benchmark_writes_mls(c: &mut Criterion) {
    let store = block_on(async { CryptoKeystore::open_with_key("bench_write", "key").await.unwrap() });
    let backend = MlsCryptoProvider::new_with_store(store, None);

    let mut group = c.benchmark_group("MLS Writes");
    group.throughput(Throughput::Elements(1));

    group.bench_with_input("Writes", &backend.keystore(), |b, store: &CryptoKeystore| {
        b.to_async(FuturesExecutor).iter_batched(
            || {
                let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
                let key = uuid::Uuid::new_v4();
                let mut rng = &mut *backend.rand().borrow_rand().unwrap();
                let kp = SignatureKeyPair::new(ciphersuite.signature_algorithm(), &mut rng).unwrap();

                (key, kp)
            },
            |(key, skp)| async move { black_box(store.store(key.as_bytes(), &skp).await) },
            BatchSize::SmallInput,
        )
    });

    group.finish();
    let store = backend.unwrap_keystore();
    block_on(async { store.wipe().await.unwrap() });
}

cfg_if::cfg_if! {
    if #[cfg(feature = "proteus-keystore")] {
        criterion_group!(benches, benchmark_writes_mls, benchmark_writes_proteus);
    } else {
        criterion_group!(benches, benchmark_writes_mls);
    }
}

criterion_main!(benches);
