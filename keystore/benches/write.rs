// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput,
};
use openmls::{
    credentials::CredentialBundle,
    extensions::{Extension, ExternalKeyIdExtension},
    key_packages::KeyPackageBundle,
    prelude::Ciphersuite,
};
use openmls_traits::{key_store::OpenMlsKeyStore, random::OpenMlsRand, OpenMlsCryptoProvider};

use core_crypto_keystore::Connection as CryptoKeystore;
use futures_lite::future::block_on;
use mls_crypto_provider::MlsCryptoProvider;

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
                let pk = PreKey::new(PreKeyId::new(u16::from_le_bytes(prng.gen())));
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

    group.bench_with_input("Writes", backend.borrow_keystore(), |b, store| {
        b.to_async(FuturesExecutor).iter_batched(
            || {
                let uuid: [u8; 16] = backend.rand().random_array().unwrap();
                let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

                let key_id = uuid::Uuid::from_bytes(uuid);

                let credentials =
                    CredentialBundle::new_basic(vec![1, 2, 3], ciphersuite.signature_algorithm(), &backend).unwrap();

                let keypackage_bundle = KeyPackageBundle::new(
                    &[ciphersuite],
                    &credentials,
                    &backend,
                    vec![Extension::ExternalKeyId(ExternalKeyIdExtension::new(key_id.as_bytes()))],
                )
                .unwrap();

                keypackage_bundle.key_package().verify(&backend).unwrap();

                let key = {
                    let id = keypackage_bundle
                        .key_package()
                        .extensions()
                        .iter()
                        .find(|e| e.as_external_key_id_extension().is_ok())
                        .unwrap()
                        .as_external_key_id_extension()
                        .unwrap()
                        .as_slice();

                    uuid::Uuid::from_slice(id).unwrap()
                };

                (key, keypackage_bundle)
            },
            |(key, bundle)| async move { black_box(store.store(key.as_bytes(), &bundle).await) },
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
