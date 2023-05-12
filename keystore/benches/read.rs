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

#![cfg(not(target_family = "wasm"))]

use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
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
struct ProteusReadParams {
    store: std::cell::RefCell<CryptoKeystore>,
    prekey_id: u16,
}

#[cfg(feature = "proteus-keystore")]
fn benchmark_reads_proteus(c: &mut Criterion) {
    let store_cached = block_on(CryptoKeystore::open_with_key("bench_cached_read_proteus", "key")).unwrap();
    let store_uncached = block_on(CryptoKeystore::open_with_key("bench_uncached_read_proteus", "key")).unwrap();
    #[cfg(feature = "memory-cache")]
    store_uncached.cache(false);

    let prekey_id = proteus_wasm::keys::PreKeyId::new(28273);
    let prekey = proteus_wasm::keys::PreKey::new(prekey_id);

    use core_crypto_keystore::CryptoKeystoreProteus as _;
    let prekey_id_value = prekey_id.value();
    let prekey_ser = prekey.serialise().unwrap();
    block_on(async {
        store_cached
            .proteus_store_prekey(prekey_id_value, &prekey_ser)
            .await
            .unwrap();
        store_uncached
            .proteus_store_prekey(prekey_id_value, &prekey_ser)
            .await
            .unwrap();
    });

    let mut group = c.benchmark_group("Proteus Reads");
    group.throughput(Throughput::Elements(1));

    use proteus_traits::PreKeyStore as _;
    let params_cached = ProteusReadParams {
        store: store_cached.into(),
        prekey_id: prekey_id_value,
    };
    group.bench_with_input(BenchmarkId::new("Reads", "cached"), &params_cached, |b, params| {
        b.to_async(FuturesExecutor).iter(|| async move {
            let prekey = params.store.borrow_mut().prekey(params.prekey_id).await.unwrap();
            black_box(prekey)
        })
    });

    let params_uncached = ProteusReadParams {
        store: store_uncached.into(),
        prekey_id: prekey_id_value,
    };
    group.bench_with_input(BenchmarkId::new("Reads", "uncached"), &params_uncached, |b, params| {
        b.to_async(FuturesExecutor).iter(|| async {
            let prekey = params.store.borrow_mut().prekey(params.prekey_id).await.unwrap();
            black_box(prekey)
        })
    });

    group.finish();

    let store_cached = params_cached.store.into_inner();
    let store_uncached = params_uncached.store.into_inner();

    block_on(async move {
        store_cached.wipe().await.unwrap();
        store_uncached.wipe().await.unwrap();
    });
}

fn benchmark_reads_mls(c: &mut Criterion) {
    let store_cached = block_on(async {
        CryptoKeystore::open_with_key("bench_cached_read_mls", "key")
            .await
            .unwrap()
    });
    let store_uncached = block_on(async {
        CryptoKeystore::open_with_key("bench_uncached_read_mls", "key")
            .await
            .unwrap()
    });
    #[cfg(feature = "memory-cache")]
    store_uncached.cache(false);

    let backend = block_on(async { MlsCryptoProvider::try_new("mls-read.edb", "secret").await.unwrap() });

    let uuid: [u8; 16] = backend.rand().random_array().unwrap();
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

    let key_id = uuid::Uuid::from_bytes(uuid);

    let credentials = CredentialBundle::new_basic(vec![1, 2, 3], ciphersuite.signature_algorithm(), &backend).unwrap();

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

    block_on(async {
        store_cached.store(key.as_bytes(), &keypackage_bundle).await.unwrap();
        store_uncached.store(key.as_bytes(), &keypackage_bundle).await.unwrap();
    });

    let mut group = c.benchmark_group("MLS Reads");
    group.throughput(Throughput::Elements(1));

    group.bench_with_input(BenchmarkId::new("Reads", "cached"), &key, |b, key| {
        b.to_async(FuturesExecutor).iter(|| async {
            let bundle: KeyPackageBundle = store_cached.read(key.as_bytes()).await.unwrap();
            black_box(bundle);
        })
    });

    group.bench_with_input(BenchmarkId::new("Reads", "uncached"), &key, |b, key| {
        b.to_async(FuturesExecutor).iter(|| async {
            let bundle: KeyPackageBundle = store_uncached.read(key.as_bytes()).await.unwrap();
            black_box(bundle);
        })
    });

    group.finish();

    block_on(async {
        store_cached.wipe().await.unwrap();
        store_uncached.wipe().await.unwrap();
    });
}

cfg_if::cfg_if! {
    if #[cfg(feature = "proteus-keystore")] {
        criterion_group!(benches, benchmark_reads_mls, benchmark_reads_proteus);
    } else {
        criterion_group!(benches, benchmark_reads_mls);
    }
}

criterion_main!(benches);
