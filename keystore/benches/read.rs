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

use core_crypto_keystore::Connection as CryptoKeystore;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use openmls::{
    credentials::{CredentialBundle, CredentialType},
    extensions::{Extension, ExternalKeyIdExtension},
    key_packages::KeyPackageBundle,
    prelude::Ciphersuite,
};
use openmls_rust_crypto_provider::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, random::OpenMlsRand, OpenMlsCryptoProvider};

#[cfg(feature = "proteus")]
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

    use core_crypto_keystore::CryptoKeystoreProteus;
    use proteus::session::PreKeyStore as _;
    group.bench_with_input(BenchmarkId::new("Reads", "cached"), &prekey_id, |b, prekey_id| {
        b.iter(|| black_box(store_cached.prekey(*prekey_id)))
    });

    group.bench_with_input(BenchmarkId::new("Reads", "uncached"), &prekey_id, |b, prekey_id| {
        b.iter(|| black_box(store_uncached.prekey(*prekey_id)))
    });

    group.finish();

    store_cached.wipe().unwrap();
    store_uncached.wipe().unwrap();
}

fn benchmark_reads_mls(c: &mut Criterion) {
    let store_cached = CryptoKeystore::open_with_key("bench_cached_read_mls", "key").unwrap();
    let store_uncached = CryptoKeystore::open_with_key("bench_uncached_read_mls", "key").unwrap();
    #[cfg(feature = "memory-cache")]
    store_uncached.cache(false);

    let backend = OpenMlsRustCrypto::default();
    let uuid: [u8; 16] = backend.rand().random_array().unwrap();
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

    let key_id = uuid::Uuid::from_bytes(uuid);

    let credentials = CredentialBundle::new_basic(
        vec![1, 2, 3],
        ciphersuite.signature_algorithm(),
        &backend,
    )
    .unwrap();

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

    store_cached.store(key.as_bytes(), &keypackage_bundle).unwrap();
    store_uncached.store(key.as_bytes(), &keypackage_bundle).unwrap();

    let mut group = c.benchmark_group("MLS Reads");
    group.throughput(Throughput::Elements(1));

    group.bench_with_input(BenchmarkId::new("Reads", "cached"), &key, |b, key| {
        b.iter(|| {
            let bundle: KeyPackageBundle = store_cached.read(key.as_bytes()).unwrap();
            black_box(bundle);
        })
    });

    group.bench_with_input(BenchmarkId::new("Reads", "uncached"), &key, |b, key| {
        b.iter(|| {
            let bundle: KeyPackageBundle = store_uncached.read(key.as_bytes()).unwrap();
            black_box(bundle);
        })
    });

    group.finish();

    store_cached.wipe().unwrap();
    store_uncached.wipe().unwrap();
}
#[cfg(not(feature = "proteus-keystore"))]
criterion_group!(benches, benchmark_reads_mls);
#[cfg(feature = "proteus-keystore")]
criterion_group!(benches, benchmark_reads_mls, benchmark_reads_proteus);
criterion_main!(benches);
