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
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use openmls::{
    credentials::{CredentialBundle, CredentialType},
    extensions::{Extension, ExternalKeyIdExtension},
    key_packages::KeyPackageBundle,
    prelude::Ciphersuite,
};
use openmls_rust_crypto_provider::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, random::OpenMlsRand, OpenMlsCryptoProvider};

#[cfg(feature = "proteus")]
fn benchmark_writes_proteus(c: &mut Criterion) {
    use core_crypto_keystore::CryptoKeystoreProteus;
    use proteus::keys::{PreKey, PreKeyId};

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
    store.wipe().unwrap();
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
                let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

                let key_id = uuid::Uuid::from_bytes(uuid);

                let credentials = CredentialBundle::new(
                    vec![1, 2, 3],
                    CredentialType::Basic,
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

                (key, keypackage_bundle)
            },
            |(key, bundle)| black_box(store.store(key.as_bytes(), &bundle)),
            BatchSize::SmallInput,
        )
    });

    group.finish();
    store.wipe().unwrap();
}

#[cfg(not(feature = "proteus-keystore"))]
criterion_group!(benches, benchmark_writes_mls);
#[cfg(feature = "proteus-keystore")]
criterion_group!(benches, benchmark_writes_mls, benchmark_writes_proteus);
criterion_main!(benches);
