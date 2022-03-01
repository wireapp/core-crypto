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

mod common;

#[cfg(test)]
mod tests {
    use super::common::*;

    use openmls::{
        credentials::{CredentialBundle, CredentialType},
        extensions::{Extension, ExternalKeyIdExtension},
        key_packages::KeyPackageBundle,
        prelude::Ciphersuite,
    };
    use openmls_rust_crypto_provider::OpenMlsRustCrypto;
    use openmls_traits::{random::OpenMlsRand, OpenMlsCryptoProvider};

    #[test]
    fn can_add_read_delete_keybundle() {
        let store = setup("mls");

        let backend = OpenMlsRustCrypto::default();
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
            let id = keypackage_bundle.key_package().external_key_id().unwrap();
            uuid::Uuid::from_slice(id).unwrap()
        };

        use openmls_traits::key_store::OpenMlsKeyStore as _;
        store.store(key.as_bytes(), &keypackage_bundle).unwrap();
        let bundle2: KeyPackageBundle = store.read(key.as_bytes()).unwrap();
        let (b1_kp, (b1_sk, b1_ls)) = keypackage_bundle.into_parts();
        let (b2_kp, (b2_sk, b2_ls)) = bundle2.into_parts();
        assert_eq!(b1_kp, b2_kp);
        assert_eq!(b1_sk, b2_sk);
        assert_eq!(b1_ls, b2_ls);

        let _ = store.delete(key.as_bytes()).unwrap();

        teardown(store);
    }
}
