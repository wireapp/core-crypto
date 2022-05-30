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

pub mod tests {
    use crate::common::*;
    use core_crypto_keystore::entities::MlsKeypackage;
    use openmls_traits::key_store::{FromKeyStoreValue, ToKeyStoreValue};
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test]
    pub fn can_add_read_delete_keypackage_bundle_openmls_traits() {
        use openmls::{
            credentials::CredentialBundle,
            extensions::{Extension, ExternalKeyIdExtension},
            key_packages::KeyPackageBundle,
            prelude::Ciphersuite,
        };
        use openmls_rust_crypto_provider::OpenMlsRustCrypto;

        let store = setup("mls-traits");

        let backend = OpenMlsRustCrypto::default();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let key_id: [u8; 16] = rand::random();
        let key_id = uuid::Uuid::from_bytes(key_id);

        let credentials =
            CredentialBundle::new_basic(vec![1, 2, 3], ciphersuite.signature_algorithm(), &backend).unwrap();

        let keypackage_bundle = KeyPackageBundle::new(
            &[ciphersuite],
            &credentials,
            &backend,
            vec![Extension::ExternalKeyId(ExternalKeyIdExtension::new(key_id.as_bytes()))],
        )
        .unwrap();
        let key_string = key_id.as_hyphenated().to_string();

        keypackage_bundle.key_package().verify(&backend).unwrap();

        use openmls_traits::key_store::OpenMlsKeyStore as _;
        store.store(&key_string.as_bytes(), &keypackage_bundle).unwrap();
        let bundle2: KeyPackageBundle = store.read(&key_string.as_bytes()).unwrap();
        let (b1_kp, (b1_sk, b1_ls)) = keypackage_bundle.into_parts();
        let (b2_kp, (b2_sk, b2_ls)) = bundle2.into_parts();
        assert_eq!(b1_kp, b2_kp);
        assert_eq!(b1_sk, b2_sk);
        assert_eq!(b1_ls, b2_ls);

        store.delete(&key_string.as_bytes()).unwrap();

        teardown(store);
    }

    #[test]
    #[wasm_bindgen_test]
    pub fn can_add_read_delete_keypackage_bundle_keystore() {
        use openmls::{
            credentials::CredentialBundle,
            extensions::{Extension, ExternalKeyIdExtension},
            key_packages::KeyPackageBundle,
            prelude::Ciphersuite,
        };
        use openmls_rust_crypto_provider::OpenMlsRustCrypto;
        let store = setup("mls-keystore");

        let backend = OpenMlsRustCrypto::default();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let key_id: [u8; 16] = rand::random();
        let key_id = uuid::Uuid::from_bytes(key_id);

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

        let key_string = key_id.as_hyphenated().to_string();

        let entity = MlsKeypackage {
            id: key_string.clone(),
            key: keypackage_bundle.to_key_store_value().unwrap(),
        };

        store.insert(entity).unwrap();

        let entity2: MlsKeypackage = store.find(key_string.as_bytes()).unwrap().unwrap();
        let bundle2 = KeyPackageBundle::from_key_store_value(&entity2.key).unwrap();

        let (b1_kp, (b1_sk, b1_ls)) = keypackage_bundle.into_parts();
        let (b2_kp, (b2_sk, b2_ls)) = bundle2.into_parts();
        assert_eq!(b1_kp, b2_kp);
        assert_eq!(b1_sk, b2_sk);
        assert_eq!(b1_ls, b2_ls);

        let _ = store.remove::<MlsKeypackage, _>(&key_string.as_bytes()).unwrap();

        teardown(store);
    }
}
