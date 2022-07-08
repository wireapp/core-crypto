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

pub use rstest::*;
pub use rstest_reuse::{self, *};

mod common;

pub mod tests {
    use crate::common::*;
    use openmls::prelude::Ciphersuite;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    use mls_crypto_provider::MlsCryptoProvider;

    use core_crypto_keystore::entities::{
        EntityBase, MlsIdentity, MlsIdentityExt as _, MlsKeypackage, PersistedMlsGroup,
    };
    use core_crypto_keystore::{Connection, MissingKeyErrorKind};
    use openmls::prelude::TlsSerializeTrait as _;
    use openmls_traits::{
        key_store::{FromKeyStoreValue as _, ToKeyStoreValue as _},
        OpenMlsCryptoProvider as _,
    };

    #[test]
    #[wasm_bindgen_test]
    fn mls_entities_have_correct_error_kinds() {
        assert_eq!(
            MlsIdentity::to_missing_key_err_kind(),
            MissingKeyErrorKind::MlsIdentityBundle
        );

        assert_eq!(
            MlsKeypackage::to_missing_key_err_kind(),
            MissingKeyErrorKind::MlsKeyPackageBundle
        );

        assert_eq!(
            PersistedMlsGroup::to_missing_key_err_kind(),
            MissingKeyErrorKind::MlsGroup
        );
    }

    #[apply(all_storage_types)]
    #[wasm_bindgen_test]
    pub async fn can_add_read_delete_credential_bundle_keystore(store: Connection) {
        use openmls::credentials::CredentialBundle;

        let store = store.await;
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let backend = MlsCryptoProvider::new_with_store(store, None);
        let identity_id: [u8; 16] = rand::random();
        let identity_id = uuid::Uuid::from_bytes(identity_id);

        let credentials = CredentialBundle::new_basic(
            identity_id.as_bytes().as_slice().into(),
            ciphersuite.signature_algorithm(),
            &backend,
        )
        .unwrap();

        let signature = credentials
            .credential()
            .signature_key()
            .tls_serialize_detached()
            .unwrap();

        let identity = MlsIdentity {
            id: identity_id.hyphenated().to_string(),
            signature: signature.clone(),
            credential: credentials.to_key_store_value().unwrap(),
        };

        backend.key_store().save(identity).await.unwrap();

        let mut conn = backend.key_store().borrow_conn().await.unwrap();
        let identity2 = MlsIdentity::find_by_signature(&mut *conn, &signature)
            .await
            .unwrap()
            .unwrap();

        drop(conn);

        let credentials2 = CredentialBundle::from_key_store_value(&identity2.credential).unwrap();
        let (b1_kp, b1_sk) = credentials.into_parts();
        let (b2_kp, b2_sk) = credentials2.into_parts();
        assert_eq!(b1_kp, b2_kp);
        assert_eq!(b1_sk.as_slice(), b2_sk.as_slice());

        let mut conn = backend.key_store().borrow_conn().await.unwrap();
        MlsIdentity::delete_by_signature(&mut *conn, &signature).await.unwrap();

        drop(conn);

        teardown(backend.unwrap_keystore()).await;
    }

    #[apply(all_storage_types)]
    #[wasm_bindgen_test]
    pub async fn can_add_read_delete_credential_bundle_openmls_traits(store: Connection) {
        use openmls::credentials::CredentialBundle;

        let store = store.await;
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let backend = MlsCryptoProvider::new_with_store(store, None);
        let identity_id: [u8; 16] = rand::random();
        let identity_id = uuid::Uuid::from_bytes(identity_id);

        let credentials = CredentialBundle::new_basic(
            identity_id.as_bytes().as_slice().into(),
            ciphersuite.signature_algorithm(),
            &backend,
        )
        .unwrap();

        use openmls_traits::key_store::OpenMlsKeyStore as _;
        let signature = credentials
            .credential()
            .signature_key()
            .tls_serialize_detached()
            .unwrap();
        let identity = MlsIdentity {
            id: identity_id.hyphenated().to_string(),
            signature: signature.clone(),
            credential: credentials.to_key_store_value().unwrap(),
        };
        backend.key_store().save(identity).await.unwrap();
        let credentials2: CredentialBundle = backend.key_store().read(&signature).await.unwrap();
        let (b1_kp, b1_sk) = credentials.into_parts();
        let (b2_kp, b2_sk) = credentials2.into_parts();
        assert_eq!(b1_kp, b2_kp);
        assert_eq!(b1_sk.as_slice(), b2_sk.as_slice());

        backend
            .key_store()
            .delete::<CredentialBundle>(&signature)
            .await
            .unwrap();

        teardown(backend.unwrap_keystore()).await;
    }

    #[apply(all_storage_types)]
    #[wasm_bindgen_test]
    pub async fn can_add_read_delete_keypackage_bundle_openmls_traits(store: Connection) {
        use openmls::{
            credentials::CredentialBundle,
            extensions::{Extension, ExternalKeyIdExtension},
            key_packages::KeyPackageBundle,
        };

        let store = store.await;
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let backend = MlsCryptoProvider::new_with_store(store, None);
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
        backend
            .key_store()
            .store(key_string.as_bytes(), &keypackage_bundle)
            .await
            .unwrap();
        let bundle2: KeyPackageBundle = backend.key_store().read(key_string.as_bytes()).await.unwrap();
        let (b1_kp, (b1_sk, b1_ls)) = keypackage_bundle.into_parts();
        let (b2_kp, (b2_sk, b2_ls)) = bundle2.into_parts();
        assert_eq!(b1_kp, b2_kp);
        assert_eq!(b1_sk, b2_sk);
        assert_eq!(b1_ls, b2_ls);

        backend
            .key_store()
            .delete::<KeyPackageBundle>(key_string.as_bytes())
            .await
            .unwrap();

        teardown(backend.unwrap_keystore()).await;
    }

    #[apply(all_storage_types)]
    #[wasm_bindgen_test]
    pub async fn can_add_read_delete_keypackage_bundle_keystore(store: Connection) {
        use openmls::{
            credentials::CredentialBundle,
            extensions::{Extension, ExternalKeyIdExtension},
            key_packages::KeyPackageBundle,
        };

        let store = store.await;

        let backend = MlsCryptoProvider::new_with_store(store, None);
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

        backend.key_store().save(entity).await.unwrap();

        let entity2: MlsKeypackage = backend.key_store().find(key_string.as_bytes()).await.unwrap().unwrap();
        let bundle2 = KeyPackageBundle::from_key_store_value(&entity2.key).unwrap();

        let (b1_kp, (b1_sk, b1_ls)) = keypackage_bundle.into_parts();
        let (b2_kp, (b2_sk, b2_ls)) = bundle2.into_parts();
        assert_eq!(b1_kp, b2_kp);
        assert_eq!(b1_sk, b2_sk);
        assert_eq!(b1_ls, b2_ls);

        backend
            .key_store()
            .remove::<MlsKeypackage, _>(key_string.as_bytes())
            .await
            .unwrap();

        teardown(backend.unwrap_keystore()).await;
    }
}
