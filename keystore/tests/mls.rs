pub use rstest::*;
pub use rstest_reuse::{self, *};

mod common;

mod tests {
    use crate::common::*;
    use openmls::prelude::TlsDeserializeTrait;
    use openmls::{credentials::Credential, prelude::Ciphersuite};
    use openmls_traits::random::OpenMlsRand;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    use mls_crypto_provider::MlsCryptoProvider;

    use core_crypto_keystore::MissingKeyErrorKind;
    use core_crypto_keystore::entities::{
        EntityBase, MlsCredential, MlsHpkePrivateKey, MlsKeyPackage, MlsPskBundle, MlsSignatureKeyPair,
        PersistedMlsGroup, PersistedMlsPendingGroup,
    };
    use openmls::prelude::TlsSerializeTrait as _;
    use openmls_traits::OpenMlsCryptoProvider as _;

    #[test]
    #[wasm_bindgen_test]
    fn mls_entities_have_correct_error_kinds() {
        assert_eq!(
            MlsCredential::to_missing_key_err_kind(),
            MissingKeyErrorKind::MlsCredential
        );

        assert_eq!(
            MlsKeyPackage::to_missing_key_err_kind(),
            MissingKeyErrorKind::MlsKeyPackage
        );

        assert_eq!(
            PersistedMlsGroup::to_missing_key_err_kind(),
            MissingKeyErrorKind::PersistedMlsGroup
        );

        assert_eq!(
            PersistedMlsPendingGroup::to_missing_key_err_kind(),
            MissingKeyErrorKind::MlsPendingGroup
        );

        assert_eq!(
            MlsHpkePrivateKey::to_missing_key_err_kind(),
            MissingKeyErrorKind::MlsHpkePrivateKey
        );

        assert_eq!(
            MlsSignatureKeyPair::to_missing_key_err_kind(),
            MissingKeyErrorKind::MlsSignatureKeyPair
        );

        assert_eq!(
            MlsPskBundle::to_missing_key_err_kind(),
            MissingKeyErrorKind::MlsPskBundle
        );
    }

    #[apply(all_storage_types)]
    pub async fn can_add_read_delete_credential_bundle_openmls_traits(context: KeystoreTestContext) {
        use core_crypto_keystore::connection::FetchFromDatabase;
        use itertools::Itertools as _;
        use openmls_basic_credential::SignatureKeyPair;

        let store = context.store();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let backend = MlsCryptoProvider::new(store.clone());
        let identity_id: [u8; 16] = rand::random();
        let identity_id = uuid::Uuid::from_bytes(identity_id);

        let credential = Credential::new_basic(identity_id.as_bytes().as_slice().into());

        let credential_id: Vec<u8> = credential.identity().into();

        let store_credential = MlsCredential {
            id: credential_id.clone(),
            credential: credential.tls_serialize_detached().unwrap(),
            created_at: 0,
        };

        backend.key_store().save(store_credential).await.unwrap();

        let keypair = SignatureKeyPair::new(
            ciphersuite.signature_algorithm(),
            &mut *backend.rand().borrow_rand().unwrap(),
        )
        .unwrap();

        let store_keypair = MlsSignatureKeyPair::new(
            keypair.signature_scheme(),
            keypair.to_public_vec(),
            keypair.tls_serialize_detached().unwrap(),
            credential_id.clone(),
        );

        backend.key_store().save(store_keypair).await.unwrap();

        let (credential_from_store,) = backend
            .key_store()
            .find_all::<MlsCredential>(Default::default())
            .await
            .unwrap()
            .into_iter()
            .filter(|cred| cred.id == credential_id)
            .collect_tuple()
            .expect("credentials should be exactly one");
        let keypair2: MlsSignatureKeyPair = backend.key_store().find(keypair.public()).await.unwrap().unwrap();

        assert_eq!(keypair2.credential_id, credential_from_store.id);

        let keypair2 = SignatureKeyPair::tls_deserialize(&mut keypair2.keypair.as_slice()).unwrap();

        let (b1_kp, b1_sk) = (keypair.to_public_vec(), keypair.private().to_vec());
        let (b2_kp, b2_sk) = (keypair2.to_public_vec(), keypair.private().to_vec());
        assert_eq!(b1_kp, b2_kp);
        assert_eq!(b1_sk.as_slice(), b2_sk.as_slice());

        backend
            .key_store()
            .cred_delete_by_credential(credential_from_store.credential.clone())
            .await
            .unwrap();
        backend
            .key_store()
            .remove::<MlsSignatureKeyPair, _>(keypair.public())
            .await
            .unwrap();
    }

    // FIXME: rewrite the tests using the new OpenMLS apis. Tracking issue: WPB-9657
    // #[apply(all_storage_types)]
    // #[wasm_bindgen_test]
    // pub async fn can_add_read_delete_keypackage_bundle_openmls_traits(store: Connection) {
    //     use openmls::{
    //         credentials::CredentialBundle,
    //         extensions::{Extension, ExternalKeyIdExtension},
    //         key_packages::KeyPackageBundle,
    //     };

    //     let store = store.await;
    //     let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    //     let backend = MlsCryptoProvider::new_with_store(store, None);
    //     let key_id: [u8; 16] = rand::random();
    //     let key_id = uuid::Uuid::from_bytes(key_id);

    //     let credentials =
    //         CredentialBundle::new_basic(vec![1, 2, 3], ciphersuite.signature_algorithm(), &backend).unwrap();

    //     let keypackage_bundle = KeyPackageBundle::new(
    //         &[ciphersuite],
    //         &credentials,
    //         &backend,
    //         vec![Extension::ExternalKeyId(ExternalKeyIdExtension::new(key_id.as_bytes()))],
    //     )
    //     .unwrap();
    //     let key_string = key_id.as_hyphenated().to_string();

    //     keypackage_bundle.key_package().verify(&backend).unwrap();

    //     use openmls_traits::key_store::OpenMlsKeyStore as _;
    //     backend
    //         .key_store()
    //         .store(key_string.as_bytes(), &keypackage_bundle)
    //         .await
    //         .unwrap();
    //     let bundle2: KeyPackageBundle = backend.key_store().read(key_string.as_bytes()).await.unwrap();
    //     let (b1_kp, (b1_sk, b1_ls)) = keypackage_bundle.into_parts();
    //     let (b2_kp, (b2_sk, b2_ls)) = bundle2.into_parts();
    //     assert_eq!(b1_kp, b2_kp);
    //     assert_eq!(b1_sk, b2_sk);
    //     assert_eq!(b1_ls, b2_ls);

    //     backend
    //         .key_store()
    //         .delete::<KeyPackageBundle>(key_string.as_bytes())
    //         .await
    //         .unwrap();

    //     teardown(backend.unwrap_keystore()).await;
    // }

    // #[apply(all_storage_types)]
    // #[wasm_bindgen_test]
    // pub async fn can_add_read_delete_keypackage_bundle_keystore(store: Connection) {
    //     use openmls::{
    //         credentials::CredentialBundle,
    //         extensions::{Extension, ExternalKeyIdExtension},
    //         key_packages::KeyPackageBundle,
    //     };

    //     let store = store.await;

    //     let backend = MlsCryptoProvider::new_with_store(store, None);
    //     let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    //     let key_id: [u8; 16] = rand::random();
    //     let key_id = uuid::Uuid::from_bytes(key_id);

    //     let credentials =
    //         CredentialBundle::new_basic(vec![1, 2, 3], ciphersuite.signature_algorithm(), &backend).unwrap();

    //     let keypackage_bundle = KeyPackageBundle::new(
    //         &[ciphersuite],
    //         &credentials,
    //         &backend,
    //         vec![Extension::ExternalKeyId(ExternalKeyIdExtension::new(key_id.as_bytes()))],
    //     )
    //     .unwrap();

    //     keypackage_bundle.key_package().verify(&backend).unwrap();

    //     let key_string = key_id.as_hyphenated().to_string();

    //     let entity = MlsKeyPackage {
    //         id: key_string.clone(),
    //         key: keypackage_bundle.to_key_store_value().unwrap(),
    //     };

    //     backend.key_store().save(entity).await.unwrap();

    //     let entity2: MlsKeyPackage = backend.key_store().find(key_string.as_bytes()).await.unwrap().unwrap();
    //     let bundle2 = KeyPackageBundle::from_key_store_value(&entity2.key).unwrap();

    //     let (b1_kp, (b1_sk, b1_ls)) = keypackage_bundle.into_parts();
    //     let (b2_kp, (b2_sk, b2_ls)) = bundle2.into_parts();
    //     assert_eq!(b1_kp, b2_kp);
    //     assert_eq!(b1_sk, b2_sk);
    //     assert_eq!(b1_ls, b2_ls);

    //     backend
    //         .key_store()
    //         .remove::<MlsKeyPackage, _>(key_string.as_bytes())
    //         .await
    //         .unwrap();

    //     teardown(backend.unwrap_keystore()).await;
    // }
}
