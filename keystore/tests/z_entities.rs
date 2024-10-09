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

#[cfg(target_family = "wasm")]
use keystore_v_1_0_0::entities::{
    E2eiAcmeCA as E2eiAcmeCAV1_0_0, E2eiCrl as E2eiCrlV1_0_0, E2eiEnrollment as E2eiEnrollmentV1_0_0,
    E2eiIntermediateCert as E2eiIntermediateCertV1_0_0, E2eiRefreshToken as E2eiRefreshTokenV1_0_0,
    Entity as EntityV1_0_0, MlsCredential as MlsCredentialV1_0_0, MlsEncryptionKeyPair as MlsEncryptionKeyPairV1_0_0,
    MlsEpochEncryptionKeyPair as MlsEpochEncryptionKeyPairV1_0_0, MlsHpkePrivateKey as MlsHpkePrivateKeyV1_0_0,
    MlsKeyPackage as MlsKeyPackageV1_0_0, MlsPendingMessage as MlsPendingMessageV1_0_0,
    MlsPskBundle as MlsPskBundleV1_0_0, MlsSignatureKeyPair as MlsSignatureKeyPairV1_0_0,
    PersistedMlsGroup as PersistedMlsGroupV1_0_0, PersistedMlsPendingGroup as PersistedMlsPendingGroupV1_0_0,
    ProteusIdentity as ProteusIdentityV1_0_0, ProteusPrekey as ProteusPrekeyV1_0_0,
    ProteusSession as ProteusSessionV1_0_0, UniqueEntity as UniqueEntityV1_0_0,
};
pub use rstest::*;
pub use rstest_reuse::{self, *};

mod common;

const ENTITY_COUNT: usize = 10;

macro_rules! pat_to_bool {
    () => {
        false
    };
    ($value:literal) => {
        $value
    };
}

macro_rules! test_for_entity {
    ($test_name:ident, $entity:ident $(ignore_entity_count:$ignore_entity_count:literal)? $(ignore_update:$ignore_update:literal)? $(ignore_find_many:$ignore_find_many:literal)?) => {
        #[apply(all_storage_types)]
        #[wasm_bindgen_test]
        async fn $test_name(context: KeystoreTestContext) {
            let store = context.store();
            let _ = pretty_env_logger::try_init();
            let mut entity = crate::tests_impl::can_save_entity::<$entity>(&store).await;

            crate::tests_impl::can_find_entity::<$entity>(&store, &entity).await;
            let ignore_update = pat_to_bool!($($ignore_update)?);

            // TODO: entities which do not support update tend not to have a primary key constraint. Tracking issue: WPB-9649
            // This can cause complications with the "default" remove implementation which does not support deleting many entities.
            // We should have an automated way to test this here

            if !ignore_update {
                crate::tests_impl::can_update_entity::<$entity>(&store, &mut entity).await;
            }
            crate::tests_impl::can_remove_entity::<$entity>(&store, entity).await;

            let ignore_count = pat_to_bool!($($ignore_entity_count)?);
            let ignore_find_many = pat_to_bool!($($ignore_find_many)?);
            crate::tests_impl::can_list_entities_with_find_many::<$entity>(&store, ignore_count, ignore_find_many).await;
            crate::tests_impl::can_list_entities_with_find_all::<$entity>(&store, ignore_count).await;
        }
    };
}

#[cfg(target_family = "wasm")]
macro_rules! work_for_unique_or_regular_entities {
    (unique: $unique_entity_work:block, regular: $regular_entity_work:block, true) => {
        $unique_entity_work
    };

    (unique: $unique_entity_work:block, regular: $regular_entity_work:block, ) => {
        $regular_entity_work
    };
}

#[cfg(target_family = "wasm")]
macro_rules! test_migration_to_db_v1_for_entity {
    ($test_name:ident, $entity:ty, $old_entity:ty $(, unique_entity: $unique_entity:tt)?) => {
        #[wasm_bindgen_test]
        async fn $test_name() {
            let _ = pretty_env_logger::try_init();
            let name = store_name();

            let old_storage = keystore_v_1_0_0::Connection::open_with_key(&name, TEST_ENCRYPTION_KEY)
                .await
                .unwrap();
            let old_record = <$old_entity>::random();

            work_for_unique_or_regular_entities!(
                unique: {
                    let mut connection = old_storage.borrow_conn().await.unwrap();
                    old_record.replace(&mut connection).await.unwrap();
                },
                regular: {
                    old_storage.save(old_record.clone()).await.unwrap();
                },
                $(
                    $unique_entity
                )?
            );

            old_storage.close().await.unwrap();

            let new_storage = core_crypto_keystore::Connection::open_with_key(&name, TEST_ENCRYPTION_KEY)
                .await
                .unwrap();
            let mut new_connection = new_storage.borrow_conn().await.unwrap();
            let result;

            work_for_unique_or_regular_entities!(
                unique: {
                    result = <$entity>::find_unique(&mut new_connection).await;
                    assert!(result.is_ok());
                },
                regular: {
                    let string_id = StringEntityId::from(old_record.id_raw());
                    result = <$entity>::find_one(&mut new_connection, &string_id).await;
                    assert!(result.unwrap().is_some());
                },
                $(
                    $unique_entity
                )?
            );

            drop(new_connection);
            new_storage.wipe().await.unwrap();
        }
    };
}

#[cfg(test)]
mod tests_impl {
    use super::common::*;
    use crate::{utils::EntityRandomUpdateExt, ENTITY_COUNT};
    use core_crypto_keystore::{
        connection::{FetchFromDatabase, KeystoreDatabaseConnection},
        entities::{Entity, EntityFindParams},
    };
    use core_crypto_keystore::entities::EntityTransactionExt;

    pub(crate) async fn can_save_entity<
        R: EntityRandomUpdateExt + Entity<ConnectionType = KeystoreDatabaseConnection> + EntityTransactionExt + Sync,
    >(
        store: &CryptoKeystore,
    ) -> R {
        let entity = R::random();
        store.save(entity.clone()).await.unwrap();
        entity
    }

    pub(crate) async fn can_find_entity<
        R: EntityRandomUpdateExt + Entity<ConnectionType = KeystoreDatabaseConnection> + 'static + Sync,
    >(
        store: &CryptoKeystore,
        entity: &R,
    ) {
        let mut entity2: R = store.find(entity.id_raw()).await.unwrap().unwrap();
        entity2.equalize();
        assert_eq!(*entity, entity2);
    }

    pub(crate) async fn can_update_entity<
        R: EntityRandomUpdateExt + Entity<ConnectionType = KeystoreDatabaseConnection> + EntityTransactionExt + Sync,
    >(
        store: &CryptoKeystore,
        entity: &mut R,
    ) {
        entity.random_update();
        store.save(entity.clone()).await.unwrap();
        let entity2: R = store.find(entity.id_raw()).await.unwrap().unwrap();
        assert_eq!(*entity, entity2);
    }

    pub(crate) async fn can_remove_entity<
        R: EntityRandomUpdateExt + Entity<ConnectionType = KeystoreDatabaseConnection> + EntityTransactionExt + Sync,
    >(
        store: &CryptoKeystore,
        entity: R,
    ) {
        store.remove::<R, _>(entity.id_raw()).await.unwrap();
        let entity2: Option<R> = store.find(entity.id_raw()).await.unwrap();
        assert!(entity2.is_none());
    }

    pub(crate) async fn can_list_entities_with_find_many<
        R: EntityRandomUpdateExt + Entity<ConnectionType = KeystoreDatabaseConnection> + EntityTransactionExt + Sync,
    >(
        store: &CryptoKeystore,
        ignore_entity_count: bool,
        ignore_find_many: bool,
    ) {
        let mut ids: Vec<Vec<u8>> = vec![];
        for _ in 0..ENTITY_COUNT {
            let entity = R::random();
            ids.push(entity.id_raw().to_vec());
            store.save(entity).await.unwrap();
        }

        if !ignore_find_many {
            let entities = store.find_many::<R>(&ids).await.unwrap();
            if !ignore_entity_count {
                assert_eq!(entities.len(), ENTITY_COUNT);
            }
        }
    }

    pub(crate) async fn can_list_entities_with_find_all<
        R: EntityRandomUpdateExt + Entity<ConnectionType = KeystoreDatabaseConnection> + Sync,
    >(
        store: &CryptoKeystore,
        ignore_entity_count: bool,
    ) {
        let entities = store.find_all::<R>(EntityFindParams::default()).await.unwrap();
        if !ignore_entity_count {
            assert_eq!(entities.len(), ENTITY_COUNT);
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_family = "wasm")]
    // Use V1_0_0 entities
    use super::*;
    use crate::common::*;
    use crate::utils::EntityRandomExt;
    use crate::utils::EntityRandomUpdateExt;
    use core_crypto_keystore::{Connection, CryptoKeystoreError};
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    use core_crypto_keystore::entities::*;

    cfg_if::cfg_if! {
        if #[cfg(feature = "mls-keystore")] {
            test_for_entity!(test_persisted_mls_group, PersistedMlsGroup);
            test_for_entity!(test_persisted_mls_pending_group, PersistedMlsPendingGroup);
            test_for_entity!(test_mls_pending_message, MlsPendingMessage ignore_update:true ignore_find_many:true);
            test_for_entity!(test_mls_credential, MlsCredential ignore_update:true);
            test_for_entity!(test_mls_keypackage, MlsKeyPackage);
            test_for_entity!(test_mls_signature_keypair, MlsSignatureKeyPair ignore_update:true);
            test_for_entity!(test_mls_psk_bundle, MlsPskBundle);
            test_for_entity!(test_mls_encryption_keypair, MlsEncryptionKeyPair);
            test_for_entity!(test_mls_epoch_encryption_keypair, MlsEpochEncryptionKeyPair);
            test_for_entity!(test_mls_hpke_private_key, MlsHpkePrivateKey);
            test_for_entity!(test_e2ei_intermediate_cert, E2eiIntermediateCert);
            test_for_entity!(test_e2ei_crl, E2eiCrl);
            test_for_entity!(test_e2ei_enrollment, E2eiEnrollment ignore_update:true);

            cfg_if::cfg_if! {
                if #[cfg(target_family = "wasm")] {
                    test_migration_to_db_v1_for_entity!(test_mls_group_migration, PersistedMlsGroup, PersistedMlsGroupV1_0_0);
                    test_migration_to_db_v1_for_entity!(test_mls_pending_group_migration, PersistedMlsPendingGroup, PersistedMlsPendingGroupV1_0_0);
                    test_migration_to_db_v1_for_entity!(test_mls_pending_message_migration, MlsPendingMessage, MlsPendingMessageV1_0_0);
                    test_migration_to_db_v1_for_entity!(test_mls_credential_migration, MlsCredential, MlsCredentialV1_0_0);
                    test_migration_to_db_v1_for_entity!(test_mls_keypackage_migration, MlsKeyPackage, MlsKeyPackageV1_0_0);
                    test_migration_to_db_v1_for_entity!(test_mls_signature_keypair_migration, MlsSignatureKeyPair, MlsSignatureKeyPairV1_0_0);
                    test_migration_to_db_v1_for_entity!(test_mls_psk_bundle_migration, MlsPskBundle, MlsPskBundleV1_0_0);
                    test_migration_to_db_v1_for_entity!(test_mls_encryption_keypair_migration, MlsEncryptionKeyPair, MlsEncryptionKeyPairV1_0_0);
                    test_migration_to_db_v1_for_entity!(test_mls_epoch_encryption_keypair_migration, MlsEpochEncryptionKeyPair, MlsEpochEncryptionKeyPairV1_0_0);
                    test_migration_to_db_v1_for_entity!(test_mls_hpke_private_key_migration, MlsHpkePrivateKey, MlsHpkePrivateKeyV1_0_0);
                    test_migration_to_db_v1_for_entity!(test_e2ei_intermediate_cert_migration, E2eiIntermediateCert, E2eiIntermediateCertV1_0_0);
                    test_migration_to_db_v1_for_entity!(test_e2ei_crl_migration, E2eiCrl, E2eiCrlV1_0_0);
                    test_migration_to_db_v1_for_entity!(test_e2ei_enrollment_migration, E2eiEnrollment, E2eiEnrollmentV1_0_0);
                    test_migration_to_db_v1_for_entity!(test_e2ei_ca_migration, E2eiAcmeCA, E2eiAcmeCAV1_0_0, unique_entity:true);
                    test_migration_to_db_v1_for_entity!(test_e2ei_token_migration, E2eiRefreshToken, E2eiRefreshTokenV1_0_0, unique_entity:true);
                }
            }
        }
    }
    cfg_if::cfg_if! {
        if #[cfg(feature = "proteus-keystore")] {
            test_for_entity!(test_proteus_identity, ProteusIdentity ignore_entity_count:true ignore_update:true);
            test_for_entity!(test_proteus_prekey, ProteusPrekey);
            test_for_entity!(test_proteus_session, ProteusSession);
            cfg_if::cfg_if! {
                if #[cfg(target_family = "wasm")] {
                    test_migration_to_db_v1_for_entity!(test_proteus_session_migration, ProteusSession, ProteusSessionV1_0_0);
                    test_migration_to_db_v1_for_entity!(test_proteus_prekey_migration, ProteusPrekey, ProteusPrekeyV1_0_0);
                    test_migration_to_db_v1_for_entity!(test_proteus_identity_migration, ProteusIdentity, ProteusIdentityV1_0_0);
                }
            }
        }
    }
    #[apply(all_storage_types)]
    #[wasm_bindgen_test]
    pub async fn update_e2ei_enrollment_emits_error(context: KeystoreTestContext) {
        let store = context.store();

        let mut entity = E2eiEnrollment::random();
        store.save(entity.clone()).await.unwrap();
        entity.random_update();
        let error = store.save(entity).await.unwrap_err();
        assert!(matches!(error, CryptoKeystoreError::AlreadyExists));
    }
}

#[cfg(test)]
pub mod utils {
    #[cfg(target_family = "wasm")]
    // Use V1_0_0 entities
    use super::*;
    use core_crypto_keystore::entities::{
        E2eiEnrollment, MlsCredential, MlsEncryptionKeyPair, MlsEpochEncryptionKeyPair, MlsHpkePrivateKey,
        MlsKeyPackage, MlsPendingMessage, MlsPskBundle, MlsSignatureKeyPair, PersistedMlsGroup,
        PersistedMlsPendingGroup, ProteusSession,
    };
    use rand::Rng as _;

    const MAX_BLOB_SIZE: std::ops::Range<usize> = 1024..8192;

    pub trait EntityRandomExt {
        fn random() -> Self;
    }
    pub trait EntityRandomUpdateExt: EntityRandomExt {
        fn random_update(&mut self);
        /// Removes auto-generated fields from the entity
        fn equalize(&mut self) {}
    }

    macro_rules! impl_entity_random_ext {
                (
                    $struct_name:ty,
                    $(id_field=$id_field:ident, )?
                    blob_fields=[
                        $($blob_field:ident
                        $( id_like:$id_like:literal)?, )*
                    ]
                    $(, additional_fields=[
                        $((
                            $additional_field_ident:ident: $additional_field_value:expr
                        ),)+
                    ])?
                ) => {
                    impl EntityRandomExt for $struct_name {
                        fn random() -> Self {
                            use rand::Rng as _;
                            let mut rng = rand::thread_rng();

                            $(
                                let uuid = uuid::Uuid::new_v4();
                                let $id_field: [u8; 16] = uuid.into_bytes();
                            )?

                            $(
                                let mut $blob_field = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                                rng.fill(&mut $blob_field[..]);
                            )*

                            Self {
                                $($id_field: $id_field.into(),)?
                                $($blob_field,)*
                                $($($additional_field_ident: $additional_field_value,)+)?
                            }
                        }
                    }
                };
            }

    macro_rules! impl_entity_random_update_ext {
                (
                    $struct_name:ty,
                    $(id_field=$id_field:ident, )?
                    blob_fields=[
                        $($blob_field:ident
                        $( id_like:$id_like:literal)?, )*
                    ]
                    $(, additional_fields=[
                        $((
                            $additional_field_ident:ident: $additional_field_value:expr
                            $(; auto-generated:$equalize:literal)?
                        ),)+
                    ])?
                ) => {

                    impl_entity_random_ext!(
                        $struct_name,
                        $(id_field=$id_field,)?
                        blob_fields=[
                            $($blob_field $(id_like:$id_like)?, )*
                        ]
                        $(, additional_fields=[
                            $(($additional_field_ident: $additional_field_value),)+
                        ])?
                    );

                    impl EntityRandomUpdateExt for $struct_name {
                        fn random_update(&mut self) {
                            let mut rng = rand::thread_rng();
                            $(
                                // Don't include id-like fields in update
                                let include_in_update = !pat_to_bool!($($id_like)?);
                                if include_in_update {
                                    self.$blob_field = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                                    rng.fill(&mut self.$blob_field[..]);
                                }
                            )*
                        }

                        $(
                            fn equalize(&mut self) {
                                $(
                                    let field_should_be_equalized = pat_to_bool!($($equalize)?);
                                    if field_should_be_equalized {
                                        self.$additional_field_ident = $additional_field_value;
                                    }
                                )+
                            }
                        )?
                    }
                };
            }

    cfg_if::cfg_if! {
        if #[cfg(feature = "mls-keystore")] {
            impl_entity_random_update_ext!(MlsKeyPackage, blob_fields=[keypackage,], additional_fields=[(keypackage_ref: uuid::Uuid::new_v4().hyphenated().to_string().into()),]);
            impl_entity_random_update_ext!(MlsCredential, blob_fields=[credential,], additional_fields=[(id: uuid::Uuid::new_v4().hyphenated().to_string().into()),(created_at: 0; auto-generated:true),]);
            impl_entity_random_update_ext!(MlsSignatureKeyPair, blob_fields=[pk,keypair,credential_id,], additional_fields=[(signature_scheme: rand::random()),]);
            impl_entity_random_update_ext!(MlsHpkePrivateKey, blob_fields=[pk id_like:true,sk,]);
            impl_entity_random_update_ext!(MlsEncryptionKeyPair, blob_fields=[pk id_like:true,sk,]);
            impl_entity_random_update_ext!(MlsPskBundle, blob_fields=[psk,psk_id id_like:true,]);
            impl_entity_random_update_ext!(PersistedMlsGroup, id_field=id, blob_fields=[state,], additional_fields=[(parent_id: None),]);
            impl_entity_random_update_ext!(PersistedMlsPendingGroup, id_field=id, blob_fields=[state,custom_configuration,], additional_fields=[(parent_id: None),]);
            impl_entity_random_update_ext!(MlsPendingMessage, id_field=foreign_id, blob_fields=[message,]);
            impl_entity_random_update_ext!(E2eiEnrollment, id_field=id, blob_fields=[content,]);
            impl_entity_random_update_ext!(MlsEpochEncryptionKeyPair, id_field=id, blob_fields=[keypairs,]);
            cfg_if::cfg_if! {
                if #[cfg(target_family = "wasm")] {
                    impl_entity_random_ext!(MlsKeyPackageV1_0_0, blob_fields=[keypackage,], additional_fields=[(keypackage_ref: uuid::Uuid::new_v4().hyphenated().to_string().into()),]);
                    impl_entity_random_ext!(MlsCredentialV1_0_0, id_field=id, blob_fields=[credential,], additional_fields=[(created_at: 0),]);
                    impl_entity_random_ext!(MlsSignatureKeyPairV1_0_0, blob_fields=[pk,keypair,credential_id,], additional_fields=[(signature_scheme: rand::random()),]);
                    impl_entity_random_ext!(MlsHpkePrivateKeyV1_0_0, blob_fields=[pk,sk,]);
                    impl_entity_random_ext!(MlsEncryptionKeyPairV1_0_0, blob_fields=[pk,sk,]);
                    impl_entity_random_ext!(MlsPskBundleV1_0_0, blob_fields=[psk,psk_id,]);
                    impl_entity_random_ext!(PersistedMlsGroupV1_0_0, id_field=id, blob_fields=[state,], additional_fields=[(parent_id: None),]);
                    impl_entity_random_ext!(PersistedMlsPendingGroupV1_0_0, id_field=id, blob_fields=[state,custom_configuration,], additional_fields=[(parent_id: None),]);
                    impl_entity_random_ext!(MlsPendingMessageV1_0_0, id_field=id, blob_fields=[message,]);
                    impl_entity_random_ext!(E2eiCrlV1_0_0, blob_fields=[content,], additional_fields=[(distribution_point: "some-distribution-point".into()),]);
                    impl_entity_random_ext!(E2eiIntermediateCertV1_0_0, blob_fields=[content,], additional_fields=[(ski_aki_pair: "some-key-pair".into()),]);
                    impl_entity_random_ext!(E2eiAcmeCAV1_0_0, blob_fields=[content,]);
                    impl_entity_random_ext!(E2eiRefreshTokenV1_0_0, blob_fields=[content,]);
                    impl_entity_random_ext!(E2eiEnrollmentV1_0_0, id_field=id, blob_fields=[content,]);
                    impl_entity_random_ext!(MlsEpochEncryptionKeyPairV1_0_0, id_field=id, blob_fields=[keypairs,]);
                }
            }


            impl EntityRandomExt for core_crypto_keystore::entities::E2eiIntermediateCert {
                fn random() -> Self {
                    let mut rng = rand::thread_rng();

                    let ski_aki_pair = rng.clone()
                        .sample_iter(rand::distributions::Alphanumeric)
                        .take(rng.gen_range(MAX_BLOB_SIZE))
                        .map(char::from)
                        .collect::<String>();

                    let mut content = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut content[..]);

                    Self {
                        ski_aki_pair,
                        content,
                    }
                }
            }


            impl EntityRandomUpdateExt for core_crypto_keystore::entities::E2eiIntermediateCert {
                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();
                    self.content = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut self.content[..]);
                }
            }

            impl EntityRandomExt for core_crypto_keystore::entities::E2eiCrl {
                fn random() -> Self {
                    let mut rng = rand::thread_rng();

                    let host = rng.clone()
                        .sample_iter(rand::distributions::Alphanumeric)
                        .take(rng.gen_range(10..20))
                        .map(char::from)
                        .collect::<String>();
                    let distribution_point = format!("https://{host}.com");

                    let mut content = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut content[..]);

                    Self {
                        distribution_point,
                        content,
                    }
                }
            }

            impl EntityRandomUpdateExt for core_crypto_keystore::entities::E2eiCrl {
                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();
                    self.content = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut self.content[..]);
                }
            }
        }
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "proteus-keystore")] {

            impl_entity_random_update_ext!(ProteusSession, blob_fields=[session,], additional_fields=[(id: uuid::Uuid::new_v4().hyphenated().to_string()),]);
            cfg_if::cfg_if! {
                if #[cfg(target_family = "wasm")] {
                    impl_entity_random_ext!(ProteusSessionV1_0_0, blob_fields=[session,], additional_fields=[(id: uuid::Uuid::new_v4().hyphenated().to_string()),]);
                    impl_entity_random_ext!(ProteusIdentityV1_0_0, blob_fields=[pk,sk,]);
                }
            }

            impl EntityRandomExt for core_crypto_keystore::entities::ProteusPrekey {
                fn random() -> Self {
                    use rand::Rng as _;
                    let mut rng = rand::thread_rng();

                    let id: u16 = rng.gen();
                    let mut prekey = vec![0u8; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut prekey[..]);

                    Self::from_raw(id, prekey)
                }
            }

            #[cfg(target_family = "wasm")]
            impl EntityRandomExt for ProteusPrekeyV1_0_0 {
                fn random() -> Self {
                    use rand::Rng as _;
                    let mut rng = rand::thread_rng();

                    let id: u16 = rng.gen();
                    let mut prekey = vec![0u8; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut prekey[..]);

                    Self::from_raw(id, prekey)
                }
            }

            impl EntityRandomUpdateExt for core_crypto_keystore::entities::ProteusPrekey {
                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();
                    // self.set_id(rng.gen());
                    self.prekey = vec![0u8; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut self.prekey[..]);
                }
            }

             impl EntityRandomExt for core_crypto_keystore::entities::ProteusIdentity {
                fn random() -> Self {
                    use rand::Rng as _;
                    let mut rng = rand::thread_rng();

                    let mut sk = vec![0u8; Self::SK_KEY_SIZE];
                    rng.fill(&mut sk[..]);
                    let mut pk = vec![0u8; Self::PK_KEY_SIZE];
                    rng.fill(&mut pk[..]);

                    Self {
                        sk,
                        pk,
                    }
                }
            }

            impl EntityRandomUpdateExt for core_crypto_keystore::entities::ProteusIdentity {
                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();
                    self.sk = vec![0u8; Self::SK_KEY_SIZE];
                    rng.fill(&mut self.sk[..]);

                    self.pk = vec![0u8; Self::PK_KEY_SIZE];
                    rng.fill(&mut self.pk[..]);
                }
            }
        }
    }
}
