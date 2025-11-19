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
        async fn $test_name(context: KeystoreTestContext) {
            let store = context.store();
            let _ = env_logger::try_init();
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

#[cfg(test)]
mod tests_impl {
    use core_crypto_keystore::{
        connection::{FetchFromDatabase, KeystoreDatabaseConnection},
        entities::{Entity, EntityFindParams, EntityTransactionExt, MlsPendingMessage, StoredCredential},
    };

    use super::common::*;
    use crate::{ENTITY_COUNT, utils::EntityRandomUpdateExt};

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
        if let Some(pending_message) = entity.downcast::<MlsPendingMessage>() {
            let pending_message_from_store = store
                .find_pending_messages_by_conversation_id(&pending_message.foreign_id)
                .await
                .unwrap()
                .pop()
                .unwrap();
            assert_eq!(*pending_message, pending_message_from_store);
        } else if let Some(credential) = entity.downcast::<StoredCredential>() {
            let mut credential_from_store = store
                .find::<StoredCredential>(&entity.merge_key())
                .await
                .unwrap()
                .unwrap();
            credential_from_store.equalize();
            assert_eq!(*credential, credential_from_store);
        } else {
            let mut entity_from_store = store.find::<R>(entity.id_raw()).await.unwrap().unwrap();
            entity_from_store.equalize();
            assert_eq!(*entity, entity_from_store);
        };
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
    use core_crypto_keystore::CryptoKeystoreError;
    use wasm_bindgen_test::*;

    use crate::{
        common::*,
        utils::{EntityRandomExt, EntityRandomUpdateExt},
    };

    wasm_bindgen_test_configure!(run_in_browser);

    use core_crypto_keystore::entities::*;

    test_for_entity!(test_persisted_mls_group, PersistedMlsGroup);
    test_for_entity!(test_persisted_mls_pending_group, PersistedMlsPendingGroup);
    test_for_entity!(test_mls_pending_message, MlsPendingMessage ignore_update:true ignore_find_many:true);
    test_for_entity!(test_mls_credential, StoredCredential ignore_update:true);
    test_for_entity!(test_mls_keypackage, StoredKeypackage);
    test_for_entity!(test_mls_psk_bundle, StoredPskBundle);
    test_for_entity!(test_mls_encryption_keypair, StoredEncryptionKeyPair);
    test_for_entity!(test_mls_epoch_encryption_keypair, StoredEpochEncryptionKeypair);
    test_for_entity!(test_mls_hpke_private_key, StoredHpkePrivateKey);
    test_for_entity!(test_e2ei_intermediate_cert, E2eiIntermediateCert);
    test_for_entity!(test_e2ei_crl, E2eiCrl);
    test_for_entity!(test_e2ei_enrollment, StoredE2eiEnrollment ignore_update:true);

    cfg_if::cfg_if! {
        if #[cfg(feature = "proteus-keystore")] {
            test_for_entity!(test_proteus_identity, ProteusIdentity ignore_entity_count:true ignore_update:true);
            test_for_entity!(test_proteus_prekey, ProteusPrekey);
            test_for_entity!(test_proteus_session, ProteusSession);
        }
    }

    // This test cannot pass on WASM: if you grep through the codebase, you'll note that
    // `CoreCryptoKeystore::AlreadyExists` is only produced in one place: in the entity derive macro,
    // in the non-wasm branch of the derive implementation.
    #[cfg_attr(target_family = "wasm", should_panic)]
    #[apply(all_storage_types)]
    pub async fn update_e2ei_enrollment_emits_error(context: KeystoreTestContext) {
        let store = context.store();

        let mut entity = StoredE2eiEnrollment::random();
        store.save(entity.clone()).await.unwrap();
        store.commit_transaction().await.unwrap();

        // Start a new transaction so that the database constraints will trigger on committing the
        // transaction
        store.new_transaction().await.unwrap();
        entity.random_update();
        store.save(entity).await.unwrap();
        let error = store.commit_transaction().await.unwrap_err();

        assert!(matches!(
            error,
            CryptoKeystoreError::AlreadyExists(StoredE2eiEnrollment::COLLECTION_NAME)
        ));

        // It's required by cleanup to have a running transaction before finishing the test
        store.rollback_transaction().await.unwrap();
        store.new_transaction().await.unwrap();
    }
}

#[cfg(test)]
pub mod utils {
    use core_crypto_keystore::entities::{
        MlsPendingMessage, PersistedMlsGroup, PersistedMlsPendingGroup, ProteusSession, StoredCredential,
        StoredE2eiEnrollment, StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredHpkePrivateKey,
        StoredKeypackage, StoredPskBundle,
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
                            $additional_field_ident:ident: $additional_field_value:expr_2021
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
                            $additional_field_ident:ident: $additional_field_value:expr_2021
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

    impl_entity_random_update_ext!(StoredKeypackage, blob_fields=[keypackage,], additional_fields=[(keypackage_ref: uuid::Uuid::new_v4().hyphenated().to_string().into()),]);
    impl_entity_random_update_ext!(StoredCredential, blob_fields=[credential,public_key,secret_key,], additional_fields=[(id: uuid::Uuid::new_v4().hyphenated().to_string().into()),(created_at: 0; auto-generated:true),(ciphersuite: rand::random()),]);
    impl_entity_random_update_ext!(StoredHpkePrivateKey, blob_fields=[pk id_like:true,sk,]);
    impl_entity_random_update_ext!(StoredEncryptionKeyPair, blob_fields=[pk id_like:true,sk,]);
    impl_entity_random_update_ext!(StoredPskBundle, blob_fields=[psk,psk_id id_like:true,]);
    impl_entity_random_update_ext!(PersistedMlsGroup, id_field=id, blob_fields=[state,], additional_fields=[(parent_id: None),]);
    impl_entity_random_update_ext!(PersistedMlsPendingGroup, id_field=id, blob_fields=[state,custom_configuration,], additional_fields=[(parent_id: None),]);
    impl_entity_random_update_ext!(MlsPendingMessage, id_field = foreign_id, blob_fields = [message,]);
    impl_entity_random_update_ext!(StoredE2eiEnrollment, id_field = id, blob_fields = [content,]);
    impl_entity_random_update_ext!(StoredEpochEncryptionKeypair, id_field = id, blob_fields = [keypairs,]);

    impl EntityRandomExt for core_crypto_keystore::entities::E2eiIntermediateCert {
        fn random() -> Self {
            let mut rng = rand::thread_rng();

            let ski_aki_pair = rng
                .clone()
                .sample_iter(rand::distributions::Alphanumeric)
                .take(rng.gen_range(MAX_BLOB_SIZE))
                .map(char::from)
                .collect::<String>();

            let mut content = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
            rng.fill(&mut content[..]);

            Self { ski_aki_pair, content }
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

            let host = rng
                .clone()
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

    cfg_if::cfg_if! {
        if #[cfg(feature = "proteus-keystore")] {

            impl_entity_random_update_ext!(ProteusSession, blob_fields=[session,], additional_fields=[(id: uuid::Uuid::new_v4().hyphenated().to_string()),]);

            impl EntityRandomExt for core_crypto_keystore::entities::ProteusPrekey {
                fn random() -> Self {
                    use rand::Rng as _;
                    let mut rng = rand::thread_rng();

                    let id: u16 = rng.r#gen();
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
