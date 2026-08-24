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

/// Emit a borrowed-primary-key round trip for this entity, or nothing if it opted out.
///
/// Unlike the `ignore_*` flags, this cannot be a runtime condition: an entity without a borrowed
/// primary key does not satisfy the round trip's trait bounds, so the call must be absent from the
/// generated code entirely rather than merely skipped. Opting out is by presence of the flag, so
/// write `no_borrowed_key:true` and never `no_borrowed_key:false`.
macro_rules! borrowed_key_round_trip {
    ($store:expr, $entity:ident,) => {
        crate::tests_impl::can_round_trip_entity_by_borrowed_key::<$entity>($store).await
    };
    ($store:expr, $entity:ident, $opted_out:literal) => {};
}

macro_rules! test_for_entity {
    (
        $test_name:ident, $entity:ident
        $(ignore_entity_count:$ignore_entity_count:literal)?
        $(ignore_update:$ignore_update:literal)?
        $(no_upsert:$no_upsert:literal)?
        $(ignore_remove:$ignore_remove:literal)?
        $(ignore_find_many:$ignore_find_many:literal)?
        $(no_borrowed_key:$no_borrowed_key:literal)?
    ) => {
        #[apply(all_storage_types)]
        async fn $test_name(context: KeystoreTestContext) {
            let store = context.store();
            let _ = env_logger::try_init();
            let mut entity = crate::tests_impl::can_save_entity::<$entity>(&store).await;

            crate::tests_impl::can_find_entity::<$entity>(&store, &entity).await;

            borrowed_key_round_trip!(&store, $entity, $($no_borrowed_key)?);

            if pat_to_bool!($($no_upsert)?) {
                crate::tests_impl::cannot_update_entity::<$entity>(&store, &entity).await;
            } else if !pat_to_bool!($($ignore_update)?) {
                crate::tests_impl::can_update_entity::<$entity>(&store, &mut entity).await;
            }
            if !pat_to_bool!($($ignore_remove)?) {
                crate::tests_impl::can_remove_entity::<$entity>(&store, entity).await;
            }

            let ignore_count = pat_to_bool!($($ignore_entity_count)?);
            if !ignore_count {
                crate::tests_impl::insert_count_entities::<$entity>(&store).await;
            }
            crate::tests_impl::can_list_entities_with_find_all::<$entity>(&store, ignore_count).await;
        }
    };
}

#[cfg(test)]
mod tests_impl {
    use std::{any::Any, borrow::Borrow, sync::Arc};

    use core_crypto_keystore::{
        CryptoKeystoreError,
        entities::{
            MlsPendingMessage, PersistedMlsGroup, PersistedMlsPendingGroup, StoredCredential, TargetedMessageTxCounter,
        },
        traits::{
            BorrowPrimaryKey, Entity, EntityDatabaseMutation, EntityDeleteBorrowed, EntityGetBorrowed,
            FetchFromDatabase as _, PrimaryKey as _,
        },
        transaction::EntityId,
    };

    use super::common::*;
    use crate::{
        ENTITY_COUNT,
        utils::{EntityRandomExt, EntityRandomUpdateExt},
    };

    /// Assert that no keystore transaction is in flight.
    ///
    /// While a transaction is in flight, reads are served from its in-memory cache and never reach
    /// SQL. A test which reads back through an open transaction therefore proves nothing about the
    /// generated queries: it would pass just as happily against a query which matches zero rows.
    /// This suite once did exactly that, which is how a primary key binding that compared a `BLOB`
    /// against `TEXT` values survived three releases.
    ///
    /// Call this immediately before any read which is meant to exercise the database.
    async fn assert_no_transaction_in_flight(store: &Arc<CryptoKeystore>) {
        // Acquiring an immediate transaction fails if and only if another transaction holds the
        // transaction semaphore. Dropping the guard right away rolls this one back, leaving the
        // database as we found it: subsequent reads find a stale weak reference, fail to upgrade
        // it, and fall through to SQL.
        assert!(
            store.try_new_immediate_transaction().await.is_ok(),
            "a transaction is in flight, so reads are served from its cache instead of the database"
        );
    }

    pub(crate) async fn can_save_entity<E>(store: &Arc<CryptoKeystore>) -> E
    where
        E: 'static + Clone + EntityRandomUpdateExt + Entity + EntityDatabaseMutation + Send + Sync,
    {
        let mut entity = E::random();
        let tx = store.new_transaction().await.unwrap();
        {
            let any_e: &mut dyn Any = &mut entity;

            // pending messages have a foreign key constraint which must be satisfied
            if let Some(pending_message) = any_e.downcast_mut::<MlsPendingMessage>() {
                let pending_groups = PersistedMlsPendingGroup::random();
                pending_message.conversation_id = pending_groups.id.clone();

                tx.save(pending_groups).await.unwrap();

            // tnt message counters also have a foreign key constraint which must be satisfied
            } else if let Some(counter) = any_e.downcast_mut::<TargetedMessageTxCounter>() {
                let group = PersistedMlsGroup::random();
                counter.conversation_id = group.id.clone();

                tx.save(group).await.unwrap();
            }
        }

        tx.save(entity.clone()).await.unwrap();
        tx.commit().await.unwrap();
        entity
    }

    pub(crate) async fn can_find_entity<E>(store: &Arc<CryptoKeystore>, entity: &E)
    where
        E: 'static
            + Clone
            + std::fmt::Debug
            + Eq
            + EntityRandomUpdateExt
            + Entity
            + EntityDatabaseMutation
            + Send
            + Sync,
    {
        assert_no_transaction_in_flight(store).await;

        let any_e: &dyn Any = entity;
        if let Some(pending_message) = any_e.downcast_ref::<MlsPendingMessage>() {
            let pending_message_from_store = store
                .search::<MlsPendingMessage, _>(&pending_message.conversation_id.clone().into())
                .await
                .unwrap()
                .pop()
                .unwrap();
            assert_eq!(*pending_message, *pending_message_from_store);
        } else if let Some(credential) = any_e.downcast_ref::<StoredCredential>() {
            let mut credential_from_store = Arc::unwrap_or_clone(
                store
                    .get::<StoredCredential>(&credential.primary_key())
                    .await
                    .unwrap()
                    .unwrap(),
            );
            credential_from_store.equalize();
            assert_eq!(*credential, credential_from_store);
        } else {
            let primary_key = entity.primary_key();
            let mut entity_from_store = Arc::unwrap_or_clone(store.get::<E>(&primary_key).await.unwrap().unwrap());
            entity_from_store.equalize();
            assert_eq!(*entity, entity_from_store);
        };
    }

    /// Save, find, and remove an entity through the borrowed form of its primary key.
    ///
    /// `Entity::get` and `EntityDatabaseMutation::delete` are generated as thin delegations to their
    /// borrowed-key counterparts, so every other test in this suite reaches `get_borrowed` and
    /// `delete_borrowed` only through that delegation. Were it ever to stop delegating, both
    /// borrowed paths would lose all coverage without a single test failing. Drive them directly.
    ///
    /// This uses an entity of its own rather than the one under test, so it neither depends on nor
    /// disturbs the owned-key tests, and leaves the entity count as it found it.
    pub(crate) async fn can_round_trip_entity_by_borrowed_key<E>(store: &Arc<CryptoKeystore>)
    where
        E: 'static
            + Clone
            + std::fmt::Debug
            + Eq
            + EntityRandomUpdateExt
            + EntityGetBorrowed
            + EntityDeleteBorrowed
            + Send
            + Sync,
        E::PrimaryKey: Borrow<E::BorrowedPrimaryKey>,
        <E as BorrowPrimaryKey>::BorrowedPrimaryKey: Send + Sync,
    {
        let entity = E::random();
        let primary_key = entity.primary_key();

        let tx = store.new_transaction().await.unwrap();
        tx.save(entity.clone()).await.unwrap();
        tx.commit().await.unwrap();

        assert_no_transaction_in_flight(store).await;
        let mut found = Arc::unwrap_or_clone(
            store
                .get_borrowed::<E>(primary_key.borrow())
                .await
                .unwrap()
                .expect("an entity which was just saved is findable by its borrowed primary key"),
        );
        found.equalize();
        assert_eq!(entity, found);

        let tx = store.new_transaction().await.unwrap();
        tx.remove_borrowed::<E>(primary_key.borrow()).await.unwrap();
        tx.commit().await.unwrap();

        assert_no_transaction_in_flight(store).await;
        assert!(
            store.get_borrowed::<E>(primary_key.borrow()).await.unwrap().is_none(),
            "the entity is still findable by its borrowed primary key after being removed"
        );

        // As in `can_remove_entity`, confirm the deletion against the one read which binds no key.
        let key = EntityId::from_primary_key::<E>(primary_key);
        let remaining = store.load_all::<E>().await.unwrap();
        assert!(
            !remaining.iter().any(|remaining| {
                let remaining_key = EntityId::from_primary_key::<E>(remaining.primary_key());
                remaining_key == key
            }),
            "the entity is still in the database, so the borrowed-key removal deleted no rows"
        );
    }

    pub(crate) async fn can_update_entity<E>(store: &Arc<CryptoKeystore>, entity: &mut E)
    where
        E: 'static
            + Clone
            + std::fmt::Debug
            + Eq
            + EntityRandomUpdateExt
            + Entity
            + EntityDatabaseMutation
            + Send
            + Sync,
    {
        entity.random_update();
        let tx = store.new_transaction().await.unwrap();
        tx.save(entity.clone()).await.unwrap();
        tx.commit().await.unwrap();

        assert_no_transaction_in_flight(store).await;
        let entity2 = store.get::<E>(&entity.primary_key()).await.unwrap().unwrap();
        assert_eq!(*entity, *entity2);
    }

    /// The mirror image of [`can_update_entity`], for entities whose primary key determines their
    /// contents: rewriting one under its existing key must fail rather than clobber it.
    ///
    /// The rejection happens at commit rather than at `save`, because `save` only buffers an
    /// operation; nothing reaches SQL until the transaction is applied. The whole transaction is
    /// therefore lost, which is the intended outcome — for these entities a duplicate key with
    /// different contents is a bug, not a caller error to be recovered from.
    pub(crate) async fn cannot_update_entity<E>(store: &Arc<CryptoKeystore>, entity: &E)
    where
        E: 'static
            + Clone
            + std::fmt::Debug
            + Eq
            + EntityRandomUpdateExt
            + Entity
            + EntityDatabaseMutation
            + Send
            + Sync,
    {
        let mut updated = entity.clone();
        updated.random_update();
        assert_ne!(
            *entity, updated,
            "`random_update` left the entity unchanged, so this test would pass vacuously"
        );

        let tx = store.new_transaction().await.unwrap();
        tx.save(updated).await.unwrap();
        let commit_error = tx
            .commit()
            .await
            .expect_err("this entity does not upsert, so rewriting it under its own key must fail");
        assert!(
            matches!(commit_error, CryptoKeystoreError::AlreadyExists(table) if table == E::TABLE_NAME),
            "expected a uniqueness violation for {}, got {commit_error:?}",
            E::TABLE_NAME
        );

        assert_no_transaction_in_flight(store).await;
        let mut stored = Arc::unwrap_or_clone(store.get::<E>(&entity.primary_key()).await.unwrap().unwrap());
        stored.equalize();
        assert_eq!(*entity, stored, "the rejected save must have left the row untouched");
    }

    pub(crate) async fn can_remove_entity<E>(store: &Arc<CryptoKeystore>, entity: E)
    where
        E: 'static + Clone + EntityRandomUpdateExt + Entity + EntityDatabaseMutation + Send + Sync,
    {
        let tx = store.new_transaction().await.unwrap();
        tx.remove::<E>(&entity.primary_key()).await.unwrap();
        tx.commit().await.unwrap();

        assert_no_transaction_in_flight(store).await;
        let entity2 = store.get::<E>(&entity.primary_key()).await.unwrap();
        assert!(entity2.is_none());

        // The check above binds the primary key into a `WHERE` clause, so it reports "absent" both
        // when the row is really gone and when the lookup binding matches nothing at all. Confirm
        // the removal against `load_all`, which binds no key: it is the only read here that cannot
        // be fooled by the same binding it is being used to validate.
        //
        // Not every primary key is `PartialEq`, but every primary key can produce its byte
        // encoding, which is what the transaction cache already uses for record identity.
        let removed_key = EntityId::from_primary_key::<E>(entity.primary_key());
        let remaining = store.load_all::<E>().await.unwrap();
        assert!(
            !remaining.iter().any(|remaining| {
                let remaining_key = EntityId::from_primary_key::<E>(remaining.primary_key());
                remaining_key == removed_key
            }),
            "the entity is still in the database, so the removal deleted no rows"
        );
    }

    pub(super) async fn insert_count_entities<E>(store: &Arc<CryptoKeystore>)
    where
        E: 'static + Clone + EntityRandomUpdateExt + Entity + EntityDatabaseMutation + Send + Sync,
    {
        let tx = store.new_transaction().await.unwrap();
        for _ in 0..ENTITY_COUNT {
            // tnt message counters also have a foreign key constraint which must be satisfied
            let mut entity = E::random();
            let any_e: &mut dyn Any = &mut entity;
            if let Some(counter) = any_e.downcast_mut::<TargetedMessageTxCounter>() {
                let group = PersistedMlsGroup::random();
                counter.conversation_id = group.id.clone();
                tx.save(group).await.unwrap();
            }
            tx.save(entity).await.unwrap();
        }
        tx.commit().await.unwrap();
    }

    pub(crate) async fn can_list_entities_with_find_all<E>(store: &Arc<CryptoKeystore>, ignore_entity_count: bool)
    where
        E: 'static + Clone + EntityRandomUpdateExt + Entity + EntityDatabaseMutation + Send + Sync,
    {
        assert_no_transaction_in_flight(store).await;

        let entities = store.load_all::<E>().await.unwrap();
        if !ignore_entity_count {
            assert_eq!(entities.len(), ENTITY_COUNT);
        }
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use crate::common::*;

    wasm_bindgen_test_configure!(run_in_browser);

    use core_crypto_keystore::entities::*;

    test_for_entity!(test_persisted_mls_group, PersistedMlsGroup);
    test_for_entity!(test_tnt_message_counter, TargetedMessageTxCounter no_borrowed_key:true);
    test_for_entity!(test_persisted_mls_pending_group, PersistedMlsPendingGroup);
    test_for_entity!(test_mls_pending_message, MlsPendingMessage ignore_entity_count: true ignore_update:true ignore_remove:true ignore_find_many:true no_borrowed_key:true);
    test_for_entity!(test_mls_credential, StoredCredential ignore_update:true no_borrowed_key:true);
    test_for_entity!(test_mls_keypackage, StoredKeyPackage no_upsert:true);
    test_for_entity!(test_mls_psk_bundle, StoredPskBundle no_upsert:true);
    test_for_entity!(test_mls_encryption_keypair, StoredEncryptionKeyPair no_upsert:true);
    test_for_entity!(test_mls_epoch_encryption_keypair, StoredEpochEncryptionKeypair);
    test_for_entity!(test_mls_hpke_private_key, StoredHpkePrivateKey no_upsert:true);
    test_for_entity!(test_e2ei_intermediate_cert, X509IntermediateCert);
    test_for_entity!(test_e2ei_crl, X509Crl);
    test_for_entity!(test_e2ei_acme_ca, X509TrustAnchor ignore_entity_count:true no_upsert:true ignore_find_many:true no_borrowed_key:true);
    #[cfg(feature = "proteus-keystore")]
    test_for_entity!(test_proteus_identity, ProteusIdentity ignore_entity_count:true ignore_update:true no_borrowed_key:true);
    #[cfg(feature = "proteus-keystore")]
    test_for_entity!(test_proteus_prekey, ProteusPrekey no_upsert:true no_borrowed_key:true);
    #[cfg(feature = "proteus-keystore")]
    test_for_entity!(test_proteus_session, ProteusSession);

    #[apply(all_storage_types)]
    async fn can_save_and_load_consumer_data(context: KeystoreTestContext) {
        use core_crypto_keystore::traits::FetchFromDatabase as _;

        eprintln!("creating store");
        let store = context.store();

        eprintln!("checking consumer data before it exists");
        assert!(!store.exists::<ConsumerData>().await.unwrap());
        let consumer_data = store.get_unique::<ConsumerData>().await.unwrap();
        assert!(consumer_data.is_none());

        let tx = store.new_transaction().await.unwrap();

        eprintln!("saving some consumer data");
        const DATA: &[u8] = b"here is some arbitrary data";
        tx.save(ConsumerData {
            content: DATA.to_owned(),
        })
        .await
        .unwrap();

        // from transaction
        eprintln!("checking retrieving consumer data from active transaction");
        assert!(store.exists::<ConsumerData>().await.unwrap());
        let consumer_data = store.get_unique::<ConsumerData>().await.unwrap().unwrap();
        assert_eq!(consumer_data.content, DATA);

        eprintln!("committing transaction");
        tx.commit().await.unwrap();

        // from storage (fallthrough)
        eprintln!("checking retrieving consumer data from storage");
        assert!(store.exists::<ConsumerData>().await.unwrap());
        let consumer_data = store.get_unique::<ConsumerData>().await.unwrap().unwrap();
        assert_eq!(consumer_data.content, DATA);
    }
}

#[cfg(test)]
pub mod utils {
    use core_crypto_keystore::entities::{
        MlsPendingMessage, PersistedMlsGroup, PersistedMlsPendingGroup, ProteusSession, StoredCredential,
        StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeyPackage, StoredPskBundle,
        TargetedMessageTxCounter, X509TrustAnchor,
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

    impl_entity_random_update_ext!(StoredKeyPackage, blob_fields=[key_package,], additional_fields=[(key_package_ref: uuid::Uuid::new_v4().hyphenated().to_string().into()),]);
    impl_entity_random_update_ext!(StoredCredential, blob_fields=[credential,public_key,private_key,], additional_fields=[(session_id: uuid::Uuid::new_v4().hyphenated().to_string().into()),(created_at: 0; auto-generated:true),(ciphersuite: rand::random()),]);
    impl_entity_random_update_ext!(StoredHpkePrivateKey, blob_fields=[pk id_like:true,sk,]);
    impl_entity_random_update_ext!(StoredEncryptionKeyPair, blob_fields=[pk id_like:true,sk,]);
    impl_entity_random_update_ext!(StoredPskBundle, blob_fields=[psk,psk_id id_like:true,]);
    impl_entity_random_update_ext!(PersistedMlsGroup, id_field = id, blob_fields = [state,]);
    impl EntityRandomExt for TargetedMessageTxCounter {
        fn random() -> Self {
            Self {
                conversation_id: b"This cannot be filled meaninfully here; need a real conversation".to_vec(),
                receiver: rand::random(),
                count: rand::random(),
            }
        }
    }

    impl EntityRandomUpdateExt for TargetedMessageTxCounter {
        fn random_update(&mut self) {
            self.count = rand::random();
        }
    }

    impl_entity_random_update_ext!(PersistedMlsPendingGroup, id_field=id, blob_fields=[state,custom_configuration,], additional_fields=[(parent_id: None),]);
    impl_entity_random_update_ext!(MlsPendingMessage, id_field = conversation_id, blob_fields = [message,]);
    impl_entity_random_update_ext!(StoredEpochEncryptionKeypair, id_field = id, blob_fields = [keypairs,]);
    impl_entity_random_update_ext!(X509TrustAnchor, id_field = fingerprint, blob_fields = [content,]);

    impl EntityRandomExt for core_crypto_keystore::entities::X509IntermediateCert {
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

    impl EntityRandomUpdateExt for core_crypto_keystore::entities::X509IntermediateCert {
        fn random_update(&mut self) {
            let mut rng = rand::thread_rng();
            self.content = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
            rng.fill(&mut self.content[..]);
        }
    }

    impl EntityRandomExt for core_crypto_keystore::entities::X509Crl {
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

    impl EntityRandomUpdateExt for core_crypto_keystore::entities::X509Crl {
        fn random_update(&mut self) {
            let mut rng = rand::thread_rng();
            self.content = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
            rng.fill(&mut self.content[..]);
        }
    }

    #[cfg(feature = "proteus-keystore")]
    const _: () = {
        impl_entity_random_update_ext!(ProteusSession, blob_fields=[session,], additional_fields=[(id: uuid::Uuid::new_v4().hyphenated().to_string()),]);

        impl EntityRandomExt for core_crypto_keystore::entities::ProteusPrekey {
            fn random() -> Self {
                use rand::Rng as _;
                let mut rng = rand::thread_rng();

                // Counted rather than drawn at random. A prekey id is only 16 bits wide and this
                // entity does not upsert, so random ids would collide across the dozen prekeys a
                // single run creates about once in a thousand runs, and each collision would fail
                // the run. Counting makes the ids unique by construction.
                static NEXT_ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(1);
                let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let mut prekey = vec![0u8; rng.gen_range(MAX_BLOB_SIZE)];
                rng.fill(&mut prekey[..]);

                Self::from_raw(id, prekey)
            }
        }

        impl EntityRandomUpdateExt for core_crypto_keystore::entities::ProteusPrekey {
            fn random_update(&mut self) {
                let mut rng = rand::thread_rng();
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

                Self { sk, pk }
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
    };
}
