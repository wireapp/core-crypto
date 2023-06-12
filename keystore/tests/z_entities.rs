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
    ($test_name:ident, $entity:ident $(ignore_entity_count:$ignore_entity_count:literal)? $(ignore_update:$ignore_update:literal)?) => {
        #[apply(all_storage_types)]
        #[wasm_bindgen_test]
        pub async fn $test_name(store: core_crypto_keystore::Connection) {
            let store = store.await;
            let _ = pretty_env_logger::try_init();
            let mut entity = crate::tests_impl::can_save_entity::<$entity>(&store).await;

            crate::tests_impl::can_find_entity::<$entity>(&store, &entity).await;
            let ignore_update = pat_to_bool!($($ignore_update)?);
            if !ignore_update {
                crate::tests_impl::can_update_entity::<$entity>(&store, &mut entity).await;
            }
            crate::tests_impl::can_remove_entity::<$entity>(&store, entity).await;

            let ignore = pat_to_bool!($($ignore_entity_count)?);
            crate::tests_impl::can_list_entities_with_find_many::<$entity>(&store, ignore).await;
            crate::tests_impl::can_list_entities_with_find_all::<$entity>(&store, ignore).await;

            store.wipe().await.unwrap();
        }
    };
}

#[cfg(test)]
mod tests_impl {
    use super::common::*;
    use crate::{utils::EntityTestExt, ENTITY_COUNT};
    use core_crypto_keystore::{
        connection::KeystoreDatabaseConnection,
        entities::{Entity, EntityFindParams},
    };

    pub async fn can_save_entity<R: EntityTestExt + Entity<ConnectionType = KeystoreDatabaseConnection>>(
        store: &CryptoKeystore,
    ) -> R {
        let entity = R::random();
        store.save(entity.clone()).await.unwrap();
        entity
    }

    pub async fn can_find_entity<R: EntityTestExt + Entity<ConnectionType = KeystoreDatabaseConnection> + 'static>(
        store: &CryptoKeystore,
        entity: &R,
    ) {
        let mut entity2: R = store.find(entity.id_raw()).await.unwrap().unwrap();
        entity2.equalize();
        assert_eq!(*entity, entity2);
    }

    pub async fn can_update_entity<R: EntityTestExt + Entity<ConnectionType = KeystoreDatabaseConnection>>(
        store: &CryptoKeystore,
        entity: &mut R,
    ) {
        entity.random_update();
        store.save(entity.clone()).await.unwrap();
        let entity2: R = store.find(entity.id_raw()).await.unwrap().unwrap();
        assert_eq!(*entity, entity2);
    }

    pub async fn can_remove_entity<R: EntityTestExt + Entity<ConnectionType = KeystoreDatabaseConnection>>(
        store: &CryptoKeystore,
        entity: R,
    ) {
        store.remove::<R, _>(entity.id_raw()).await.unwrap();
        let entity2: Option<R> = store.find(entity.id_raw()).await.unwrap();
        assert!(entity2.is_none());
    }

    pub async fn can_list_entities_with_find_many<
        R: EntityTestExt + Entity<ConnectionType = KeystoreDatabaseConnection>,
    >(
        store: &CryptoKeystore,
        ignore_entity_count: bool,
    ) {
        let mut ids: Vec<Vec<u8>> = vec![];
        for _ in 0..ENTITY_COUNT {
            let entity = R::random();
            ids.push(entity.id_raw().to_vec());
            store.save(entity).await.unwrap();
        }

        let entities = store.find_many::<R, _>(&ids).await.unwrap();
        if !ignore_entity_count {
            assert_eq!(entities.len(), ENTITY_COUNT);
        }
    }

    pub async fn can_list_entities_with_find_all<
        R: EntityTestExt + Entity<ConnectionType = KeystoreDatabaseConnection>,
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
pub mod tests {
    use crate::common::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    use core_crypto_keystore::entities::*;

    cfg_if::cfg_if! {
        if #[cfg(feature = "mls-keystore")] {
            test_for_entity!(test_persisted_mls_group, PersistedMlsGroup);
            test_for_entity!(test_persisted_mls_pending_group, PersistedMlsPendingGroup);
            test_for_entity!(test_mls_credential, MlsCredential ignore_update:true);
            test_for_entity!(test_mls_keypackage, MlsKeyPackage);
            test_for_entity!(test_mls_signature_keypair, MlsSignatureKeyPair ignore_update:true);
            test_for_entity!(test_mls_psk_bundle, MlsPskBundle);
            test_for_entity!(test_mls_encryption_keypair, MlsEncryptionKeyPair);
            test_for_entity!(test_mls_hpke_private_key, MlsHpkePrivateKey);
        }
    }
    cfg_if::cfg_if! {
        if #[cfg(feature = "proteus-keystore")] {
            test_for_entity!(test_proteus_identity, ProteusIdentity ignore_entity_count:true ignore_update:true);
            test_for_entity!(test_proteus_prekey, ProteusPrekey);
            test_for_entity!(test_proteus_session, ProteusSession);
        }
    }
}

#[cfg(test)]
pub mod utils {
    use rand::Rng as _;
    const MAX_BLOB_SIZE: std::ops::Range<usize> = 1024..8192;

    pub trait EntityTestExt: core_crypto_keystore::entities::Entity {
        fn random() -> Self;
        fn random_update(&mut self);
        /// Removes auto-generated fields from the entity
        fn equalize(&mut self) {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "mls-keystore")] {
            impl EntityTestExt for core_crypto_keystore::entities::MlsKeyPackage {
                fn random() -> Self {
                    let mut rng = rand::thread_rng();

                    let keypackage_ref = uuid::Uuid::new_v4().hyphenated().to_string().into_bytes();
                    let mut keypackage = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut keypackage[..]);

                    Self {
                        keypackage_ref,
                        keypackage,
                    }
                }

                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();
                    self.keypackage = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut self.keypackage[..]);
                }
            }

            impl EntityTestExt for core_crypto_keystore::entities::MlsCredential {
                fn random() -> Self {
                    let mut rng = rand::thread_rng();

                    let id: String = uuid::Uuid::new_v4().hyphenated().to_string();

                    let mut credential = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut credential[..]);

                    Self {
                        id: id.into(),
                        credential,
                    }
                }

                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();
                    self.id = uuid::Uuid::new_v4().hyphenated().to_string().into();
                    self.credential = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut self.credential[..]);
                }
            }

            impl EntityTestExt for core_crypto_keystore::entities::MlsSignatureKeyPair {
                fn random() -> Self {
                    let mut rng = rand::thread_rng();

                    let mut pk = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut pk[..]);

                    let mut keypair = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut keypair[..]);

                    let mut credential_id = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut credential_id[..]);

                    Self {
                        signature_scheme: rand::random(),
                        keypair, pk, credential_id, created_at: 0,
                    }
                }

                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();

                    self.keypair = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut self.keypair[..]);

                    self.credential_id = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut self.credential_id[..]);
                }

                fn equalize(&mut self) {
                    self.created_at = 0;
                }
            }

            impl EntityTestExt for core_crypto_keystore::entities::MlsHpkePrivateKey {
                fn random() -> Self {
                    let mut rng = rand::thread_rng();

                    let mut pk = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut pk[..]);

                    let mut sk = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut sk[..]);

                    Self {
                        pk, sk
                    }
                }

                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();

                    self.sk = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut self.sk[..]);
                }
            }

            impl EntityTestExt for core_crypto_keystore::entities::MlsEncryptionKeyPair {
                fn random() -> Self {
                    let mut rng = rand::thread_rng();

                    let mut pk = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut pk[..]);

                    let mut sk = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut sk[..]);

                    Self {
                        pk, sk
                    }
                }

                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();

                    self.sk = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut self.sk[..]);
                }
            }

            impl EntityTestExt for core_crypto_keystore::entities::MlsPskBundle {
                fn random() -> Self {
                    let mut rng = rand::thread_rng();

                    let mut psk_id = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut psk_id[..]);

                    let mut psk = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut psk[..]);

                    Self {
                        psk, psk_id
                    }
                }

                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();
                    self.psk = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut self.psk[..]);
                }
            }

            impl EntityTestExt for core_crypto_keystore::entities::PersistedMlsGroup {
                fn random() -> Self {
                    use rand::Rng as _;
                    let mut rng = rand::thread_rng();

                    let uuid = uuid::Uuid::new_v4();
                    let id: [u8; 16] = uuid.into_bytes();

                    let mut state = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut state[..]);

                    Self {
                        id: id.into(),
                        state,
                        parent_id: None,
                    }
                }

                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();
                    self.state = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut self.state[..]);
                }
            }

            impl EntityTestExt for core_crypto_keystore::entities::PersistedMlsPendingGroup {
                fn random() -> Self {
                    use rand::Rng as _;
                    let mut rng = rand::thread_rng();

                    let uuid = uuid::Uuid::new_v4();
                    let id: [u8; 16] = uuid.into_bytes();

                    let mut state = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut state[..]);

                    let mut custom_configuration = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut custom_configuration[..]);

                    Self {
                        id: id.into(),
                        state,
                        custom_configuration,
                        parent_id: None,
                    }
                }

                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();
                    self.state = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut self.state[..]);
                }
            }
        }
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "proteus-keystore")] {
            impl EntityTestExt for core_crypto_keystore::entities::ProteusPrekey {
                fn random() -> Self {
                    use rand::Rng as _;
                    let mut rng = rand::thread_rng();

                    let id: u16 = rng.gen();
                    let mut prekey = vec![0u8; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut prekey[..]);

                    Self::from_raw(id, prekey)
                }

                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();
                    // self.set_id(rng.gen());
                    self.prekey = vec![0u8; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut self.prekey[..]);
                }
            }

            impl EntityTestExt for core_crypto_keystore::entities::ProteusIdentity {
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

                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();
                    self.sk = vec![0u8; Self::SK_KEY_SIZE];
                    rng.fill(&mut self.sk[..]);

                    self.pk = vec![0u8; Self::PK_KEY_SIZE];
                    rng.fill(&mut self.pk[..]);
                }
            }

            impl EntityTestExt for core_crypto_keystore::entities::ProteusSession {
                fn random() -> Self {
                    use rand::Rng as _;
                    let mut rng = rand::thread_rng();

                    let uuid = uuid::Uuid::new_v4();

                    let mut session = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut session[..]);

                    Self {
                        id: uuid.hyphenated().to_string(),
                        session,
                    }
                }

                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();

                    self.session = vec![0; rng.gen_range(MAX_BLOB_SIZE)];
                    rng.fill(&mut self.session[..]);
                }
            }
        }
    }
}
