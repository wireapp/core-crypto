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

macro_rules! test_for_entity {
    ($test_name:ident, $entity:ident) => {
        #[apply(all_storage_types)]
        #[wasm_bindgen_test]
        pub async fn $test_name(store: core_crypto_keystore::Connection) {
            let store = store.await;
            let mut entity = crate::tests_impl::can_save_entity::<$entity>(&store).await;

            crate::tests_impl::can_find_entity::<$entity>(&store, &entity).await;
            crate::tests_impl::can_update_entity::<$entity>(&store, &mut entity).await;
            crate::tests_impl::can_remove_entity::<$entity>(&store, entity).await;

            crate::tests_impl::can_list_entities_with_find_many::<$entity>(&store).await;
            crate::tests_impl::can_list_entities_with_find_all::<$entity>(&store).await;

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

    pub async fn can_find_entity<R: EntityTestExt + Entity<ConnectionType = KeystoreDatabaseConnection>>(
        store: &CryptoKeystore,
        entity: &R,
    ) {
        let entity2: R = store.find(entity.id_raw()).await.unwrap().unwrap();
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
    ) {
        let mut ids: Vec<Vec<u8>> = vec![];
        for _ in 0..ENTITY_COUNT {
            let entity = R::random();
            ids.push(entity.id_raw().to_vec());
            store.save(entity).await.unwrap();
        }

        let entities = store.find_many::<R, _>(&ids).await.unwrap();
        assert_eq!(entities.len(), ENTITY_COUNT);
    }

    pub async fn can_list_entities_with_find_all<
        R: EntityTestExt + Entity<ConnectionType = KeystoreDatabaseConnection>,
    >(
        store: &CryptoKeystore,
    ) {
        let entities = store.find_all::<R>(EntityFindParams::default()).await.unwrap();
        assert_eq!(entities.len(), ENTITY_COUNT);
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
            test_for_entity!(test_mls_identity, MlsIdentity);
            test_for_entity!(test_mls_keypackage, MlsKeypackage);
        }
    }

    #[cfg(feature = "proteus-keystore")]
    test_for_entity!(test_proteus_prekey, ProteusPrekey);
}

#[cfg(test)]
pub mod utils {

    use rand::Rng as _;

    // ? This is making the tests WAY too slow
    // const MAX_BLOB_SIZE: std::ops::Range<usize> = 1024..MAX_BLOB_LEN;
    const MAX_BLOB_SIZE: std::ops::Range<usize> = 1024..8192;

    pub trait EntityTestExt: core_crypto_keystore::entities::Entity {
        fn random() -> Self;
        fn random_update(&mut self);
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "mls-keystore")] {
            impl EntityTestExt for core_crypto_keystore::entities::MlsKeypackage {
                fn random() -> Self {
                    let mut rng = rand::thread_rng();

                    let id: String = uuid::Uuid::new_v4().hyphenated().to_string();
                    let mut key = Vec::with_capacity(rng.gen_range(MAX_BLOB_SIZE));
                    rng.fill(&mut key[..]);

                    Self {
                        id,
                        key
                    }
                }

                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();
                    self.key = Vec::with_capacity(rng.gen_range(MAX_BLOB_SIZE));
                    rng.fill(&mut self.key[..]);
                }
            }

            impl EntityTestExt for core_crypto_keystore::entities::MlsIdentity {
                fn random() -> Self {
                    let mut rng = rand::thread_rng();

                    let id: String = uuid::Uuid::new_v4().hyphenated().to_string();
                    let mut signature = Vec::with_capacity(rng.gen_range(MAX_BLOB_SIZE));
                    rng.fill(&mut signature[..]);

                    let mut credential = Vec::with_capacity(rng.gen_range(MAX_BLOB_SIZE));
                    rng.fill(&mut credential[..]);

                    Self {
                        id,
                        signature,
                        credential,
                    }
                }

                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();
                    self.signature = Vec::with_capacity(rng.gen_range(MAX_BLOB_SIZE));
                    self.credential = Vec::with_capacity(rng.gen_range(MAX_BLOB_SIZE));
                    rng.fill(&mut self.signature[..]);
                    rng.fill(&mut self.credential[..]);
                }
            }

            impl EntityTestExt for core_crypto_keystore::entities::PersistedMlsGroup {
                fn random() -> Self {
                    use rand::Rng as _;
                    let mut rng = rand::thread_rng();

                    let uuid = uuid::Uuid::new_v4();
                    let id: [u8; 16] = uuid.into_bytes();

                    let mut state = Vec::with_capacity(rng.gen_range(MAX_BLOB_SIZE));
                    rng.fill(&mut state[..]);

                    Self {
                        id: id.into(),
                        state,
                    }
                }

                fn random_update(&mut self) {
                    let mut rng = rand::thread_rng();
                    self.state = Vec::with_capacity(rng.gen_range(MAX_BLOB_SIZE));
                    rng.fill(&mut self.state[..]);
                }
            }
        }
    }

    #[cfg(feature = "proteus-keystore")]
    impl EntityTestExt for core_crypto_keystore::entities::ProteusPrekey {
        fn random() -> Self {
            use rand::Rng as _;
            let mut rng = rand::thread_rng();

            let id: u16 = rng.gen();
            let mut prekey = Vec::with_capacity(rng.gen_range(MAX_BLOB_SIZE));
            rng.fill(&mut prekey);

            Self {
                id,
                prekey: prekey.into(),
            }
        }

        fn random_update(&mut self) {
            let mut rng = rand::thread_rng();
            self.prekey = Vec::with_capacity(rng.gen_range(MAX_BLOB_SIZE));
            rng.fill(&mut self.prekey[..]);
        }
    }
}
