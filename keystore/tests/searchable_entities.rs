//! To add tests for different searchable entities, copy and paste one of the entity modules.
//!
//! This is annoying and against DRY, but on the other hand it works. Things known not to work:
//!   - putting `random_entity` and `get_search_key` into a trait
//!   - writing a macro which generates the inner tests

use rand::{Rng, RngCore, distributions::uniform::SampleRange};
pub use rstest::*;
pub use rstest_reuse::{self, *};
use wasm_bindgen_test::*;

mod common;

wasm_bindgen_test_configure!(run_in_browser);

fn random_bytes(len: impl SampleRange<usize>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(len);
    let mut value = vec![0; len];
    rng.fill_bytes(&mut value);
    value
}

#[cfg(test)]
mod persisted_mls_groups {
    use core_crypto_keystore::{
        entities::{ParentGroupId, PersistedMlsGroup},
        traits::FetchFromDatabase as _,
    };
    use rstest_reuse::apply;

    use crate::{common::*, random_bytes};

    fn random_entity() -> PersistedMlsGroup {
        PersistedMlsGroup {
            id: random_bytes(32..=32),
            state: random_bytes(128..256),
            parent_id: Some(random_bytes(32..=32)),
        }
    }

    fn get_search_key(entity: &PersistedMlsGroup) -> ParentGroupId<'_> {
        entity
            .parent_id
            .as_deref()
            .expect("all entities in these tests have a parent id")
            .into()
    }

    #[apply(all_storage_types)]
    async fn search_can_find_an_entity(context: KeystoreTestContext) {
        let store = context.store();
        let _ = env_logger::try_init();

        let entity = random_entity();
        let search_key = get_search_key(&entity);

        store.save(entity.clone()).await.unwrap();
        store.commit_transaction().await.unwrap();
        store.new_transaction().await.unwrap();

        let found = store
            .search::<PersistedMlsGroup, ParentGroupId>(&search_key)
            .await
            .unwrap();
        assert_eq!(found, vec![entity]);
    }

    #[apply(all_storage_types)]
    async fn search_can_find_two_entities(context: KeystoreTestContext) {
        let store = context.store();
        let _ = env_logger::try_init();

        let mut entities = vec![random_entity(), random_entity()];
        entities.sort_unstable_by(|e1, e2| e1.id.cmp(&e2.id));

        entities[1].parent_id = entities[0].parent_id.clone();

        for entity in &entities {
            store.save(entity.clone()).await.unwrap();
        }
        store.commit_transaction().await.unwrap();
        store.new_transaction().await.unwrap();

        let search_key = get_search_key(&entities[0]);
        let mut found = store
            .search::<PersistedMlsGroup, ParentGroupId>(&search_key)
            .await
            .unwrap();
        found.sort_unstable_by(|e1, e2| e1.id.cmp(&e2.id));

        assert_eq!(entities, found);
    }

    #[apply(all_storage_types)]
    async fn search_finds_only_entities_with_matching_search_key(context: KeystoreTestContext) {
        let store = context.store();
        let _ = env_logger::try_init();

        let relevant_entity = random_entity();
        let irrelevant_entity = random_entity();

        assert_ne!(
            relevant_entity.parent_id.as_ref().unwrap(),
            irrelevant_entity.parent_id.as_ref().unwrap()
        );

        for entity in [&relevant_entity, &irrelevant_entity] {
            store.save(entity.clone()).await.unwrap();
        }
        store.commit_transaction().await.unwrap();
        store.new_transaction().await.unwrap();

        let search_key = get_search_key(&relevant_entity);
        let found = store
            .search::<PersistedMlsGroup, ParentGroupId>(&search_key)
            .await
            .unwrap();

        assert_eq!(found, vec![relevant_entity]);
    }

    #[apply(all_storage_types)]
    async fn search_can_find_an_uncommitted_entity(context: KeystoreTestContext) {
        let store = context.store();
        let _ = env_logger::try_init();

        let entity = random_entity();
        let search_key = get_search_key(&entity);

        store.save(entity.clone()).await.unwrap();

        let found = store
            .search::<PersistedMlsGroup, ParentGroupId>(&search_key)
            .await
            .unwrap();
        assert_eq!(found, vec![entity]);
    }

    #[apply(all_storage_types)]
    async fn search_does_not_find_uncommitted_deleted_entity(context: KeystoreTestContext) {
        use core_crypto_keystore::traits::BorrowPrimaryKey as _;

        let store = context.store();
        let _ = env_logger::try_init();

        let entity = random_entity();
        let search_key = get_search_key(&entity);

        store.save(entity.clone()).await.unwrap();
        store.commit_transaction().await.unwrap();
        store.new_transaction().await.unwrap();

        store
            .remove_borrowed::<PersistedMlsGroup>(entity.borrow_primary_key())
            .await
            .unwrap();

        let found = store
            .search::<PersistedMlsGroup, ParentGroupId>(&search_key)
            .await
            .unwrap();
        assert!(found.is_empty());
    }
}

#[cfg(test)]
mod stored_credential {
    use core_crypto_keystore::{
        entities::{CredentialFindFilters, StoredCredential},
        traits::{FetchFromDatabase as _, PrimaryKey as _},
    };
    use rand::Rng;
    use rstest_reuse::apply;

    use crate::{common::*, random_bytes};

    fn random_entity() -> StoredCredential {
        let mut rng = rand::thread_rng();

        let session_id = random_bytes(32..=32);
        let credential = random_bytes(128..=256);
        let created_at = 0; // updated on save
        let ciphersuite = rng.gen_range(1_u16..=7);
        let public_key = random_bytes(512..=1024);
        let private_key = random_bytes(128..=256);

        StoredCredential {
            session_id,
            credential,
            created_at,
            ciphersuite,
            public_key,
            private_key,
        }
    }

    fn get_search_key(entity: &StoredCredential) -> CredentialFindFilters<'_> {
        loop {
            let ciphersuite = rand::random::<bool>().then_some(entity.ciphersuite);
            let earliest_validity = rand::random::<bool>().then_some(entity.created_at);

            // don't generate hash or public key; those are unique to a credential
            // but ciphersuite and earliest validity are fair game
            // we could in principle do this with session id but two parameters are sufficient to demonstrate
            // that ultimately this works
            if ciphersuite.is_some() || earliest_validity.is_some() {
                return CredentialFindFilters {
                    ciphersuite,
                    earliest_validity,
                    ..Default::default()
                };
            }
        }
    }

    #[apply(all_storage_types)]
    async fn search_can_find_an_entity(context: KeystoreTestContext) {
        let store = context.store();
        let _ = env_logger::try_init();

        let mut entity = random_entity();

        entity.created_at = store.save(entity.clone()).await.unwrap();
        let search_key = get_search_key(&entity);

        store.commit_transaction().await.unwrap();
        store.new_transaction().await.unwrap();

        let found = store
            .search::<StoredCredential, CredentialFindFilters>(&search_key)
            .await
            .unwrap();
        assert_eq!(found, vec![entity]);
    }

    #[apply(all_storage_types)]
    async fn search_can_find_two_entities(context: KeystoreTestContext) {
        let store = context.store();
        let _ = env_logger::try_init();

        let mut entities = vec![random_entity(), random_entity()];
        entities.sort_unstable_by(|e1, e2| e1.public_key.cmp(&e2.public_key));
        entities[1].ciphersuite = entities[0].ciphersuite;

        for entity in &mut entities {
            entity.created_at = store.save(entity.clone()).await.unwrap();
        }
        entities[1].created_at = entities[0].created_at;

        store.commit_transaction().await.unwrap();
        store.new_transaction().await.unwrap();

        let search_key = get_search_key(&entities[0]);
        let mut found = store
            .search::<StoredCredential, CredentialFindFilters>(&search_key)
            .await
            .unwrap();
        found.sort_unstable_by(|e1, e2| e1.public_key.cmp(&e2.public_key));

        assert_eq!(entities, found);
    }

    // we don't have a good way to just delay for a second in wasm, so skip this test which relies on that behavior
    #[cfg(not(target_family = "wasm"))]
    #[apply(all_storage_types)]
    async fn search_finds_only_entities_with_matching_search_key(context: KeystoreTestContext) {
        let store = context.store();
        let _ = env_logger::try_init();

        let mut relevant_entity = random_entity();
        let mut irrelevant_entity = random_entity();
        // ensure the irrelevant entity will definitely not accidentally match
        irrelevant_entity.ciphersuite = relevant_entity.ciphersuite + 1;

        for entity in [&mut relevant_entity, &mut irrelevant_entity] {
            entity.created_at = store.save(entity.clone()).await.unwrap();
            // ensure the entities are created in different seconds so they don't accidentally match
            smol::Timer::after(std::time::Duration::from_secs(1)).await;
        }
        store.commit_transaction().await.unwrap();
        store.new_transaction().await.unwrap();

        let search_key = get_search_key(&relevant_entity);
        let found = store
            .search::<StoredCredential, CredentialFindFilters>(&search_key)
            .await
            .unwrap();

        assert_eq!(found, vec![relevant_entity]);
    }

    #[apply(all_storage_types)]
    async fn search_can_find_an_uncommitted_entity(context: KeystoreTestContext) {
        let store = context.store();
        let _ = env_logger::try_init();

        let mut entity = random_entity();
        entity.created_at = store.save(entity.clone()).await.unwrap();
        let search_key = get_search_key(&entity);

        let found = store
            .search::<StoredCredential, CredentialFindFilters>(&search_key)
            .await
            .unwrap();
        assert_eq!(found, vec![entity]);
    }

    #[apply(all_storage_types)]
    async fn search_does_not_find_uncommitted_deleted_entity(context: KeystoreTestContext) {
        let store = context.store();
        let _ = env_logger::try_init();

        let entity = random_entity();
        let search_key = get_search_key(&entity);

        store.save(entity.clone()).await.unwrap();
        store.commit_transaction().await.unwrap();
        store.new_transaction().await.unwrap();

        store.remove::<StoredCredential>(&entity.primary_key()).await.unwrap();

        let found = store
            .search::<StoredCredential, CredentialFindFilters>(&search_key)
            .await
            .unwrap();
        assert!(found.is_empty());
    }
}
