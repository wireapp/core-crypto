//! To add tests for different searchable entities, copy and paste one of the entity modules.
//!
//! This is annoying and against DRY, but on the other hand it works. Things known not to work:
//!   - putting `random_entity` and `get_search_key` into a trait
//!   - writing a macro which generates the inner tests

pub use rstest::*;
pub use rstest_reuse::{self, *};
use wasm_bindgen_test::wasm_bindgen_test_configure;

mod common;

wasm_bindgen_test_configure!(run_in_browser);

#[cfg(test)]
mod persisted_mls_groups {
    use crate::common::*;
    use core_crypto_keystore::{
        entities::{ParentGroupId, PersistedMlsGroup},
        traits::FetchFromDatabase as _,
    };
    use rand::{Rng, RngCore, distributions::uniform::SampleRange};
    use rstest_reuse::apply;

    fn random_bytes(len: impl SampleRange<usize>) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let len = rng.gen_range(len);
        let mut value = vec![0; len];
        rng.fill_bytes(&mut value);
        value
    }

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
}
