//! These methods are specialized for performing certain entity-specific queries.

use std::sync::Arc;

use crate::{
    CryptoKeystoreResult,
    entities::{ConversationId, MlsPendingMessage},
    transaction::Transaction,
};
#[cfg(feature = "proteus-keystore")]
use crate::{entities::ProteusPrekey, transaction::EntityId};

impl Transaction {
    pub(crate) async fn remove_pending_messages_by_conversation_id(&self, conversation_id: impl AsRef<[u8]> + Send) {
        let conversation_id = conversation_id.as_ref().to_vec().into();
        self.bulk_remove::<MlsPendingMessage, ConversationId>(conversation_id)
            .await;
    }

    pub(crate) async fn find_pending_messages_by_conversation_id(
        &self,
        conversation_id: &[u8],
        persisted_records: impl IntoIterator<Item = Arc<MlsPendingMessage>>,
    ) -> CryptoKeystoreResult<Vec<Arc<MlsPendingMessage>>> {
        let conversation_id = conversation_id.to_vec().into();
        Ok(self.search(persisted_records, &conversation_id).await.collect())
    }

    /// Find a free proteus prekey id.
    ///
    /// Prefers an id freed by a deletion in this transaction, which is not necessarily the lowest
    /// free id overall but is quite fast to compute. Otherwise returns the lowest id which is free
    /// in the database and not already claimed by this transaction, or 1 if no prekey exists at all.
    ///
    /// NOTE: repeated calls to this method will produce the same value until and unless someone
    /// adds or deletes another prekey.
    #[cfg(feature = "proteus-keystore")]
    pub(crate) async fn free_proteus_prekey_id(&self) -> CryptoKeystoreResult<u16> {
        fn as_prekey_id(entity_id: &EntityId) -> Option<u16> {
            entity_id.primary_key::<ProteusPrekey>().map(Arc::unwrap_or_clone)
        }

        // if we can find a deleted id, we don't need to touch the DB at all;
        // that's worth a scan through the operations
        {
            let operations = self.operations.read().await;
            if let Some(free) = operations
                .delete_indices_for_type::<ProteusPrekey>()
                .find_map(|delete_idx| {
                    let entity_id = operations[delete_idx]
                        .as_delete::<ProteusPrekey>()
                        .expect("delete_indices_for_type has correct indices for delete operations");
                    operations
                        .last_upsert_idx_for(&entity_id)
                        .is_none_or(|upsert_idx| upsert_idx < delete_idx)
                        .then(|| as_prekey_id(&entity_id))?
                })
            {
                return Ok(free);
            }
        }

        // assumption: nobody is going to be assigning auto prekeys while also assigning manual prekeys, so if multiple
        // prekeys exist in our cache, they'll exist in a continuous run.
        // Technically this assumption means that this is a partial function, in the sense that it never returns
        // a wrong free prekey id, but may incorrectly report that no free prekey id exists.
        // Practically, that should never actually happen.
        let conn = self.database.conn().await;
        let db_free_id = ProteusPrekey::free_id_greater_than(&conn, 0)?;
        let Some((low, high)) = ({
            use itertools::Itertools as _;

            let operations = self.operations.read().await;
            operations.upsert_indices_for_type::<ProteusPrekey>()
                .filter(|&(entity_id, idx)|
                    operations.last_delete_idx_for(entity_id)
                        .is_none_or(|delete_idx| delete_idx < idx))
                .map(|(_entity_id, idx)| {
                    let entity = operations[idx]
                        .as_upsert::<ProteusPrekey>()
                        .expect("upsert_indices_for_type has correct data");
                    entity.id
                })
                // exclude the last resort prekey, if we happen to have set that
                .filter(|id| *id != u16::MAX)
                .minmax()
                .into_option()
        }) else {
            // no prekeys already added to the cache, so no possible conflict
            return Ok(db_free_id);
        };

        if db_free_id < low || db_free_id > high {
            // db produced a value which is outside the range of values in the cache;
            // no conflict is possible
            return Ok(db_free_id);
        }

        // the database's next free id is in the range within our cache.
        // As we assume that the cached prekeys are contiguous, we just ask the database
        // for the next one.
        ProteusPrekey::free_id_greater_than(&conn, high)
    }
}

#[cfg(all(test, feature = "proteus-keystore", not(target_os = "unknown")))]
mod tests {
    use crate::{Database, entities::ProteusPrekey};

    fn prekey(id: u16) -> ProteusPrekey {
        ProteusPrekey::from_raw(id, vec![id as u8; 8])
    }

    /// A database whose prekey table holds `1..=3`, so its own next free id is 4.
    async fn store_with_three_prekeys() -> std::sync::Arc<Database> {
        let store = Database::open_in_memory().unwrap();
        store
            .transactionally(async |tx| {
                for id in 1..=3 {
                    tx.save(prekey(id)).await?;
                }
                Ok(())
            })
            .await
            .unwrap();
        store
    }

    /// An id freed by a deletion in this transaction wins over the database's next free id.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn free_prekey_id_prefers_an_id_deleted_in_this_transaction() {
        let store = store_with_three_prekeys().await;
        let tx = store.new_transaction().await.unwrap();

        assert_eq!(
            tx.free_proteus_prekey_id().await.unwrap(),
            4,
            "with no deletions staged, the id has to come from the database"
        );

        tx.remove::<ProteusPrekey>(&2).await.unwrap();

        assert_eq!(
            tx.free_proteus_prekey_id().await.unwrap(),
            2,
            "the staged deletion frees id 2, which is preferred over the database's id 4"
        );
    }

    /// Saving a prekey under an id staged for deletion nops that deletion, so the id stops being
    /// offered and the next call moves on to the other staged deletion.
    ///
    /// The deleted set is unordered, so which of the two ids comes back first is unspecified;
    /// the property under test is that a claimed id is not handed out twice.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn claiming_a_freed_prekey_id_uncovers_the_next_one() {
        let store = store_with_three_prekeys().await;
        let tx = store.new_transaction().await.unwrap();

        tx.remove::<ProteusPrekey>(&2).await.unwrap();
        tx.remove::<ProteusPrekey>(&3).await.unwrap();

        let first = tx.free_proteus_prekey_id().await.unwrap();
        assert!(
            [2, 3].contains(&first),
            "one of the two staged deletions must be offered, got {first}"
        );
        tx.save(prekey(first)).await.unwrap();

        let second = tx.free_proteus_prekey_id().await.unwrap();
        assert_ne!(
            second, first,
            "claiming {first} must nop its deletion so it is no longer free"
        );
        assert!(
            [2, 3].contains(&second),
            "the remaining staged deletion must be offered, got {second}"
        );
        tx.save(prekey(second)).await.unwrap();

        assert_eq!(
            tx.free_proteus_prekey_id().await.unwrap(),
            4,
            "with both staged deletions claimed, the id has to come from the database again"
        );
    }

    /// The same, for a prekey which was saved and then deleted within this one transaction:
    /// the deletion is still the last operation for that id, so it must still be nop'd on re-save.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn claiming_a_prekey_id_deleted_after_being_saved_in_the_same_transaction() {
        let store = Database::open_in_memory().unwrap();
        let tx = store.new_transaction().await.unwrap();

        tx.save(prekey(1)).await.unwrap();
        tx.remove::<ProteusPrekey>(&1).await.unwrap();

        assert_eq!(
            tx.free_proteus_prekey_id().await.unwrap(),
            1,
            "the staged deletion frees id 1 again"
        );

        tx.save(prekey(1)).await.unwrap();

        assert_eq!(
            tx.free_proteus_prekey_id().await.unwrap(),
            2,
            "claiming 1 must nop its deletion, so 1 is no longer free"
        );
    }
}
