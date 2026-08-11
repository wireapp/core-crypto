//! These methods are specialized for performing certain entity-specific queries.

use std::borrow::Cow;
use std::sync::Arc;

use super::dynamic_dispatch::EntityId;
use crate::CryptoKeystoreResult;
use crate::entities::MlsPendingMessage;
#[cfg(feature = "proteus-keystore")]
use crate::entities::ProteusPrekey;
use crate::transaction::Transaction;

impl Transaction {
    pub(crate) async fn remove_pending_messages_by_conversation_id(&self, conversation_id: impl AsRef<[u8]> + Send) {
        let conversation_id = conversation_id.as_ref();

        {
            let mut cache_guard = self.cache.write().await;
            cache_guard.retain(|_entity_id, entity| {
                let Some(pending_message) = entity.downcast::<MlsPendingMessage>() else {
                    return true;
                };
                pending_message.foreign_id != conversation_id
            });
        }

        let mut deleted_set = self.deleted.write().await;
        deleted_set.insert(
            EntityId::from_key::<MlsPendingMessage>(conversation_id.into())
                .expect("mls pending messages are proper entities which can be parsed"),
        );
    }

    pub(crate) async fn find_pending_messages_by_conversation_id(
        &self,
        conversation_id: &[u8],
        persisted_records: impl IntoIterator<Item = MlsPendingMessage>,
    ) -> CryptoKeystoreResult<Vec<MlsPendingMessage>> {
        let persisted_records = persisted_records.into_iter().map(Cow::Owned);

        let cached_records = self.find_all_in_cache::<MlsPendingMessage>().await;
        let cached_records = cached_records
            .iter()
            .filter(|pending_message| pending_message.foreign_id == conversation_id)
            .map(Arc::as_ref)
            .map(Cow::Borrowed);

        let merged_records = self.merge_records(cached_records, persisted_records).await;
        Ok(merged_records)
    }

    /// Find a free proteus prekey id.
    ///
    /// Prefers an id freed by a deletion in this transaction, which is not necessarily the lowest
    /// free id overall but is quite fast to compute. Otherwise returns the lowest id which is free
    /// in the database and not already claimed by this transaction, or 1 if no prekey exists at all.
    #[cfg(feature = "proteus-keystore")]
    pub(crate) async fn free_proteus_prekey_id(&self) -> CryptoKeystoreResult<u16> {
        fn as_prekey_id(entity_id: &EntityId) -> Option<u16> {
            entity_id.matches_type::<ProteusPrekey>().then(|| {
                entity_id
                    .primary_key::<ProteusPrekey>()
                    .expect("primary keys in a cache table have valid byte encoding")
            })
        }

        // an id can never be in both the cache and the deleted set: `save` un-deletes, `remove`
        // un-caches. So a deleted id needs no conflict check.
        {
            let guard = self.deleted.read().await;
            if let Some(id) = guard.iter().filter_map(as_prekey_id).min() {
                return Ok(id);
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

            let guard = self.cache.read().await;
            guard
                .keys()
                .filter_map(as_prekey_id)
                // exclude the last resort prekey, if we happen to be setting that
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
