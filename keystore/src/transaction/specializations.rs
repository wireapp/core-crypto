//! These methods are specialized for performing certain entity-specific queries.

use super::dynamic_dispatch::EntityId;
#[cfg(feature = "proteus-keystore")]
use crate::entities::ProteusPrekey;
use crate::{
    CryptoKeystoreResult,
    entities::{ConversationId, MlsPendingMessage},
    transaction::Transaction,
};

impl Transaction {
    pub(crate) async fn remove_pending_messages_by_conversation_id(&self, conversation_id: impl AsRef<[u8]> + Send) {
        let conversation_id = conversation_id.as_ref().to_vec().into();
        self.bulk_remove::<MlsPendingMessage, ConversationId>(conversation_id)
            .await;
    }

    pub(crate) async fn find_pending_messages_by_conversation_id(
        &self,
        conversation_id: &[u8],
        persisted_records: impl IntoIterator<Item = MlsPendingMessage>,
    ) -> CryptoKeystoreResult<Vec<MlsPendingMessage>> {
        let conversation_id = conversation_id.to_vec().into();
        Ok(self.search(persisted_records, &conversation_id).await.collect())
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

        // if we can find a deleted id, we don't need to touch the DB at all;
        // that's worth a scan through the operations
        {
            let mut candidates = Vec::new();

            let operations = self.operations.read().await;
            for operation in operations.iter() {
                if let Some(deleted) = operation.as_delete::<ProteusPrekey>()
                    && let Some(prekey) = as_prekey_id(&deleted)
                {
                    candidates.push(prekey);
                }

                if let Some(inserted) = operation.as_upsert::<ProteusPrekey>() {
                    let id = inserted.id;
                    if let Some(position) = candidates.iter().position(|candidate| *candidate == id) {
                        // oops, we're reusing that prekey id already
                        candidates.swap_remove(position);
                    }
                }
            }

            if let Some(id) = candidates.first() {
                return Ok(*id);
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
            operations.iter().filter_map(|operation| operation.as_upsert::<ProteusPrekey>())
                .map(|prekey| prekey.id)
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
