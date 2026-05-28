//! The MLS conversation cache keeps deserialised conversations in memory to
//! reduce DB / deserialisation latency.

use std::sync::Arc;

use core_crypto_keystore::{Database, entities::PersistedMlsGroup, traits::FetchFromDatabase};
use schnellru::{ByLength, LruMap};

use super::conversation::{ConversationId, ConversationIdRef};
use crate::{
    ImmutableDatabase, KeystoreError, RecursiveError, Result, Session, mls::conversation::ImmutableConversation,
};

/// LRU cache of live [`ImmutableConversation`]s, keyed by conversation id.
///
/// On a cache miss, [`Self::get_or_fetch`] loads the persisted MLS group state
/// from the keystore and deserialises it. Persisted-but-inactive groups are
/// treated as missing.
///
/// **Rollback invariant:** because the cache outlives any single transaction,
/// [`Self::clear`] must be called when a transaction is rolled back. Otherwise,
/// in-memory state mutated during the aborted transaction would diverge from
/// the keystore.
pub(crate) struct ConversationCache {
    // `Arc<_>` is required here so that `ConversationGuard` can
    // hold a handle that outlives any single cache lookup.
    entries: LruMap<ConversationId, Arc<ImmutableConversation>, ByLength>,
}

impl MlsConversationCache {
    /// Maximum number of conversations kept in memory before LRU eviction.
    const CAPACITY: u32 = 200;

    pub(crate) fn new() -> Self {
        Self {
            entries: LruMap::new(ByLength::new(Self::CAPACITY)),
        }
    }

    /// Returns the cached conversation if present; otherwise loads it from the keystore.
    ///
    /// `Ok(None)` means the conversation is neither cached nor persisted.
    /// Groups which are inactive (i.e. those from which this client has been removed)
    /// are treated as if they are missing and are not cached.
    pub(crate) async fn get_or_fetch(
        &mut self,
        id: &ConversationIdRef,
        keystore: &Database,
        session: Session,
    ) -> Result<Option<Arc<ImmutableConversation>>> {
        if let Some(entry) = self.entries.get(id) {
            return Ok(Some(entry.clone()));
        }

        let Some(conversation) =
            ImmutableConversation::load(session, id)
                .await
                .map_err(RecursiveError::mls_conversation(
                    "fetching persisted mls group from keystore",
                ))?
        else {
            return Ok(None);
        };

        if !conversation.group().await.is_active() {
            keystore
                .remove_borrowed::<PersistedMlsGroup>(id.as_ref())
                .await
                .map_err(KeystoreError::wrap("deleting inactive conversation from keystore"))?;
            return Ok(None);
        }

        let key = conversation.id().to_owned();
        let handle = Arc::new(conversation);
        self.entries.insert(key, handle.clone());
        Ok(Some(handle))
    }

    /// Returns `true` when a conversation with the given ID exists in the cache or the database.
    ///
    /// Does not load the converation into the cache or change the order of the LRU cache.
    pub(crate) async fn exists(&self, id: &ConversationIdRef, database: &ImmutableDatabase) -> Result<bool> {
        if self.entries.peek(id).is_some() {
            return Ok(true);
        }
        database
            .get_borrowed::<PersistedMlsGroup>(id.as_ref())
            .await
            .map(|maybe_entry| maybe_entry.is_some())
            .map_err(KeystoreError::wrap("checking for existence of mls group"))
            .map_err(Into::into)
    }

    /// Inserts a freshly-created conversation and returns the cached handle.
    pub(crate) fn insert(&mut self, conversation: ImmutableConversation) -> Arc<ImmutableConversation> {
        let key = conversation.id().to_owned();
        let handle = Arc::new(conversation);
        self.entries.insert(key, handle.clone());
        handle
    }

    /// Removes an entry from the cache, if present.
    pub(crate) fn remove(&mut self, id: &ConversationIdRef) -> Option<Arc<ImmutableConversation>> {
        self.entries.remove(id)
    }

    /// Empties the cache.
    ///
    /// Must be called on transaction rollback to avoid serving
    /// stale state that was mutated in-memory but never persisted.
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }
}

impl std::fmt::Debug for MlsConversationCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsConversationCache")
            .field("len", &self.entries.len())
            .finish_non_exhaustive()
    }
}
