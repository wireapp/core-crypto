//! The session cache keeps Proteus sessions in memory to reduce DB / deserialization latency.

use std::sync::Arc;

use core_crypto_keystore::{Database, entities::ProteusSession, traits::FetchFromDatabase as _};
use proteus_wasm::{keys::IdentityKeyPair, session::Session};
use schnellru::{ByLength, LruMap};

use super::{ProteusConversationSession, SessionIdentifier};
use crate::{KeystoreError, ProteusError, Result};

/// LRU cache of live [`ProteusConversationSession`]s, keyed by session id.
///
/// On a cache miss, [`Self::get_or_fetch`] loads the encoded session from the
/// keystore and deserialises it using the configured identity. Cache entries
/// are owned by the cache; callers operate on `&mut` references obtained via
/// the cache's methods and so cannot hold a reference across cache mutations.
pub(crate) struct ProteusSessionCache {
    entries: LruMap<SessionIdentifier, ProteusConversationSession, ByLength>,
    identity: Arc<IdentityKeyPair>,
}

impl ProteusSessionCache {
    /// Maximum number of sessions kept in memory before LRU eviction kicks in.
    const CAPACITY: u32 = 200;

    pub(crate) fn new(identity: Arc<IdentityKeyPair>) -> Self {
        Self {
            entries: LruMap::new(ByLength::new(Self::CAPACITY)),
            identity,
        }
    }

    /// Returns a mutable reference to the requested session.
    ///
    /// If the session is present in the cache, returns it immediately.
    /// Otherwise, loads the session from the database, adds it to the cache,
    /// and returns the appropriate reference.
    ///
    /// `Ok(None)` means the session is neither cached nor persisted.
    pub(crate) async fn get_or_fetch(
        &mut self,
        id: &str,
        keystore: &Database,
    ) -> Result<Option<&mut ProteusConversationSession>> {
        if self.entries.peek(id).is_some() {
            return Ok(self.entries.get(id));
        }

        let Some(raw) = keystore
            .get_borrowed::<ProteusSession>(id)
            .await
            .map_err(KeystoreError::wrap("fetching proteus session from keystore"))?
        else {
            return Ok(None);
        };

        let session = Session::deserialise(self.identity.clone(), &raw.session)
            .map_err(ProteusError::wrap("deserialising proteus session"))?;
        let key = raw.id.clone();
        let conversation = ProteusConversationSession {
            identifier: key.clone(),
            session,
        };
        self.entries.insert(key.clone(), conversation);
        Ok(self.entries.get(&key))
    }

    /// Inserts a freshly-created session and returns a mutable reference to it.
    pub(crate) fn insert(&mut self, session: ProteusConversationSession) -> &mut ProteusConversationSession {
        let key = session.identifier.clone();
        self.entries.insert(key.clone(), session);
        self.entries
            .get(&key)
            .expect("the entry we just inserted should still be present")
    }

    /// Removes an entry from the cache, if present.
    pub(crate) fn remove(&mut self, id: &str) -> Option<ProteusConversationSession> {
        self.entries.remove(id)
    }
}

impl std::fmt::Debug for ProteusSessionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProteusSessionCache")
            .field("len", &self.entries.len())
            .finish_non_exhaustive()
    }
}
