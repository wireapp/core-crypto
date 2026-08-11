//! The session cache keeps Proteus sessions in memory to reduce DB / deserialization latency.

use std::sync::Arc;

use core_crypto_keystore::entities::ProteusSession;
use core_crypto_keystore::traits::FetchFromDatabase;
use proteus_wasm::keys::IdentityKeyPair;
use proteus_wasm::session::Session;
use schnellru::ByLength;
use schnellru::LruMap;

use super::ProteusConversationSession;
use super::SessionIdentifier;
use crate::KeystoreError;
use crate::ProteusError;
use crate::Result;

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
        keystore: &impl FetchFromDatabase,
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

#[cfg(test)]
mod tests {
    use core_crypto_keystore::DatabaseKey;

    use crate::proteus::ProteusCentral;
    use crate::test_utils::proteus_utils::*;
    use crate::test_utils::*;

    /// A session persisted by one [`ProteusCentral`] must be loaded by the next one over the same
    /// database, never silently replaced by a freshly established session.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn persisted_session_is_loaded_rather_than_regenerated() {
        let (path, _db_file) = tmp_db_file();
        let key = DatabaseKey::generate();
        let session_id = uuid::Uuid::new_v4().hyphenated().to_string();

        let mut bob = CryptoboxLike::init();

        // Establish a session, advance it in both directions, and persist it.
        let (expected_fingerprint, expected_state) = {
            let keystore = core_crypto_keystore::Database::open(&path, &key).await.unwrap();
            let tx = keystore.new_transaction().await.unwrap();
            let mut alice = ProteusCentral::try_new(&tx).await.unwrap();

            let alice_prekey_bundle = alice.new_prekey(1, &tx).await.unwrap();
            bob.init_session_from_prekey_bundle(&session_id, &alice_prekey_bundle);

            let from_bob = bob.encrypt(&session_id, b"hello alice");
            let (_, decrypted) = alice.session_from_message(&tx, &session_id, &from_bob).await.unwrap();
            assert_eq!(b"hello alice", decrypted.as_slice());

            // `encrypt` persists the session, which `session_from_message` on its own does not.
            let from_alice = alice.encrypt(&tx, &session_id, b"hello bob").await.unwrap();
            assert_eq!(b"hello bob", bob.decrypt(&session_id, &from_alice).await.as_slice());

            let session = alice.session(&session_id, &tx).await.unwrap().unwrap();
            tx.commit().await.unwrap();

            (session.fingerprint_remote(), session.session.serialise().unwrap())
        };

        // A new `ProteusCentral` over the same database starts with an empty cache, so this is the
        // first lookup which has to come from the keystore.
        let keystore = core_crypto_keystore::Database::open(&path, &key).await.unwrap();
        let tx = keystore.new_transaction().await.unwrap();
        let mut alice = ProteusCentral::try_new(&tx).await.unwrap();

        {
            let session = alice
                .proteus_sessions
                .get_or_fetch(&session_id, &tx)
                .await
                .unwrap()
                .expect("the persisted session should be found in the keystore");

            assert_eq!(
                expected_fingerprint,
                session.fingerprint_remote(),
                "the loaded session should have the same peer as the persisted one"
            );
            assert_eq!(
                expected_state,
                session.session.serialise().unwrap(),
                "the loaded session should carry the persisted state, not a fresh handshake"
            );
        }

        // The strongest form of the claim: the reloaded session can still decrypt on the ratchet
        // bob has been advancing all along, which a regenerated session could not do.
        let from_bob = bob.encrypt(&session_id, b"still talking");
        let decrypted = alice.decrypt(&tx, &session_id, &from_bob).await.unwrap();
        assert_eq!(b"still talking", decrypted.as_slice());
    }
}
