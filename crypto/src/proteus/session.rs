use core_crypto_keystore::{Database, entities::ProteusSession};
use proteus_wasm::{keys::PreKeyBundle, message::Envelope, session::Session};

use super::{ProteusCentral, ProteusConversationSession};
use crate::{KeystoreError, LeafError, ProteusError, Result};

impl ProteusCentral {
    /// Creates a new session from a prekey
    pub async fn session_from_prekey(
        &mut self,
        session_id: &str,
        key: &[u8],
    ) -> Result<&mut ProteusConversationSession> {
        let prekey = PreKeyBundle::deserialise(key).map_err(ProteusError::wrap("deserializing prekey bundle"))?;
        // Note on the `::<>` turbofish below:
        //
        // `init_from_prekey` returns an error type which is parametric over some wrapped `E`,
        // because one variant (not relevant to this particular operation) wraps an error type based
        // on a parameter of a different function entirely.
        //
        // Rust complains here, because it can't figure out what type that `E` should be. After all, it's
        // not inferrable from this function call! It is also entirely irrelevant in this case.
        //
        // We can derive two general rules about error-handling in Rust from this example:
        //
        // 1. It's better to make smaller error types where possible, encapsulating fallible operations with their own
        //    error variants, and then wrapping those errors where required, as opposed to creating giant catch-all
        //    errors. Doing so also has knock-on benefits with regard to tracing the precise origin of the error.
        // 2. One should never make an error wrapper parametric. If you need to wrap an unknown error, it's always
        //    better to wrap a `Box<dyn std::error::Error>` than to make your error type parametric. The allocation cost
        //    of creating the `Box` is utterly trivial in an error-handling path, and it avoids parametric virality.
        //    (`init_from_prekey` is itself only generic because it returns this error type with a type-parametric
        //    variant, which the function never returns.)
        //
        // In this case, we have the out of band knowledge that `ProteusErrorKind` has a `#[from]` implementation
        // for `proteus_wasm::session::Error<core_crypto_keystore::CryptoKeystoreError>` and for no other kinds
        // of session error. So we can safely say that the type of error we are meant to catch here, and
        // therefore pass in that otherwise-irrelevant type, to ensure that error handling works properly.
        //
        // Some people say that if it's stupid but it works, it's not stupid. I disagree. If it's stupid but
        // it works, that's our cue to seek out even better, non-stupid ways to get things done. I reiterate:
        // the actual type referred to in this turbofish is nothing but a magic incantation to make error
        // handling work; it has no bearing on the error retured from this function. How much better would it
        // have been if `session::Error` were not parametric and we could have avoided the turbofish entirely?
        let proteus_session = Session::init_from_prekey::<core_crypto_keystore::CryptoKeystoreError>(
            self.proteus_identity.clone(),
            prekey,
        )
        .map_err(ProteusError::wrap("initializing session from prekey"))?;

        let conversation = ProteusConversationSession {
            identifier: session_id.into(),
            session: proteus_session,
        };

        Ok(self.proteus_sessions.insert(conversation))
    }

    /// Creates a new proteus Session from a received message
    pub(crate) async fn session_from_message(
        &mut self,
        keystore: &mut Database,
        session_id: &str,
        envelope: &[u8],
    ) -> Result<(&mut ProteusConversationSession, Vec<u8>)> {
        let message = Envelope::deserialise(envelope).map_err(ProteusError::wrap("deserialising envelope"))?;
        let (session, payload) = Session::init_from_message(self.proteus_identity.clone(), keystore, &message)
            .await
            .map_err(ProteusError::wrap("initializing session from message"))?;

        let conversation = ProteusConversationSession {
            identifier: session_id.into(),
            session,
        };

        Ok((self.proteus_sessions.insert(conversation), payload))
    }

    /// Persists a session in store
    ///
    /// **Note**: This isn't usually needed as persisting sessions happens automatically when decrypting/encrypting
    /// messages and initializing Sessions
    pub(crate) async fn session_save(&mut self, keystore: &Database, session_id: &str) -> Result<()> {
        if let Some(session) = self.proteus_sessions.get_or_fetch(session_id, keystore).await? {
            Self::session_save_by_ref(keystore, session).await?;
        }
        Ok(())
    }

    pub(crate) async fn session_save_by_ref(keystore: &Database, session: &ProteusConversationSession) -> Result<()> {
        let db_session = ProteusSession {
            id: session.identifier().to_string(),
            session: session
                .session
                .serialise()
                .map_err(ProteusError::wrap("serializing session"))?,
        };
        keystore
            .save(db_session)
            .await
            .map_err(KeystoreError::wrap("saving proteus session"))?;
        Ok(())
    }

    /// Deletes a session in the store
    pub(crate) async fn session_delete(&mut self, keystore: &Database, session_id: &str) -> Result<()> {
        if keystore.remove_borrowed::<ProteusSession>(session_id).await.is_ok() {
            let _ = self.proteus_sessions.remove(session_id);
        }
        Ok(())
    }

    /// Session accessor
    pub(crate) async fn session(
        &mut self,
        session_id: &str,
        keystore: &Database,
    ) -> Result<Option<&mut ProteusConversationSession>> {
        self.proteus_sessions.get_or_fetch(session_id, keystore).await
    }

    /// Session exists
    pub(crate) async fn session_exists(&mut self, session_id: &str, keystore: &Database) -> bool {
        self.session(session_id, keystore).await.ok().flatten().is_some()
    }

    /// Proteus Session local hex-encoded fingerprint
    ///
    /// # Errors
    /// When the session is not found
    pub(crate) async fn fingerprint_local(&mut self, session_id: &str, keystore: &Database) -> Result<String> {
        let session = self
            .session(session_id, keystore)
            .await?
            .ok_or(LeafError::ConversationNotFound(session_id.as_bytes().into()))
            .map_err(ProteusError::wrap("getting session"))?;
        Ok(session.fingerprint_local())
    }

    /// Proteus Session remote hex-encoded fingerprint
    ///
    /// # Errors
    /// When the session is not found
    pub(crate) async fn fingerprint_remote(&mut self, session_id: &str, keystore: &Database) -> Result<String> {
        let session = self
            .session(session_id, keystore)
            .await?
            .ok_or(LeafError::ConversationNotFound(session_id.as_bytes().into()))
            .map_err(ProteusError::wrap("getting session"))?;
        Ok(session.fingerprint_remote())
    }
}
