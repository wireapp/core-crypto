use std::sync::Arc;

use proteus_wasm::{keys::IdentityKeyPair, message::Envelope, session::Session};

use crate::{ProteusError, Result};

/// Proteus session IDs, it seems it's basically a string
pub type SessionIdentifier = String;

/// Proteus Session wrapper, that contains the identifier and the associated proteus Session
#[derive(Debug)]
pub struct ProteusConversationSession {
    pub(crate) identifier: SessionIdentifier,
    pub(crate) session: Session<Arc<IdentityKeyPair>>,
}

impl ProteusConversationSession {
    /// Encrypts a message for this Proteus session
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.session
            .encrypt(plaintext)
            .and_then(|e| e.serialise())
            .map_err(ProteusError::wrap("encrypting message for proteus session"))
            .map_err(Into::into)
    }

    /// Decrypts a message for this Proteus session
    pub async fn decrypt(&mut self, store: &mut core_crypto_keystore::Database, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let envelope = Envelope::deserialise(ciphertext).map_err(ProteusError::wrap("deserializing envelope"))?;
        self.session
            .decrypt(store, &envelope)
            .await
            .map_err(ProteusError::wrap("decrypting message for proteus session"))
            .map_err(Into::into)
    }

    /// Returns the session identifier
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Returns the public key fingerprint of the local identity (= self identity)
    pub fn fingerprint_local(&self) -> String {
        self.session.local_identity().fingerprint()
    }

    /// Returns the public key fingerprint of the remote identity (= client you're communicating with)
    pub fn fingerprint_remote(&self) -> String {
        self.session.remote_identity().fingerprint()
    }
}
