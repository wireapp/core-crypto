use std::collections::HashMap;

use core_crypto_keystore::Database;

use super::ProteusCentral;
use crate::{LeafError, ProteusError, Result};

impl ProteusCentral {
    /// Decrypt a proteus message for an already existing session
    /// Note: This cannot be used for handshake messages, see [ProteusCentral::session_from_message]
    pub(crate) async fn decrypt(
        &mut self,
        keystore: &mut Database,
        session_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let session = self
            .proteus_sessions
            .get_or_fetch(session_id, keystore)
            .await?
            .ok_or(LeafError::ConversationNotFound(session_id.as_bytes().into()))
            .map_err(ProteusError::wrap("getting session"))?;

        let plaintext = session.decrypt(keystore, ciphertext).await?;
        Self::session_save_by_ref(keystore, session).await?;

        Ok(plaintext)
    }

    /// Encrypt a message for a session
    pub(crate) async fn encrypt(
        &mut self,
        keystore: &mut Database,
        session_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let session = self
            .session(session_id, keystore)
            .await?
            .ok_or(LeafError::ConversationNotFound(session_id.as_bytes().into()))
            .map_err(ProteusError::wrap("getting session"))?;

        let ciphertext = session.encrypt(plaintext)?;
        Self::session_save_by_ref(keystore, session).await?;

        Ok(ciphertext)
    }

    /// Encrypts a message for a list of sessions
    /// This is mainly used for conversations with multiple clients, this allows to minimize FFI roundtrips
    pub(crate) async fn encrypt_batched(
        &mut self,
        keystore: &mut Database,
        sessions: &[impl AsRef<str>],
        plaintext: &[u8],
    ) -> Result<HashMap<String, Vec<u8>>> {
        // unfortunately we can't write this as an iterator chain because
        // the operations are async
        let mut acc = HashMap::new();
        for session_id in sessions {
            if let Some(session) = self.session(session_id.as_ref(), keystore).await? {
                let identifier = session.identifier.clone();
                let ciphertext = session.encrypt(plaintext)?;
                Self::session_save_by_ref(keystore, session).await?;
                acc.insert(identifier, ciphertext);
            }
        }
        Ok(acc)
    }
}

#[cfg(test)]
mod tests {
    use core_crypto_keystore::{ConnectionType, DatabaseKey};

    use super::*;
    use crate::test_utils::{proteus_utils::*, *};

    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn can_talk_with_proteus() {
        #[cfg(not(target_os = "unknown"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_os = "unknown")]
        let (path, _) = tmp_db_file();

        let session_id = uuid::Uuid::new_v4().hyphenated().to_string();

        let key = DatabaseKey::generate();
        let mut keystore = core_crypto_keystore::Database::open(ConnectionType::Persistent(&path), &key)
            .await
            .unwrap();
        keystore.new_transaction().await.unwrap();

        let mut alice = ProteusCentral::try_new(&keystore).await.unwrap();

        let mut bob = CryptoboxLike::init();
        let bob_pk_bundle = bob.new_prekey();

        alice
            .session_from_prekey(&session_id, &bob_pk_bundle.serialise().unwrap())
            .await
            .unwrap();

        let message = b"Hello world";

        let encrypted = alice.encrypt(&mut keystore, &session_id, message).await.unwrap();
        let decrypted = bob.decrypt(&session_id, &encrypted).await;
        assert_eq!(decrypted, message);

        let encrypted = bob.encrypt(&session_id, message);
        let decrypted = alice.decrypt(&mut keystore, &session_id, &encrypted).await.unwrap();
        assert_eq!(decrypted, message);

        keystore.commit_transaction().await.unwrap();
        keystore.wipe().await.unwrap();
        #[cfg(not(target_os = "unknown"))]
        drop(db_file);
    }
}
