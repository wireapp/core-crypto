use std::collections::HashMap;

use core_crypto_keystore::Transaction;

use super::ProteusCentral;
use crate::{LeafError, ProteusError, Result};

impl ProteusCentral {
    /// Decrypt a proteus message for an already existing session
    /// Note: This cannot be used for handshake messages, see [ProteusCentral::session_from_message]
    pub(crate) async fn decrypt(
        &mut self,
        transaction: &Transaction,
        session_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let session = self
            .proteus_sessions
            .get_or_fetch(session_id, transaction)
            .await?
            .ok_or(LeafError::ConversationNotFound(session_id.as_bytes().into()))
            .map_err(ProteusError::wrap("getting session"))?;

        let plaintext = session.decrypt(transaction, ciphertext).await?;
        Self::session_save_by_ref(transaction, session).await?;

        Ok(plaintext)
    }

    /// Encrypt a message for a session
    pub(crate) async fn encrypt(
        &mut self,
        transaction: &Transaction,
        session_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let session = self
            .session(session_id, transaction)
            .await?
            .ok_or(LeafError::ConversationNotFound(session_id.as_bytes().into()))
            .map_err(ProteusError::wrap("getting session"))?;

        let ciphertext = session.encrypt(plaintext)?;
        Self::session_save_by_ref(transaction, session).await?;

        Ok(ciphertext)
    }

    /// Encrypts a message for a list of sessions
    /// This is mainly used for conversations with multiple clients, this allows to minimize FFI roundtrips
    pub(crate) async fn encrypt_batched(
        &mut self,
        transaction: &Transaction,
        sessions: &[impl AsRef<str>],
        plaintext: &[u8],
    ) -> Result<HashMap<String, Vec<u8>>> {
        // unfortunately we can't write this as an iterator chain because
        // the operations are async
        let mut acc = HashMap::new();
        for session_id in sessions {
            if let Some(session) = self.session(session_id.as_ref(), transaction).await? {
                let identifier = session.identifier.clone();
                let ciphertext = session.encrypt(plaintext)?;
                Self::session_save_by_ref(transaction, session).await?;
                acc.insert(identifier, ciphertext);
            }
        }
        Ok(acc)
    }
}

#[cfg(test)]
mod tests {
    use core_crypto_keystore::DatabaseKey;

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
        let keystore = core_crypto_keystore::Database::open(&path, &key).await.unwrap();
        let tx = keystore.new_transaction().await.unwrap();

        let mut alice = ProteusCentral::try_new(&tx).await.unwrap();

        let mut bob = CryptoboxLike::init();
        let bob_pk_bundle = bob.new_prekey();

        alice
            .session_from_prekey(&session_id, &bob_pk_bundle.serialise().unwrap())
            .await
            .unwrap();

        let message = b"Hello world";

        let encrypted = alice.encrypt(&tx, &session_id, message).await.unwrap();
        let decrypted = bob.decrypt(&session_id, &encrypted).await;
        assert_eq!(decrypted, message);

        let encrypted = bob.encrypt(&session_id, message);
        let decrypted = alice.decrypt(&tx, &session_id, &encrypted).await.unwrap();
        assert_eq!(decrypted, message);

        tx.commit().await.unwrap();
        #[cfg(not(target_os = "unknown"))]
        drop(db_file);
    }
}
