//! This module contains all [super::TransactionContext] methods concerning proteus.

use super::{Error, Result, TransactionContext};
use crate::{
    RecursiveError,
    group_store::GroupStoreValue,
    proteus::{ProteusCentral, ProteusConversationSession},
};

impl TransactionContext {
    /// Initializes the proteus client
    pub async fn proteus_init(&self) -> Result<()> {
        let keystore = self.database().await?;
        let proteus_client = ProteusCentral::try_new(&keystore)
            .await
            .map_err(RecursiveError::root("creating new proteus client"))?;

        // ? Make sure the last resort prekey exists
        let _ = proteus_client
            .last_resort_prekey(&keystore)
            .await
            .map_err(RecursiveError::root("getting last resort prekey"))?;

        let mutex = self.proteus_central().await?;
        let mut guard = mutex.lock().await;
        *guard = Some(proteus_client);
        Ok(())
    }

    /// Reloads the sessions from the key store
    ///
    /// Warning: The Proteus client **MUST** be initialized with [TransactionContext::proteus_init] first or it will do
    /// nothing
    pub async fn proteus_reload_sessions(&self) -> Result<()> {
        let arc = self.proteus_central().await?;
        let mut mutex = arc.lock().await;
        let Some(proteus) = mutex.as_mut() else { return Ok(()) };
        let keystore = self.database().await?;
        proteus
            .reload_sessions(&keystore)
            .await
            .map_err(RecursiveError::root("reloading proteus session"))
            .map_err(Into::into)
    }

    /// Creates a proteus session from a prekey
    ///
    /// Warning: The Proteus client **MUST** be initialized with [TransactionContext::proteus_init] first or an error
    /// will be returned
    pub async fn proteus_session_from_prekey(
        &self,
        session_id: &str,
        prekey: &[u8],
    ) -> Result<GroupStoreValue<ProteusConversationSession>> {
        let arc = self.proteus_central().await?;
        let mut mutex = arc.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let keystore = self.database().await?;
        let session = proteus
            .session_from_prekey(session_id, prekey)
            .await
            .map_err(RecursiveError::root("creating proteus session from prekey"))?;
        ProteusCentral::session_save_by_ref(&keystore, session.clone())
            .await
            .map_err(RecursiveError::root("saving proteus session by ref"))?;

        Ok(session)
    }

    /// Creates a proteus session from a Proteus message envelope
    ///
    /// Warning: The Proteus client **MUST** be initialized with [TransactionContext::proteus_init] first or an error
    /// will be returned
    pub async fn proteus_session_from_message(
        &self,
        session_id: &str,
        envelope: &[u8],
    ) -> Result<(GroupStoreValue<ProteusConversationSession>, Vec<u8>)> {
        let arc = self.proteus_central().await?;
        let mut mutex = arc.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let mut keystore = self.database().await?;
        let (session, message) = proteus
            .session_from_message(&mut keystore, session_id, envelope)
            .await
            .map_err(RecursiveError::root("creating proteus sesseion from message"))?;
        ProteusCentral::session_save_by_ref(&keystore, session.clone())
            .await
            .map_err(RecursiveError::root("saving proteus session by ref"))?;

        Ok((session, message))
    }

    /// Saves a proteus session in the keystore
    ///
    /// Warning: The Proteus client **MUST** be initialized with [TransactionContext::proteus_init] first or an error
    /// will be returned
    pub async fn proteus_session_save(&self, session_id: &str) -> Result<()> {
        let arc = self.proteus_central().await?;
        let mut mutex = arc.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let keystore = self.database().await?;
        proteus
            .session_save(&keystore, session_id)
            .await
            .map_err(RecursiveError::root("saving proteus session"))
            .map_err(Into::into)
    }

    /// Deletes a proteus session from the keystore
    ///
    /// Warning: The Proteus client **MUST** be initialized with [TransactionContext::proteus_init] first or an error
    /// will be returned
    pub async fn proteus_session_delete(&self, session_id: &str) -> Result<()> {
        let arc = self.proteus_central().await?;
        let mut mutex = arc.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let keystore = self.database().await?;
        proteus
            .session_delete(&keystore, session_id)
            .await
            .map_err(RecursiveError::root("deleting proteus session"))
            .map_err(Into::into)
    }

    /// Proteus session accessor
    ///
    /// Warning: The Proteus client **MUST** be initialized with [TransactionContext::proteus_init] first or an error
    /// will be returned
    pub async fn proteus_session(
        &self,
        session_id: &str,
    ) -> Result<Option<GroupStoreValue<ProteusConversationSession>>> {
        let arc = self.proteus_central().await?;
        let mut mutex = arc.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let keystore = self.database().await?;
        proteus
            .session(session_id, &keystore)
            .await
            .map_err(RecursiveError::root("getting proteus session"))
            .map_err(Into::into)
    }

    /// Proteus session exists
    ///
    /// Warning: The Proteus client **MUST** be initialized with [TransactionContext::proteus_init] first or an error
    /// will be returned
    pub async fn proteus_session_exists(&self, session_id: &str) -> Result<bool> {
        let arc = self.proteus_central().await?;
        let mut mutex = arc.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let keystore = self.database().await?;
        Ok(proteus.session_exists(session_id, &keystore).await)
    }

    /// Decrypts a proteus message envelope
    ///
    /// Warning: The Proteus client **MUST** be initialized with [TransactionContext::proteus_init] first or an error
    /// will be returned
    pub async fn proteus_decrypt(&self, session_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let arc = self.proteus_central().await?;
        let mut mutex = arc.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let mut keystore = self.database().await?;
        proteus
            .decrypt(&mut keystore, session_id, ciphertext)
            .await
            .map_err(RecursiveError::root("decrypting proteus message"))
            .map_err(Into::into)
    }

    /// Encrypts proteus message for a given session ID
    ///
    /// Warning: The Proteus client **MUST** be initialized with [TransactionContext::proteus_init] first or an error
    /// will be returned
    pub async fn proteus_encrypt(&self, session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let arc = self.proteus_central().await?;
        let mut mutex = arc.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let mut keystore = self.database().await?;
        proteus
            .encrypt(&mut keystore, session_id, plaintext)
            .await
            .map_err(RecursiveError::root("encrypting proteus message"))
            .map_err(Into::into)
    }

    /// Encrypts a proteus message for several sessions ID. This is more efficient than other methods as the calls are
    /// batched. This also reduces the rountrips when crossing over the FFI
    ///
    /// Warning: The Proteus client **MUST** be initialized with [TransactionContext::proteus_init] first or an error
    /// will be returned
    pub async fn proteus_encrypt_batched(
        &self,
        sessions: &[impl AsRef<str>],
        plaintext: &[u8],
    ) -> Result<std::collections::HashMap<String, Vec<u8>>> {
        let arc = self.proteus_central().await?;
        let mut mutex = arc.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let mut keystore = self.database().await?;
        proteus
            .encrypt_batched(&mut keystore, sessions, plaintext)
            .await
            .map_err(RecursiveError::root("batch encrypting proteus message"))
            .map_err(Into::into)
    }

    /// Creates a new Proteus prekey and returns the CBOR-serialized version of the prekey bundle
    ///
    /// Warning: The Proteus client **MUST** be initialized with [TransactionContext::proteus_init] first or an error
    /// will be returned
    pub async fn proteus_new_prekey(&self, prekey_id: u16) -> Result<Vec<u8>> {
        let arc = self.proteus_central().await?;
        let mut mutex = arc.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let keystore = self.database().await?;
        proteus
            .new_prekey(prekey_id, &keystore)
            .await
            .map_err(RecursiveError::root("new proteus prekey"))
            .map_err(Into::into)
    }

    /// Creates a new Proteus prekey with an automatically incremented ID and returns the CBOR-serialized version of the
    /// prekey bundle
    ///
    /// Warning: The Proteus client **MUST** be initialized with [TransactionContext::proteus_init] first or an error
    /// will be returned
    pub async fn proteus_new_prekey_auto(&self) -> Result<(u16, Vec<u8>)> {
        let arc = self.proteus_central().await?;
        let mut mutex = arc.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let keystore = self.database().await?;
        proteus
            .new_prekey_auto(&keystore)
            .await
            .map_err(RecursiveError::root("proteus new prekey auto"))
            .map_err(Into::into)
    }

    /// Returns the last resort prekey
    pub async fn proteus_last_resort_prekey(&self) -> Result<Vec<u8>> {
        let arc = self.proteus_central().await?;
        let mut mutex = arc.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let keystore = self.database().await?;

        proteus
            .last_resort_prekey(&keystore)
            .await
            .map_err(RecursiveError::root("getting proteus last resort prekey"))
            .map_err(Into::into)
    }

    /// Returns the proteus last resort prekey id (u16::MAX = 65535)
    pub fn proteus_last_resort_prekey_id() -> u16 {
        ProteusCentral::last_resort_prekey_id()
    }

    /// Returns the proteus identity's public key fingerprint
    ///
    /// Warning: The Proteus client **MUST** be initialized with [TransactionContext::proteus_init] first or an error
    /// will be returned
    pub async fn proteus_fingerprint(&self) -> Result<String> {
        let arc = self.proteus_central().await?;
        let mut mutex = arc.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        Ok(proteus.fingerprint())
    }

    /// Returns the proteus identity's public key fingerprint
    ///
    /// Warning: The Proteus client **MUST** be initialized with [TransactionContext::proteus_init] first or an error
    /// will be returned
    pub async fn proteus_fingerprint_local(&self, session_id: &str) -> Result<String> {
        let arc = self.proteus_central().await?;
        let mut mutex = arc.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let keystore = self.database().await?;
        proteus
            .fingerprint_local(session_id, &keystore)
            .await
            .map_err(RecursiveError::root("getting proteus fingerprint local"))
            .map_err(Into::into)
    }

    /// Returns the proteus identity's public key fingerprint
    ///
    /// Warning: The Proteus client **MUST** be initialized with [TransactionContext::proteus_init] first or an error
    /// will be returned
    pub async fn proteus_fingerprint_remote(&self, session_id: &str) -> Result<String> {
        let arc = self.proteus_central().await?;
        let mut mutex = arc.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let keystore = self.database().await?;
        proteus
            .fingerprint_remote(session_id, &keystore)
            .await
            .map_err(RecursiveError::root("geeting proteus fingerprint remote"))
            .map_err(Into::into)
    }
}
