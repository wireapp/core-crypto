use crate::{CoreCryptoContext, CoreCryptoResult, ProteusAutoPrekeyBundle, proteus_impl};

type BatchedEncryptedMessages = std::collections::HashMap<String, Vec<u8>>;

#[uniffi::export]
impl CoreCryptoContext {
    /// Initializes the Proteus client.
    ///
    /// In general this method should be called at most once per core-crypto instance.
    /// Calling it multiple times with the same parameters should silently succeed, but this is not
    /// a supported or tested mode of operation.
    /// Calling it multiple times with varying parameters might succeed, but this is not a supported or tested mode of
    /// operation.
    pub async fn proteus_init(&self) -> CoreCryptoResult<()> {
        proteus_impl!({
            self.inner.proteus_init().await?;
            Ok(())
        })
    }

    /// Creates a new Proteus session from the given prekey bundle bytes, stored under the given session ID.
    pub async fn proteus_session_from_prekey(&self, session_id: String, prekey: Vec<u8>) -> CoreCryptoResult<()> {
        proteus_impl!({
            self.inner.proteus_session_from_prekey(&session_id, &prekey).await?;
            Ok(())
        })
    }

    /// Creates a new Proteus session from an incoming encrypted message, returning the decrypted message payload.
    pub async fn proteus_session_from_message(&self, session_id: &str, envelope: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl!({
            let payload = self.inner.proteus_session_from_message(session_id, &envelope).await?;
            Ok(payload)
        })
    }

    /// Saves the Proteus session with the given ID to the keystore.
    ///
    /// Note: this is not usually needed, as sessions are persisted automatically when
    /// decrypting or encrypting messages and when initializing sessions.
    pub async fn proteus_session_save(&self, session_id: &str) -> CoreCryptoResult<()> {
        proteus_impl!({ self.inner.proteus_session_save(session_id).await.map_err(Into::into) })
    }

    /// Deletes the Proteus session with the given ID from local storage.
    pub async fn proteus_session_delete(&self, session_id: String) -> CoreCryptoResult<()> {
        proteus_impl!({ self.inner.proteus_session_delete(&session_id).await.map_err(Into::into) })
    }

    /// Returns true if a Proteus session with the given ID exists in local storage.
    pub async fn proteus_session_exists(&self, session_id: &str) -> CoreCryptoResult<bool> {
        proteus_impl!({ self.inner.proteus_session_exists(session_id).await.map_err(Into::into) })
    }

    /// Decrypts a Proteus ciphertext in the given session, returning the plaintext.
    pub async fn proteus_decrypt(&self, session_id: &str, ciphertext: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl!({
            self.inner
                .proteus_decrypt(session_id, &ciphertext)
                .await
                .map_err(Into::into)
        })
    }

    /// Decrypt a message whether or not the proteus session already exists, and saves the session.
    ///
    /// This is intended to replace simple usages of `proteusDecrypt`.
    ///
    /// However, when decrypting large numbers of messages in a single session, the existing methods
    /// may be more efficient.
    pub async fn proteus_decrypt_safe(&self, session_id: &str, ciphertext: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl!({
            let decrypted_message = if self.proteus_session_exists(session_id).await? {
                self.proteus_decrypt(session_id, ciphertext).await?
            } else {
                self.proteus_session_from_message(session_id, ciphertext).await?
            };
            self.proteus_session_save(session_id).await?;
            Ok(decrypted_message)
        })
    }

    /// Encrypts a plaintext message in the given Proteus session.
    pub async fn proteus_encrypt(&self, session_id: String, plaintext: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl!({
            self.inner
                .proteus_encrypt(&session_id, &plaintext)
                .await
                .map_err(Into::into)
        })
    }

    /// Encrypts a plaintext message in multiple Proteus sessions, returning a map from session ID to ciphertext.
    pub async fn proteus_encrypt_batched(
        &self,
        sessions: Vec<String>,
        plaintext: Vec<u8>,
    ) -> CoreCryptoResult<BatchedEncryptedMessages> {
        proteus_impl!({
            let batched_encrypted_messages = self.inner.proteus_encrypt_batched(&sessions, &plaintext).await?;
            Ok(batched_encrypted_messages)
        })
    }

    /// Creates a new Proteus prekey with the given ID and returns its CBOR-serialized bundle.
    ///
    /// Warning: the Proteus client must be initialized with `proteus_init` first or an error will be returned.
    pub async fn proteus_new_prekey(&self, prekey_id: u16) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl!({ self.inner.proteus_new_prekey(prekey_id).await.map_err(Into::into) })
    }

    /// Creates a new Proteus prekey with an automatically assigned ID and returns its CBOR-serialized bundle.
    ///
    /// Warning: the Proteus client must be initialized with `proteus_init` first or an error will be returned.
    pub async fn proteus_new_prekey_auto(&self) -> CoreCryptoResult<ProteusAutoPrekeyBundle> {
        proteus_impl!({
            let (id, pkb) = self.inner.proteus_new_prekey_auto().await?;
            Ok(ProteusAutoPrekeyBundle { id, pkb })
        })
    }

    /// Returns the CBOR-serialized last resort prekey bundle, creating it if it does not yet exist.
    pub async fn proteus_last_resort_prekey(&self) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl!({ self.inner.proteus_last_resort_prekey().await.map_err(Into::into) })
    }

    /// Returns the hex-encoded public key fingerprint of this device's Proteus identity.
    pub async fn proteus_fingerprint(&self) -> CoreCryptoResult<String> {
        proteus_impl!({ self.inner.proteus_fingerprint().await.map_err(Into::into) })
    }

    /// Returns the hex-encoded local public key fingerprint for the Proteus session with the given ID.
    pub async fn proteus_fingerprint_local(&self, session_id: String) -> CoreCryptoResult<String> {
        proteus_impl!({
            self.inner
                .proteus_fingerprint_local(&session_id)
                .await
                .map_err(Into::into)
        })
    }

    /// Returns the hex-encoded remote public key fingerprint for the Proteus session with the given ID.
    pub async fn proteus_fingerprint_remote(&self, session_id: String) -> CoreCryptoResult<String> {
        proteus_impl!({
            self.inner
                .proteus_fingerprint_remote(&session_id)
                .await
                .map_err(Into::into)
        })
    }
}
