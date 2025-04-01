use crate::CoreCryptoResult;
use crate::ProteusAutoPrekeyBundle;
use crate::context::CoreCryptoContext;
use crate::proteus_impl;

#[uniffi::export]
impl CoreCryptoContext {
    /// See [core_crypto::proteus::ProteusCentral::try_new]
    pub async fn proteus_init(&self) -> CoreCryptoResult<()> {
        proteus_impl!({
            self.inner.proteus_init().await?;
            Ok(())
        })
    }

    /// See [core_crypto::context::CentralContext::proteus_session_from_prekey]
    pub async fn proteus_session_from_prekey(&self, session_id: String, prekey: Vec<u8>) -> CoreCryptoResult<()> {
        proteus_impl!({
            self.inner.proteus_session_from_prekey(&session_id, &prekey).await?;
            Ok(())
        })
    }

    /// See [core_crypto::context::CentralContext::proteus_session_from_message]
    pub async fn proteus_session_from_message(
        &self,
        session_id: String,
        envelope: Vec<u8>,
    ) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl!({
            let (_, payload) = self.inner.proteus_session_from_message(&session_id, &envelope).await?;
            Ok(payload)
        })
    }

    /// See [core_crypto::context::CentralContext::proteus_session_save]
    /// **Note**: This isn't usually needed as persisting sessions happens automatically when decrypting/encrypting messages and initializing Sessions
    pub async fn proteus_session_save(&self, session_id: String) -> CoreCryptoResult<()> {
        proteus_impl!({ Ok(self.inner.proteus_session_save(&session_id).await?) })
    }

    /// See [core_crypto::context::CentralContext::proteus_session_delete]
    pub async fn proteus_session_delete(&self, session_id: String) -> CoreCryptoResult<()> {
        proteus_impl!({ Ok(self.inner.proteus_session_delete(&session_id).await?) })
    }

    /// See [core_crypto::context::CentralContext::proteus_session_exists]
    pub async fn proteus_session_exists(&self, session_id: String) -> CoreCryptoResult<bool> {
        proteus_impl!({ Ok(self.inner.proteus_session_exists(&session_id).await?) })
    }

    /// See [core_crypto::context::CentralContext::proteus_decrypt]
    pub async fn proteus_decrypt(&self, session_id: String, ciphertext: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl!({ Ok(self.inner.proteus_decrypt(&session_id, &ciphertext).await?) })
    }

    /// See [core_crypto::context::CentralContext::proteus_encrypt]
    pub async fn proteus_encrypt(&self, session_id: String, plaintext: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl!({ Ok(self.inner.proteus_encrypt(&session_id, &plaintext).await?) })
    }

    /// See [core_crypto::context::CentralContext::proteus_encrypt_batched]
    pub async fn proteus_encrypt_batched(
        &self,
        sessions: Vec<String>,
        plaintext: Vec<u8>,
    ) -> CoreCryptoResult<std::collections::HashMap<String, Vec<u8>>> {
        proteus_impl!({ Ok(self.inner.proteus_encrypt_batched(&sessions, &plaintext).await?) })
    }

    /// See [core_crypto::context::CentralContext::proteus_new_prekey]
    pub async fn proteus_new_prekey(&self, prekey_id: u16) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl!({ CoreCryptoResult::Ok(self.inner.proteus_new_prekey(prekey_id).await?) })
    }

    /// See [core_crypto::context::CentralContext::proteus_new_prekey_auto]
    pub async fn proteus_new_prekey_auto(&self) -> CoreCryptoResult<ProteusAutoPrekeyBundle> {
        proteus_impl!({
            let (id, pkb) = self.inner.proteus_new_prekey_auto().await?;
            CoreCryptoResult::Ok(ProteusAutoPrekeyBundle { id, pkb })
        })
    }

    /// See [core_crypto::context::CentralContext::proteus_last_resort_prekey]
    pub async fn proteus_last_resort_prekey(&self) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl!({ Ok(self.inner.proteus_last_resort_prekey().await?) })
    }

    /// See [core_crypto::context::CentralContext::proteus_last_resort_prekey_id]
    pub fn proteus_last_resort_prekey_id(&self) -> CoreCryptoResult<u16> {
        proteus_impl!({ Ok(core_crypto::CoreCrypto::proteus_last_resort_prekey_id()) })
    }

    /// See [core_crypto::context::CentralContext::proteus_fingerprint]
    pub async fn proteus_fingerprint(&self) -> CoreCryptoResult<String> {
        proteus_impl!({ Ok(self.inner.proteus_fingerprint().await?) })
    }

    /// See [core_crypto::context::CentralContext::proteus_fingerprint_local]
    pub async fn proteus_fingerprint_local(&self, session_id: String) -> CoreCryptoResult<String> {
        proteus_impl!({ Ok(self.inner.proteus_fingerprint_local(&session_id).await?) })
    }

    /// See [core_crypto::context::CentralContext::proteus_fingerprint_remote]
    pub async fn proteus_fingerprint_remote(&self, session_id: String) -> CoreCryptoResult<String> {
        proteus_impl!({ Ok(self.inner.proteus_fingerprint_remote(&session_id).await?) })
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle]
    /// NOTE: uniffi doesn't support associated functions, so we have to have the self here
    pub fn proteus_fingerprint_prekeybundle(&self, prekey: Vec<u8>) -> CoreCryptoResult<String> {
        proteus_impl!({ Ok(core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle(&prekey)?) })
    }

    /// See [core_crypto::context::CentralContext::proteus_cryptobox_migrate]
    pub async fn proteus_cryptobox_migrate(&self, path: String) -> CoreCryptoResult<()> {
        proteus_impl!({ Ok(self.inner.proteus_cryptobox_migrate(&path).await?) })
    }

    /// See [core_crypto::context::CentralContext::proteus_reload_sessions]
    pub async fn proteus_reload_sessions(&self) -> CoreCryptoResult<()> {
        proteus_impl!({ Ok(self.context.proteus_reload_sessions().await?) })
    }
}
