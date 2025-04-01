#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{CoreCryptoContext, CoreCryptoResult, ProteusAutoPrekeyBundle, proteus_impl};

#[cfg(not(target_family = "wasm"))]
type BatchedEncryptedMessages = std::collections::HashMap<String, Vec<u8>>;

#[cfg(target_family = "wasm")]
type BatchedEncryptedMessages = JsValue;

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
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
        proteus_impl!({ self.inner.proteus_session_save(&session_id).await.map_err(Into::into) })
    }

    /// See [core_crypto::context::CentralContext::proteus_session_delete]
    pub async fn proteus_session_delete(&self, session_id: String) -> CoreCryptoResult<()> {
        proteus_impl!({ self.inner.proteus_session_delete(&session_id).await.map_err(Into::into) })
    }

    /// See [core_crypto::context::CentralContext::proteus_session_exists]
    pub async fn proteus_session_exists(&self, session_id: String) -> CoreCryptoResult<bool> {
        proteus_impl!({ self.inner.proteus_session_exists(&session_id).await.map_err(Into::into) })
    }

    /// See [core_crypto::context::CentralContext::proteus_decrypt]
    pub async fn proteus_decrypt(&self, session_id: String, ciphertext: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl!({
            self.inner
                .proteus_decrypt(&session_id, &ciphertext)
                .await
                .map_err(Into::into)
        })
    }

    /// See [core_crypto::context::CentralContext::proteus_encrypt]
    pub async fn proteus_encrypt(&self, session_id: String, plaintext: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl!({
            self.inner
                .proteus_encrypt(&session_id, &plaintext)
                .await
                .map_err(Into::into)
        })
    }

    /// See [core_crypto::context::CentralContext::proteus_encrypt_batched]
    #[cfg_attr(
        target_family = "wasm",
        wasm_bindgen(unchecked_return_type = "Map<string, Uint8Array>")
    )]
    pub async fn proteus_encrypt_batched(
        &self,
        sessions: Vec<String>,
        plaintext: Vec<u8>,
    ) -> CoreCryptoResult<BatchedEncryptedMessages> {
        proteus_impl!({
            let batched_encrypted_messages = self.inner.proteus_encrypt_batched(&sessions, &plaintext).await?;

            #[cfg(target_family = "wasm")]
            let batched_encrypted_messages = serde_wasm_bindgen::to_value(&batched_encrypted_messages)?;

            Ok(batched_encrypted_messages)
        })
    }

    /// See [core_crypto::context::CentralContext::proteus_new_prekey]
    pub async fn proteus_new_prekey(&self, prekey_id: u16) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl!({ self.inner.proteus_new_prekey(prekey_id).await.map_err(Into::into) })
    }

    /// See [core_crypto::context::CentralContext::proteus_new_prekey_auto]
    pub async fn proteus_new_prekey_auto(&self) -> CoreCryptoResult<ProteusAutoPrekeyBundle> {
        proteus_impl!({
            let (id, pkb) = self.inner.proteus_new_prekey_auto().await?;
            Ok(ProteusAutoPrekeyBundle { id, pkb })
        })
    }

    /// See [core_crypto::context::CentralContext::proteus_last_resort_prekey]
    pub async fn proteus_last_resort_prekey(&self) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl!({ self.inner.proteus_last_resort_prekey().await.map_err(Into::into) })
    }

    /// See [core_crypto::context::CentralContext::proteus_fingerprint]
    pub async fn proteus_fingerprint(&self) -> CoreCryptoResult<String> {
        proteus_impl!({ self.inner.proteus_fingerprint().await.map_err(Into::into) })
    }

    /// See [core_crypto::context::CentralContext::proteus_fingerprint_local]
    pub async fn proteus_fingerprint_local(&self, session_id: String) -> CoreCryptoResult<String> {
        proteus_impl!({
            self.inner
                .proteus_fingerprint_local(&session_id)
                .await
                .map_err(Into::into)
        })
    }

    /// See [core_crypto::context::CentralContext::proteus_fingerprint_remote]
    pub async fn proteus_fingerprint_remote(&self, session_id: String) -> CoreCryptoResult<String> {
        proteus_impl!({
            self.inner
                .proteus_fingerprint_remote(&session_id)
                .await
                .map_err(Into::into)
        })
    }

    /// See [core_crypto::context::CentralContext::proteus_cryptobox_migrate]
    pub async fn proteus_cryptobox_migrate(&self, path: String) -> CoreCryptoResult<()> {
        proteus_impl!({ self.inner.proteus_cryptobox_migrate(&path).await.map_err(Into::into) })
    }

    /// See [core_crypto::context::CentralContext::proteus_reload_sessions]
    pub async fn proteus_reload_sessions(&self) -> CoreCryptoResult<()> {
        proteus_impl!({ Ok(self.context.proteus_reload_sessions().await?) })
    }
}

// here are some static members, except that Uniffi doesn't do that, so we insert a pointless `self` param in that context

/// See [core_crypto::proteus::ProteusCentral::last_resort_prekey_id]
fn last_resort_prekey_id_inner() -> CoreCryptoResult<u16> {
    proteus_impl!({ Ok(core_crypto::CoreCrypto::proteus_last_resort_prekey_id()) })
}

/// See [core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle]
fn fingerprint_prekeybundle_inner(prekey: Vec<u8>) -> CoreCryptoResult<String> {
    proteus_impl!({ core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle(&prekey).map_err(Into::into) })
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl CoreCryptoContext {
    /// See [core_crypto::proteus::ProteusCentral::last_resort_prekey_id]
    pub fn proteus_last_resort_prekey_id() -> CoreCryptoResult<u16> {
        last_resort_prekey_id_inner()
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle]
    pub fn proteus_fingerprint_prekeybundle(prekey: Vec<u8>) -> CoreCryptoResult<String> {
        fingerprint_prekeybundle_inner(prekey)
    }
}

#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
impl CoreCryptoContext {
    /// See [core_crypto::proteus::ProteusCentral::last_resort_prekey_id]
    pub fn proteus_last_resort_prekey_id(&self) -> CoreCryptoResult<u16> {
        last_resort_prekey_id_inner()
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle]
    pub fn proteus_fingerprint_prekeybundle(&self, prekey: Vec<u8>) -> CoreCryptoResult<String> {
        fingerprint_prekeybundle_inner(prekey)
    }
}
