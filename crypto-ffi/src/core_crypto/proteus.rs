use crate::{CoreCryptoFfi, CoreCryptoResult, proteus_impl};

#[uniffi::export]
impl CoreCryptoFfi {
    /// Returns true if a Proteus session with the given ID exists in local storage.
    pub async fn proteus_session_exists(&self, session_id: String) -> CoreCryptoResult<bool> {
        proteus_impl!({ self.inner.proteus_session_exists(&session_id).await.map_err(Into::into) })
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

// some static members, that we define as free functions for uniffi and define as static members in the wrappers

/// Returns the Proteus last resort prekey ID.
///
/// The last resort prekey is a special prekey retained after all other prekeys have been consumed,
/// ensuring a session can always be established. Its ID is always `u16::MAX` (65535).
#[uniffi::export]
fn proteus_last_resort_prekey_id_ffi() -> CoreCryptoResult<u16> {
    proteus_impl!({ Ok(core_crypto::CoreCrypto::proteus_last_resort_prekey_id()) })
}

/// Returns the hex-encoded fingerprint of the identity key contained in the given prekey bundle.
#[uniffi::export]
fn proteus_fingerprint_prekeybundle_ffi(prekey: Vec<u8>) -> CoreCryptoResult<String> {
    proteus_impl!({ core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle(&prekey).map_err(Into::into) })
}
