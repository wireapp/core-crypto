use crate::{CoreCryptoFfi, CoreCryptoResult, proteus_impl};

#[uniffi::export]
impl CoreCryptoFfi {
    /// See [core_crypto::proteus::ProteusCentral::session_exists]
    pub async fn proteus_session_exists(&self, session_id: String) -> CoreCryptoResult<bool> {
        proteus_impl!({ self.inner.proteus_session_exists(&session_id).await.map_err(Into::into) })
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint]
    pub async fn proteus_fingerprint(&self) -> CoreCryptoResult<String> {
        proteus_impl!({ self.inner.proteus_fingerprint().await.map_err(Into::into) })
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_local]
    pub async fn proteus_fingerprint_local(&self, session_id: String) -> CoreCryptoResult<String> {
        proteus_impl!({
            self.inner
                .proteus_fingerprint_local(&session_id)
                .await
                .map_err(Into::into)
        })
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_remote]
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

/// See [core_crypto::proteus::ProteusCentral::last_resort_prekey_id]
#[uniffi::export]
fn proteus_last_resort_prekey_id_ffi() -> CoreCryptoResult<u16> {
    proteus_impl!({ Ok(core_crypto::CoreCrypto::proteus_last_resort_prekey_id()) })
}

/// See [core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle]
#[uniffi::export]
fn proteus_fingerprint_prekeybundle_ffi(prekey: Vec<u8>) -> CoreCryptoResult<String> {
    proteus_impl!({ core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle(&prekey).map_err(Into::into) })
}
