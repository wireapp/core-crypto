#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{CoreCrypto, CoreCryptoResult, proteus_impl};

#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl CoreCrypto {
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
impl CoreCrypto {
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
impl CoreCrypto {
    /// See [core_crypto::proteus::ProteusCentral::last_resort_prekey_id]
    pub fn proteus_last_resort_prekey_id(&self) -> CoreCryptoResult<u16> {
        last_resort_prekey_id_inner()
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle]
    pub fn proteus_fingerprint_prekeybundle(&self, prekey: Vec<u8>) -> CoreCryptoResult<String> {
        fingerprint_prekeybundle_inner(prekey)
    }
}
