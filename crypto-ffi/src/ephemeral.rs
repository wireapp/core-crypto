#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{CoreCrypto, CoreCryptoError, CoreCryptoResult};
use core_crypto::prelude::{CoreCrypto as CoreCryptoFfi, HistorySecret as HistorySecretFfi};

/// A `HistorySecret` encodes sufficient client state that it can be used to instantiate an
/// ephemeral client.
pub type HistorySecret = Vec<u8>;

async fn history_client_inner(history_secret: HistorySecret) -> CoreCryptoResult<CoreCrypto> {
    let secret = rmp_serde::from_slice::<HistorySecretFfi>(&history_secret).map_err(CoreCryptoError::generic())?;
    CoreCryptoFfi::history_client(secret)
        .await
        .map(|inner| CoreCrypto { inner })
        .map_err(Into::into)
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl CoreCrypto {
    /// Instantiate a history client.
    ///
    /// This client exposes the full interface of `CoreCrypto`, but it should only be used to decrypt messages.
    /// Other use is a logic error.
    pub async fn history_client(history_secret: HistorySecret) -> CoreCryptoResult<Self> {
        history_client_inner(history_secret).await
    }
}

/// Instantiate a history client.
///
/// This client exposes the full interface of `CoreCrypto`, but it should only be used to decrypt messages.
/// Other use is a logic error.
#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
pub async fn core_crypto_history_client(history_secret: HistorySecret) -> CoreCryptoResult<CoreCrypto> {
    history_client_inner(history_secret).await
}
