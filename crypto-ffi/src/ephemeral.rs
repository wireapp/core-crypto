#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{ClientId, CoreCrypto, CoreCryptoError, CoreCryptoResult};
use core_crypto::prelude::{CoreCrypto as CoreCryptoFfi, HistorySecret as HistorySecretFfi};

/// A `HistorySecret` encodes sufficient client state that it can be used to instantiate an
/// ephemeral client.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct HistorySecret {
    pub client_id: ClientId,
    pub data: Vec<u8>,
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl HistorySecret {
    #[wasm_bindgen(constructor)]
    pub fn new(client_id: ClientId, data: &[u8]) -> Result<HistorySecret, wasm_bindgen::JsError> {
        Ok(HistorySecret {
            client_id,
            data: data.into(),
        })
    }
}

impl TryFrom<&HistorySecretFfi> for HistorySecret {
    type Error = CoreCryptoError;

    fn try_from(value: &HistorySecretFfi) -> Result<Self, Self::Error> {
        let client_id = value.client_id.clone();
        rmp_serde::to_vec(&value)
            .map_err(CoreCryptoError::generic())
            .map(|secret| HistorySecret {
                client_id: client_id.into(),
                data: secret,
            })
    }
}

async fn history_client_inner(history_secret: HistorySecret) -> CoreCryptoResult<CoreCrypto> {
    let secret = rmp_serde::from_slice::<HistorySecretFfi>(&history_secret.data).map_err(CoreCryptoError::generic())?;
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
