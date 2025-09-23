#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{ClientId, CoreCryptoError, CoreCryptoFfi, CoreCryptoResult, client_id::ClientIdMaybeArc};
use core_crypto::prelude::{CoreCrypto, HistorySecret as CoreCryptoHistorySecret};

/// A `HistorySecret` encodes sufficient client state that it can be used to instantiate an
/// ephemeral client.
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq)]
#[cfg_attr(target_family = "wasm", wasm_bindgen(getter_with_clone))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct HistorySecret {
    /// Client id of the associated history client
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly, js_name = clientId))]
    pub client_id: ClientIdMaybeArc,
    /// Opaque secret data sufficient to reconstruct a history client.
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub data: Vec<u8>,
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl HistorySecret {
    /// Construct a history secret from client id and raw data
    #[wasm_bindgen(constructor)]
    pub fn new(client_id: ClientIdMaybeArc, data: &[u8]) -> Result<HistorySecret, wasm_bindgen::JsError> {
        Ok(HistorySecret {
            client_id,
            data: data.into(),
        })
    }
}

impl TryFrom<&CoreCryptoHistorySecret> for HistorySecret {
    type Error = CoreCryptoError;

    fn try_from(value: &CoreCryptoHistorySecret) -> Result<Self, Self::Error> {
        let client_id = value.client_id.clone();
        rmp_serde::to_vec(&value)
            .map_err(CoreCryptoError::generic())
            .map(|secret| HistorySecret {
                client_id: ClientId::from_cc(client_id),
                data: secret,
            })
    }
}

async fn history_client_inner(history_secret: HistorySecret) -> CoreCryptoResult<CoreCryptoFfi> {
    let secret =
        rmp_serde::from_slice::<CoreCryptoHistorySecret>(&history_secret.data).map_err(CoreCryptoError::generic())?;
    CoreCrypto::history_client(secret)
        .await
        .map(|inner| CoreCryptoFfi { inner })
        .map_err(Into::into)
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl CoreCryptoFfi {
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
pub async fn core_crypto_history_client(history_secret: HistorySecret) -> CoreCryptoResult<CoreCryptoFfi> {
    history_client_inner(history_secret).await
}
