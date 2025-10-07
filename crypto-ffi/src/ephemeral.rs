use core_crypto::{CoreCrypto, HistorySecret as CoreCryptoHistorySecret};

use crate::{ClientId, CoreCryptoError, CoreCryptoFfi, CoreCryptoResult, client_id::ClientIdMaybeArc};

/// A `HistorySecret` encodes sufficient client state that it can be used to instantiate an
/// ephemeral client.
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HistorySecret {
    /// Client id of the associated history client
    pub client_id: ClientIdMaybeArc,
    /// Opaque secret data sufficient to reconstruct a history client.
    pub data: Vec<u8>,
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

/// Instantiate a history client.
///
/// This client exposes the full interface of `CoreCrypto`, but it should only be used to decrypt messages.
/// Other use is a logic error.
#[uniffi::export]
pub async fn core_crypto_history_client(history_secret: HistorySecret) -> CoreCryptoResult<CoreCryptoFfi> {
    history_client_inner(history_secret).await
}
