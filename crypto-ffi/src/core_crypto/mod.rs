mod client;
pub(crate) mod command;
pub(crate) mod conversation;
pub(crate) mod e2ei;
pub(crate) mod epoch_observer;
pub(crate) mod history_observer;
pub(crate) mod logger;
pub(crate) mod mls_transport;
mod proteus;

#[cfg(feature = "wasm")]
mod randomness;

use std::sync::Arc;

use core_crypto::Session;

use crate::{CoreCryptoResult, Database};

/// CoreCrypto wraps around MLS and Proteus implementations and provides a transactional interface for each.
#[derive(Debug, uniffi::Object)]
pub struct CoreCryptoFfi {
    pub(crate) inner: core_crypto::CoreCrypto,
}

/// Free function to construct a new `CoreCryptoFfi` instance.
///
/// This is necessary because in uniffi async constructors are not supported.
///
/// MLS or proteus can be initialized  with [core_crypto::transaction_context::TransactionContext::mls_init] or
/// [core_crypto::transaction_context::TransactionContext::proteus_init], respectively.
#[uniffi::export]
pub async fn core_crypto_new(database: &Arc<Database>) -> CoreCryptoResult<CoreCryptoFfi> {
    CoreCryptoFfi::new(database).await
}

impl CoreCryptoFfi {
    /// Instantiate CC
    pub async fn new(database: &Arc<Database>) -> CoreCryptoResult<Self> {
        #[cfg(target_family = "wasm")]
        console_error_panic_hook::set_once();

        let client = Session::try_new(database).await?;
        let inner = core_crypto::CoreCrypto::from(client);

        Ok(Self { inner })
    }
}

#[cfg(feature = "wasm")]
#[uniffi::export]
impl CoreCryptoFfi {
    /// See [Session::close]
    // indexdb connections must be closed explicitly while rusqlite implements drop which suffices.
    pub async fn close(&self) -> CoreCryptoResult<()> {
        self.inner.close().await.map_err(Into::into)
    }
}
