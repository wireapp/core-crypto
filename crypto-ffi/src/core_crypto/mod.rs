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

use crate::{CoreCryptoResult, Database};

/// CoreCrypto wraps around MLS and Proteus implementations and provides a transactional interface for each.
#[derive(Debug, uniffi::Object)]
pub struct CoreCryptoFfi {
    pub(crate) inner: core_crypto::CoreCrypto,
}

#[uniffi::export]
impl CoreCryptoFfi {
    /// Construct a new `CoreCryptoFfi` instance.
    /// MLS or proteus can be initialized  with [core_crypto::transaction_context::TransactionContext::mls_init] or
    /// [core_crypto::transaction_context::TransactionContext::proteus_init], respectively.
    #[uniffi::constructor]
    pub fn new(database: &Arc<Database>) -> CoreCryptoResult<Self> {
        #[cfg(target_family = "wasm")]
        console_error_panic_hook::set_once();
        let db = database.as_ref().clone().into();
        let inner = core_crypto::CoreCrypto::new(db);

        Ok(Self { inner })
    }
}

#[cfg_attr(feature = "wasm", uniffi::export)]
impl CoreCryptoFfi {
    /// Closes the database
    /// indexdb connections must be closed explicitly while rusqlite implements drop which suffices.
    pub async fn close(&self) -> CoreCryptoResult<()> {
        self.inner.close().await.map_err(Into::into)
    }
}
