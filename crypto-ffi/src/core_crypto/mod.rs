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

/// Construct a new `CoreCryptoFfi` instance.
///
/// MLS or Proteus can be initialized via `mls_init` or `proteus_init` on a
/// `CoreCryptoContext` obtained through a transaction.
#[uniffi::export]
pub fn core_crypto_new(database: &Arc<Database>) -> CoreCryptoResult<CoreCryptoFfi> {
    #[cfg(target_os = "unknown")]
    console_error_panic_hook::set_once();
    let db = database.as_ref().clone().into();
    let inner = core_crypto::CoreCrypto::new(db);

    Ok(CoreCryptoFfi { inner })
}

#[cfg_attr(any(feature = "wasm", feature = "napi"), uniffi::export)]
impl CoreCryptoFfi {
    /// This is only needed to allow TS inheritance and should be hidden from library consumers.
    #[uniffi::constructor]
    pub fn new(instance: Arc<Self>) -> Arc<Self> {
        instance
    }
}
