mod client;
pub(crate) mod command;
pub(crate) mod conversation;
pub(crate) mod e2ei;
pub(crate) mod epoch_observer;
pub(crate) mod history_observer;
pub(crate) mod logger;
pub(crate) mod mls_transport;
mod proteus;
mod randomness;

use core_crypto::Session;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    CoreCryptoResult,
    database::{DatabaseMaybeArc, ToCc as _},
};

/// In Wasm, boxed slices are the natural way to communicate an immutable byte slice
#[cfg(target_family = "wasm")]
pub(crate) type EntropySeed = Box<[u8]>;

/// In uniffi, a vector is the natural way to communicate a byte slice
#[cfg(not(target_family = "wasm"))]
pub(crate) type EntropySeed = Vec<u8>;

#[cfg(target_family = "wasm")]
#[expect(dead_code)]
// Will be needed when implementing WPB-19570
pub(crate) fn entropy_seed_map(e: EntropySeed) -> Vec<u8> {
    e.into()
}

#[cfg(not(target_family = "wasm"))]
#[expect(dead_code)]
// Will be needed when implementing WPB-19570
pub(crate) fn entropy_seed_map(e: EntropySeed) -> Vec<u8> {
    e
}

/// CoreCrypto wraps around MLS and Proteus implementations and provides a transactional interface for each.
#[derive(Debug)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Object))]
pub struct CoreCryptoFfi {
    pub(crate) inner: core_crypto::CoreCrypto,
}

/// Free function to construct a new `CoreCryptoFfi` instance.
///
/// This is necessary because in uniffi async constructors are not supported.
///
/// MLS or proteus can be initialized  with [core_crypto::transaction_context::TransactionContext::mls_init] or
/// [core_crypto::transaction_context::TransactionContext::proteus_init], respectively.
#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
pub async fn core_crypto_new(database: DatabaseMaybeArc) -> CoreCryptoResult<CoreCryptoFfi> {
    CoreCryptoFfi::new(database).await
}

impl CoreCryptoFfi {
    /// Instantiate CC
    pub async fn new(database: DatabaseMaybeArc) -> CoreCryptoResult<Self> {
        #[cfg(target_family = "wasm")]
        console_error_panic_hook::set_once();

        let client = Session::try_new(database.to_cc()).await?;
        let inner = core_crypto::CoreCrypto::from(client);

        Ok(Self { inner })
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl CoreCryptoFfi {
    /// Asynchronously instantiate CC.
    ///
    /// MLS or proteus can be initialized  with [core_crypto::transaction_context::TransactionContext::mls_init] or
    /// [core_crypto::transaction_context::TransactionContext::proteus_init], respectively.
    pub async fn async_new(database: DatabaseMaybeArc) -> CoreCryptoResult<CoreCryptoFfi> {
        CoreCryptoFfi::new(database).await
    }

    /// See [Session::close]
    // Note that this is implemented only for Wasm; Uniffi already generates a `close` method which suffices.
    pub async fn close(self) -> CoreCryptoResult<()> {
        self.inner.take().close().await.map_err(Into::into)
    }
}
