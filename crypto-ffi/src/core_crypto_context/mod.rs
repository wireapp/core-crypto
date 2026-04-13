mod e2ei;
pub(crate) mod mls;
mod proteus;

use std::{ops::Deref, sync::Arc};

use core_crypto::transaction_context::TransactionContext;

use crate::CoreCryptoResult;

/// The `CoreCryptoContext` holds the primary `CoreCrypto` APIs.
///
/// An instance of this struct is provided to the closure passed to `CoreCryptoFfi::transaction`.
///
/// Every mutable operation is done through this struct. Operations are buffered in memory
/// and persisted to the keystore when the transaction completes.
#[derive(Debug, uniffi::Object)]
pub struct CoreCryptoContext {
    pub(crate) inner: Arc<TransactionContext>,
}

impl Deref for CoreCryptoContext {
    type Target = TransactionContext;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

#[cfg_attr(any(feature = "wasm", feature = "napi"), uniffi::export)]
impl CoreCryptoContext {
    /// This is only needed to allow TS inheritance and should be hidden from library consumers.
    #[uniffi::constructor]
    pub fn new(instance: Arc<Self>) -> Arc<Self> {
        instance
    }
}

#[uniffi::export]
impl CoreCryptoContext {
    /// Stores arbitrary data to be used as a transaction checkpoint.
    ///
    /// The stored data can be retrieved via `get_data`. Keep the data size reasonable;
    /// this is not a general-purpose key-value store.
    pub async fn set_data(&self, data: Vec<u8>) -> CoreCryptoResult<()> {
        self.inner.set_data(data).await.map_err(Into::into)
    }

    /// Returns data previously stored by `set_data`, or `None` if no data has been stored.
    pub async fn get_data(&self) -> CoreCryptoResult<Option<Vec<u8>>> {
        self.inner.get_data().await.map_err(Into::into)
    }

    /// Generates `len` random bytes from the cryptographically secure RNG.
    pub async fn random_bytes(&self, len: u32) -> CoreCryptoResult<Vec<u8>> {
        self.inner.random_bytes(len as _).await.map_err(Into::into)
    }
}
