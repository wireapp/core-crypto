mod e2ei;
pub(crate) mod mls;
mod proteus;

use std::{ops::Deref, sync::Arc};

use core_crypto::transaction_context::TransactionContext;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::CoreCryptoResult;

/// The `CoreCryptoContext` holds the primary `CoreCrypto` APIs.
///
/// An instance of this struct is provided to the function handed to `CoreCrypto::transaction`.
///
/// Every mutable operation is done through this struct. This struct will buffer all
/// operations in memory and when [TransactionContext::finish] is called, it will persist the data into
/// the keystore.
#[derive(Debug)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Object))]
pub struct CoreCryptoContext {
    pub(crate) inner: Arc<TransactionContext>,
}

impl Deref for CoreCryptoContext {
    type Target = TransactionContext;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl CoreCryptoContext {
    /// See [core_crypto::transaction_context::TransactionContext::set_data]
    pub async fn set_data(&self, data: Vec<u8>) -> CoreCryptoResult<()> {
        self.inner.set_data(data).await.map_err(Into::into)
    }

    /// See [core_crypto::transaction_context::TransactionContext::get_data]
    pub async fn get_data(&self) -> CoreCryptoResult<Option<Vec<u8>>> {
        self.inner.get_data().await.map_err(Into::into)
    }

    /// See [core_crypto::Session::random_bytes].
    pub async fn random_bytes(&self, len: u32) -> CoreCryptoResult<Vec<u8>> {
        self.inner.random_bytes(len as _).await.map_err(Into::into)
    }
}
