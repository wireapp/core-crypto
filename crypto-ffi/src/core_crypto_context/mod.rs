#[cfg(target_family = "wasm")]
pub(crate) mod array_of_byte_array;
mod mls;

use std::{ops::Deref, sync::Arc};

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use core_crypto::context::CentralContext;

use crate::CoreCryptoResult;

#[derive(Debug)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Object))]
pub struct CoreCryptoContext {
    pub(crate) inner: Arc<CentralContext>,
}

impl Deref for CoreCryptoContext {
    type Target = CentralContext;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl CoreCryptoContext {
    /// See [core_crypto::context::CentralContext::set_data].
    pub async fn set_data(&self, data: Vec<u8>) -> CoreCryptoResult<()> {
        self.inner.set_data(data).await.map_err(Into::into)
    }

    /// See [core_crypto::context::CentralContext::get_data].
    pub async fn get_data(&self) -> CoreCryptoResult<Option<Vec<u8>>> {
        self.inner.get_data().await.map_err(Into::into)
    }
}
