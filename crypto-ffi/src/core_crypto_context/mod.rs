use std::{ops::Deref, sync::Arc};

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use core_crypto::context::CentralContext;

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
