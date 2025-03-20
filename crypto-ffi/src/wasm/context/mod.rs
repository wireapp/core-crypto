use crate::{CoreCryptoContext, CoreCryptoError, WasmCryptoResult};
use futures_util::TryFutureExt;
use js_sys::{Promise, Uint8Array};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen_futures::future_to_promise;

pub mod e2ei;
pub mod proteus;

#[wasm_bindgen]
impl CoreCryptoContext {
    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::random_bytes]
    pub fn random_bytes(&self, len: usize) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let bytes = context.random_bytes(len).map_err(CoreCryptoError::from).await?;
                WasmCryptoResult::Ok(Uint8Array::from(bytes.as_slice()).into())
            }
            .err_into(),
        )
    }
}
