#[cfg(not(target_family = "wasm"))]
pub(crate) mod transaction_helper;

use crate::{CoreCrypto, CoreCryptoContext, CoreCryptoResult};
use std::sync::Arc;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

/// :nodoc:
#[cfg(not(target_family = "wasm"))]
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait CoreCryptoCommand: Send + Sync {
    /// Will be called inside a transaction in CoreCrypto
    async fn execute(&self, context: Arc<CoreCryptoContext>) -> CoreCryptoResult<()>;
}

/// :nodoc:
#[cfg(not(target_family = "wasm"))]
#[async_trait::async_trait]
impl<F, Fut> CoreCryptoCommand for F
where
    F: Fn(Arc<CoreCryptoContext>) -> Fut + Send + Sync,
    Fut: Future<Output = CoreCryptoResult<()>> + Send,
{
    async fn execute(&self, context: Arc<CoreCryptoContext>) -> CoreCryptoResult<()> {
        self(context).await
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
extern "C" {
    pub type CoreCryptoCommand;

    #[wasm_bindgen(structural, method, catch)]
    pub async fn execute(this: &CoreCryptoCommand, ctx: CoreCryptoContext) -> Result<(), JsValue>;
}

/// In uniffi, a Command is an Arc wrapping a dyn trait object
#[cfg(not(target_family = "wasm"))]
type Command = Arc<dyn CoreCryptoCommand>;

/// In wasm, a Command is a duck-typed JsValue that someone has promised implements the appropriate interface.
#[cfg(target_family = "wasm")]
type Command = CoreCryptoCommand;

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl CoreCrypto {
    /// Starts a new transaction in Core Crypto. If the callback succeeds, it will be committed,
    /// otherwise, every operation performed with the context will be discarded.
    ///
    /// When calling this function from within Rust, async functions accepting a context
    /// implement `CoreCryptoCommand`, so operations can be defined inline as follows:
    ///
    /// ```ignore
    /// core_crypto.transaction(Arc::new(async |context| {
    ///     // your implementation here
    ///     Ok(())
    /// }))?;
    /// ```
    pub async fn transaction(&self, command: Command) -> CoreCryptoResult<()> {
        let inner_context = Arc::new(self.inner.new_transaction().await?);

        let context = CoreCryptoContext {
            inner: inner_context.clone(),
        };

        // We need one more layer of Arc-wrapping in uniffi. It's kind of silly, given the
        // also-mandatory Arc-wrapping internally, but that's the price we have to pay in order
        // to reuse the code in both target contexts.
        #[cfg(not(target_family = "wasm"))]
        let context = Arc::new(context);

        let result = command.execute(context).await;
        match result {
            Ok(()) => {
                inner_context.finish().await?;
                Ok(())
            }
            Err(err) => {
                inner_context.abort().await?;

                // In wasm only, we are required to manually convert the error type. Uniffi does it for us.
                #[cfg(target_family = "wasm")]
                let err = crate::error::core_crypto::CoreCryptoError::TransactionFailed(err).into();

                Err(err)
            }
        }
    }
}
