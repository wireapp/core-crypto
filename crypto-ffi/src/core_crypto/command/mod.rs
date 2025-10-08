#[cfg(not(target_family = "wasm"))]
pub(crate) mod transaction_helper;

use std::sync::Arc;

use crate::{CoreCryptoContext, CoreCryptoFfi, CoreCryptoResult};

/// A `CoreCryptoCommand` has an `execute` method which accepts a `CoreCryptoContext` and returns nothing.
///
/// It is the argument to a `CoreCrypto::transaction` call.
#[uniffi::export(with_foreign)]
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait CoreCryptoCommand: Send + Sync {
    /// Will be called inside a transaction in CoreCrypto
    async fn execute(&self, context: Arc<CoreCryptoContext>) -> CoreCryptoResult<()>;
}

/// When building outside WASM, any async function of appropriate signature is a `CoreCryptoCommand`.

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl<F, Fut> CoreCryptoCommand for F
where
    F: Fn(Arc<CoreCryptoContext>) -> Fut + Send + Sync,
    Fut: Future<Output = CoreCryptoResult<()>> + Send,
{
    async fn execute(&self, context: Arc<CoreCryptoContext>) -> CoreCryptoResult<()> {
        self(context).await
    }
}

/// In uniffi, a Command is an Arc wrapping a dyn trait object
type Command = Arc<dyn CoreCryptoCommand>;

#[uniffi::export]
impl CoreCryptoFfi {
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
        let context = Arc::new(context);

        let result = command.execute(context).await;
        match result {
            Ok(()) => {
                inner_context.finish().await?;
                Ok(())
            }
            Err(err) => {
                inner_context.abort().await?;
                Err(err)
            }
        }
    }
}
