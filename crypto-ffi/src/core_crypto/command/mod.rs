#[cfg(not(target_os = "unknown"))]
pub(crate) mod transaction_helper;

use std::sync::Arc;

use crate::{CoreCryptoContext, CoreCryptoFfi, CoreCryptoResult};

/// A `CoreCryptoCommand` has an `execute` method which accepts a `CoreCryptoContext` and returns nothing.
///
/// It is the argument to a `CoreCrypto::transaction` call.
#[uniffi::export(with_foreign)]
#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
pub trait CoreCryptoCommand: Send + Sync {
    /// Will be called inside a transaction in CoreCrypto
    async fn execute(&self, context: Arc<CoreCryptoContext>) -> CoreCryptoResult<()>;
}

/// When building outside WASM, any async function of appropriate signature is a `CoreCryptoCommand`.

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
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
    pub async fn transaction_ffi(&self, command: Command) -> CoreCryptoResult<()> {
        log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 1; "awaiting transaction semaphore");
        let inner_context = Arc::new(self.inner.new_transaction().await?);
        log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 2; "acquired semaphore; creating context");

        let context = CoreCryptoContext {
            inner: inner_context.clone(),
        };

        // We need one more layer of Arc-wrapping in uniffi. It's kind of silly, given the
        // also-mandatory Arc-wrapping internally, but that's the price we have to pay in order
        // to reuse the code in both target contexts.
        let context = Arc::new(context);

        log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 3; "created context; executing command");
        let result = command.execute(context).await;
        match result {
            Ok(()) => {
                log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 4, command_success = true; "command succeeded; committing transaction");
                inner_context.finish().await?;
                log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 5, command_success = true; "exiting successfully");
                Ok(())
            }
            Err(err) => {
                log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 4, command_success = false; "command failed; aborting transaction");
                inner_context.abort().await?;
                log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 5, command_success = false, err:err; "exiting propagating error");
                Err(err)
            }
        }
    }
}
