use std::sync::Arc;

use async_lock::{Mutex, OnceCell};

use crate::{CoreCryptoContext, CoreCryptoResult};

use super::CoreCryptoCommand;

/// Helper for working with the new transasction interface.
///
/// This helper serves two purposes: to present a `FnOnce` interface for transactions,
/// and to allow the extraction of data from within transactions.
///
/// ## Extracting Data
///
/// The `CoreCryptoCommand` interface requires some kind of interior mutability to extract
/// any data: it takes an immutable reference to the implementing item, and returns the unit struct
/// in the success case.
///
/// That pattern is relatively arcane and verbose, particularly when we just want to smuggle out
/// some data from within the transaction. This helper is intended to ease and automate
/// that process.
///
/// Use it like this (pseudocode):
///
/// ```ignore
/// // an extractor is always `Arc`-wrapped
/// let extractor: Arc<_> = TransactionHelper::new(async move |context| {
///     // return whatever you need from the transaction here
/// });
/// core_crypto.transaction(extractor.clone()).await?;
/// let return_value = extractor.into_return_value();
/// ```
///
/// ## Panics
///
/// `TransactionHelper` is a one-shot item. Attempting to use the
/// same extractor in two different transactions will cause a panic.
pub struct TransactionHelper<T, F> {
    func: Mutex<Option<F>>,
    return_value: OnceCell<T>,
}

impl<T, F, Fut> TransactionHelper<T, F>
where
    F: FnOnce(Arc<CoreCryptoContext>) -> Fut + Send + Sync,
    Fut: Future<Output = CoreCryptoResult<T>> + Send,
    T: Send + Sync,
{
    pub fn new(func: F) -> Arc<Self> {
        Arc::new(Self {
            func: Mutex::new(Some(func)),
            return_value: OnceCell::new(),
        })
    }

    /// Get the return value from the internal function.
    ///
    /// ## Panics
    ///
    /// - If there exists more than one strong reference to this extractor
    /// - If the inner function was never called
    /// - If the inner function returned an `Err` variant
    ///
    /// In general if you call this after a call like
    ///
    /// ```ignore
    /// core_crypto.transaction(extractor.clone())?;
    /// ```
    ///
    /// then this will be fine.
    pub fn into_return_value(self: Arc<Self>) -> T {
        Arc::into_inner(self)
            .expect("there should exist exactly one strong ref right now")
            .return_value
            .into_inner()
            .expect("return value should be initialized")
    }

    /// Safely get the return value from the internal function.
    ///
    /// If there exists more than one strong reference to this item, or
    /// the inner function was never called or returned an `Err` variant,
    /// this will return `None`.
    pub fn try_into_return_value(self: Arc<Self>) -> Option<T> {
        Arc::into_inner(self)?.return_value.into_inner()
    }
}

#[async_trait::async_trait]
impl<T, F, Fut> CoreCryptoCommand for TransactionHelper<T, F>
where
    F: FnOnce(Arc<CoreCryptoContext>) -> Fut + Send + Sync,
    Fut: Future<Output = CoreCryptoResult<T>> + Send,
    T: Send + Sync,
{
    async fn execute(&self, context: Arc<CoreCryptoContext>) -> CoreCryptoResult<()> {
        let func = self
            .func
            .lock()
            .await
            .take()
            .expect("inner function must only be called once");
        let return_value = func(context).await?;
        let set_result = self.return_value.set(return_value).await;
        if set_result.is_err() {
            // can't just `.expect()` here because `T` is not `Debug`
            // though TBH this would be a really weird case; we should already have
            // paniced getting `func` above
            panic!("return value was previously set");
        }
        Ok(())
    }
}
