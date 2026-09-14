use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};

/// Use this to cancel a `CoreCrypto` transaction and running foreign callbacks. Should be used in the Swift wrapper
/// only.
#[derive(Debug, uniffi::Object)]
pub struct CoreCryptoCancellationToken {
    inner: CancellationToken,
}

#[uniffi::export]
impl CoreCryptoCancellationToken {
    /// Create a new `CoreCryptoCancellationToken`.
    #[expect(clippy::new_without_default)]
    #[uniffi::constructor]
    pub fn new() -> Self {
        let inner = CancellationToken::new();

        Self { inner }
    }

    /// Cancel the token and resolve all futures waiting for its cancellation.
    pub fn cancel(&self) {
        self.inner.cancel();
    }
}

impl CoreCryptoCancellationToken {
    /// Return a future that resolves when this token is cancelled.
    pub(crate) fn cancelled(&self) -> WaitForCancellationFuture<'_> {
        self.inner.cancelled()
    }
}
