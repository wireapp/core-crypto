mod wakers;

use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, Ordering},
};

use crate::cancellation::{Cancelled, token::wakers::CancellationWakers};

/// Use this to cancel a `CoreCrypto` transaction and running foreign callbacks. Should be used in the Swift wrapper
/// only.
#[derive(Debug, uniffi::Object)]
pub struct CoreCryptoCancellationToken {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    cancelled: AtomicBool,
    /// We're using a non-async lock to avoid spawning another future to wait during
    /// [CoreCryptoCancellationToken::cancel].
    wakers: Mutex<CancellationWakers>,
}

#[uniffi::export]
impl CoreCryptoCancellationToken {
    /// Create a new `CoreCryptoCancellationToken`.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Default::default(),
        })
    }

    /// Cancel the token and wake all futures waiting for `cancelled()`.
    pub fn cancel(&self) {
        // Set the cancel atomic to true, clear wakers and wake them.
        if !self.inner.cancelled.swap(true, Ordering::SeqCst) {
            let wakers = self.wakers().take_all();

            for waker in wakers.into_iter().flatten() {
                waker.wake();
            }
        }
    }

    /// Whether `cancel` has been called.
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::SeqCst)
    }
}

impl CoreCryptoCancellationToken {
    /// Locks the disposable waker registry, recovering poisoned state.
    ///
    /// The registry contains only transient notification state, so cancellation
    /// remains usable after a waiter panics. Recovery is logged for visibility.
    pub(crate) fn wakers(&self) -> MutexGuard<'_, CancellationWakers> {
        self.inner.wakers.lock().unwrap_or_else(|poisoned| {
            log::warn!("recovering poisoned cancellation waker registry");
            poisoned.into_inner()
        })
    }

    /// Return a future that resolves when this token is cancelled.
    pub(crate) fn cancelled(self: &Arc<Self>) -> Cancelled {
        Cancelled {
            token: self.clone(),
            wakers_index: None,
        }
    }
}
