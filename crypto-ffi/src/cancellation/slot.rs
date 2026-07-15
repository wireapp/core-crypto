use std::sync::{Arc, Mutex};

use crate::{CoreCryptoCancellationToken, CoreCryptoError, CoreCryptoResult};

/// Makes the current transaction's cancellation token available to foreign callbacks.
///
/// Cancelling the outer transaction does not automatically stop a nested Rust call that is
/// waiting for a Swift callback. The transport uses this token to stop waiting, which
/// lets the nested call return and the transaction unwind.
#[derive(Debug, Default)]
pub(crate) struct CancellationSlot {
    current: Mutex<Option<Arc<CoreCryptoCancellationToken>>>,
}

/// Clears the active cancellation token from the slot when dropped.
#[derive(Debug)]
pub(crate) struct CancellationGuard {
    slot: Arc<CancellationSlot>,
}

impl CancellationSlot {
    /// Installs the token for the transaction currently holding the semaphore.
    ///
    /// Only one token may be installed at a time.
    pub(crate) fn enter(
        self: &Arc<Self>,
        token: Arc<CoreCryptoCancellationToken>,
    ) -> CoreCryptoResult<CancellationGuard> {
        let mut current = self.current.lock().map_err(CoreCryptoError::ad_hoc)?;

        assert!(
            current.is_none(),
            "only one transaction cancellation token may be in the slot; correct wrapper implementation never hits this"
        );

        *current = Some(token);
        Ok(CancellationGuard { slot: self.clone() })
    }

    pub(crate) fn current(&self) -> CoreCryptoResult<Option<Arc<CoreCryptoCancellationToken>>> {
        self.current
            .lock()
            .map_err(CoreCryptoError::ad_hoc)
            .map(|guard| guard.clone())
    }
}

impl Drop for CancellationGuard {
    fn drop(&mut self) {
        let mut current = self.slot.current.lock().unwrap_or_else(|poisoned| {
            log::warn!("recovering poisoned cancellation slot");
            poisoned.into_inner()
        });

        *current = None;
    }
}
