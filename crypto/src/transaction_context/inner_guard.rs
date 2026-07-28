use std::ops::Deref;

use async_lock::RwLockReadGuardArc;

use crate::transaction_context::{Error, Result, TransactionContext, TransactionContextInner};

struct InnerGuard {
    guard: RwLockReadGuardArc<Option<TransactionContextInner>>,
}

impl Deref for InnerGuard {
    type Target = TransactionContextInner;

    fn deref(&self) -> &Self::Target {
        self.guard
            .deref()
            .as_ref()
            .expect("we ensure at construction that the guard is valid")
        // ... and it can't go invalid because we still hold that guard
    }
}

impl TransactionContext {
    /// Get a guard which derefs to [`TransactionContextInner`], or produce an appropriate error.
    pub(crate) async fn inner(&self) -> Result<impl Deref<Target = TransactionContextInner>> {
        let guard = self.inner.read_arc().await;
        match *guard {
            Some(_) => Ok(InnerGuard { guard }),
            None => Err(Error::InvalidTransactionContext),
        }
    }

    /// Take the [`TransactionContextInner`] from self, leaving it in an invalid state.
    pub(super) async fn take_inner(&self) -> Result<TransactionContextInner> {
        let mut guard = self.inner.write().await;
        guard.take().ok_or(Error::InvalidTransactionContext)
    }
}
