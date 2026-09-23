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
    pub(crate) fn inner(&self) -> Result<impl Deref<Target = TransactionContextInner>> {
        // Access to inner is designed to be immutable, concurrent, and fast.
        // There is exactly one place where we take a write guard: `take_inner`, below, where we invalidate the context.
        // If we can't immediately acquire a read guard, we'll never be able to (unless the future containing
        // the `take_inner` is cancelled, which is a niche enough edge case I'm not going to worry about it).
        //
        // NOTE: there is no structural guarantee that there is exactly one place which acquires a write lock.
        // We depend on convention to enforce the precondition underlying this logic.
        let guard = self.inner.try_read_arc().ok_or(Error::InvalidTransactionContext)?;
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

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use smol::future::{or, poll_once};

    use crate::{CoreCrypto, Database};

    /// Nesting [`TransactionContext::inner`] must not deadlock against
    /// [`TransactionContext::take_inner`].
    ///
    /// `async_lock::RwLock` is write-preferring: the write future sets its writer bit while the
    /// existing readers are still live, and new readers park as soon as that bit is set. So a task
    /// which holds an [`InnerGuard`] across an await point and then re-enters `inner()` cannot get
    /// the second guard once another task has asked for the write lock in between — and that writer
    /// is itself waiting for the first guard to drop.
    ///
    /// Real code has this shape: `remove_credential` holds a guard across
    /// `remove_key_packages_for`, which holds one across `remove_key_package`, which takes a third;
    /// `check_credentials` does the same across `clean_up_irrelevant_crls`. The writer is any
    /// concurrent `finish` or `abort` on a retained context.
    ///
    /// Whichever side wins, both must terminate: the nesting caller either gets its second guard or
    /// gets [`Error::InvalidTransactionContext`], and the writer either takes the inner or reports
    /// that it was already taken.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn nested_inner_calls_with_take_inner_do_not_deadlock() {
        let core_crypto = CoreCrypto::new(Database::open_in_memory().unwrap());
        let context = core_crypto.new_transaction().await.unwrap();

        // The nesting caller: take a guard, await something, then take the guard again.
        let mut nested = Box::pin({
            let context = context.clone();
            async move {
                let _outer_guard = context.inner().await.expect("outer guard is valid");
                smol::future::yield_now().await;
                context.inner().await.map(|_| ())
            }
        });

        // The writer: `finish`/`abort` from a retained context or a callback-spawned task.
        let mut taker = Box::pin({
            let context = context.clone();
            async move { context.take_inner().await.map(|_| ()) }
        });

        // Force the interleaving: the nesting caller parks holding the outer guard, then the writer
        // parks behind it, setting the writer bit.
        assert!(
            poll_once(nested.as_mut()).await.is_none(),
            "the nesting caller should suspend while holding the outer guard"
        );
        assert!(
            poll_once(taker.as_mut()).await.is_none(),
            "the writer should park behind the outer guard"
        );

        // Now let both of them run. Each must reach some conclusion, successful or not.
        let timed_out = or(
            async {
                let _ = futures_util::future::join(nested, taker).await;
                false
            },
            async {
                smol::Timer::after(Duration::from_secs(1)).await;
                true
            },
        )
        .await;

        assert!(
            !timed_out,
            "nesting `inner()` deadlocked against a concurrent `take_inner()`"
        );
    }
}
