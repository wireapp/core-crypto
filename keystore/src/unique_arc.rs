use std::{
    borrow::Borrow,
    ops::Deref,
    sync::{Arc, Weak},
};

use async_lock::{RwLock, RwLockReadGuardArc};
use async_trait::async_trait;

use crate::{
    CryptoKeystoreResult,
    traits::{
        BorrowPrimaryKey, Entity, EntityGetBorrowed, FetchFromDatabase, KeyType, SearchableEntity, UniqueEntityExt,
    },
};

/// A smart pointer which has exactly one strong reference to the inner type,
/// but may have several weak references.
///
/// This type is intentionally `!Clone` so that we know for a fact that it can be
/// safely unpacked.
#[derive(Debug, derive_more::Deref)]
pub struct UniqueArc<T> {
    #[deref(forward)]
    arc: Arc<T>,
    /// Coordinates temporary upgrades (shared/read) against final unpacking (exclusive/write).
    gate: Arc<RwLock<()>>,
}

impl<T> From<T> for UniqueArc<T> {
    fn from(value: T) -> Self {
        UniqueArc {
            arc: Arc::new(value),
            gate: Arc::new(RwLock::new(())),
        }
    }
}

impl<T> UniqueArc<T> {
    /// Unpack this `UniqueArc`, returning the inner value.
    ///
    /// This waits for any in-flight [`UniqueWeak::with_upgrade`] / [`UniqueWeak::with_upgrade_sync`]
    /// callback to finish before unpacking, so that the sole remaining strong reference is the one
    /// held by this `UniqueArc`.
    ///
    /// Note: do not call this from within a `with_upgrade[_sync]` callback operating on a
    /// [`UniqueWeak`] derived from `this`; the exclusive lease can never be granted while that
    /// callback holds its shared lease, so it would deadlock.
    pub async fn into_inner(this: Self) -> T {
        let UniqueArc { arc, gate } = this;
        // Wait for all outstanding upgrades to release their shared lease, and prevent new ones,
        // before unpacking. This guard is not held across an `.await`, so synchronous upgrades on a
        // single-threaded runtime can never observe it mid-unpack.
        let _exclusive = gate.write().await;
        Arc::into_inner(arc)
            .expect("no other strong reference exists: `UniqueArc` is `!Clone` and all upgrades are gated")
    }

    /// Produce a weak reference to this item
    pub fn downgrade(this: &Self) -> UniqueWeak<T> {
        UniqueWeak {
            weak: Arc::downgrade(&this.arc),
            gate: Arc::clone(&this.gate),
        }
    }
}

/// This type derefs to `T`, and holds the read guard for its lifetime, ensuring that
/// callers of [`UniqueWeak::upgrade`] neither remove the guard before the reads are complete
/// nor have the capability to clone additional instances of `Arc<T>`.
///
/// Field order matters here: struct fields drop in declaration order, so `t` (the strong
/// reference) must come before `_guard` (the read lease). Otherwise the lease would be released
/// while a strong reference is still live, letting [`UniqueArc::into_inner`] acquire the write
/// lease and panic on a doubled strong count.
#[derive(Debug, derive_more::Deref)]
struct ArcWithReadGuard<T> {
    #[deref(forward)]
    t: Arc<T>,
    _guard: RwLockReadGuardArc<()>,
}

/// A weak version of [`UniqueArc`] which holds a non-owning, non-lifetimed reference to the managed allocation.
///
/// This allocation is accessed by calling `with_upgrade` or `with_upgrade_sync` on the `UniqueWeak`, each of which
/// accepts a function which accepts an `&T` parameter.
#[derive(Debug)]
pub struct UniqueWeak<T> {
    weak: Weak<T>,
    /// Shared with the originating [`UniqueArc`]; a shared lease is held for the duration of each
    /// upgrade so that [`UniqueArc::into_inner`] cannot unpack while a temporary reference is alive.
    gate: Arc<RwLock<()>>,
}

impl<T> UniqueWeak<T> {
    /// Gain access to the wrapped member if it is available.
    ///
    /// Note that the return type here is `impl Deref<Target = T>`.
    /// This intentionally masks the real concrete type in order to prevent
    /// receivers from increasing the internal Arc's strong count.
    pub async fn upgrade(&self) -> Option<impl Deref<Target = T>> {
        let _guard = self.gate.read_arc().await;
        self.weak.upgrade().map(move |t| ArcWithReadGuard { _guard, t })
    }

    /// Synchronously gain access to the wrapped member if it is available.
    ///
    /// Unlike [`Self::upgrade`], this method cannot suspend, so it takes the
    /// shared guard with `try_read` and bails with `None` if the guard is held.
    /// This is a racy snapshot rather than a definitive check, because if
    /// `into_inner`'s future is dropped while parked waiting for readers to drain,
    /// the value survives, yet this call already reported it gone.
    pub fn upgrade_sync(&self) -> Option<impl Deref<Target = T>> {
        let _guard = self.gate.try_read_arc()?;
        self.weak.upgrade().map(move |t| ArcWithReadGuard { _guard, t })
    }
}

#[cfg_attr(target_os = "unknown", async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait)]
impl<T> FetchFromDatabase for UniqueArc<T>
where
    T: FetchFromDatabase,
{
    /// Get an instance of `E` from the database by its primary key.
    async fn get<E>(&self, id: &E::PrimaryKey) -> CryptoKeystoreResult<Option<E>>
    where
        E: 'static + Entity + Clone + Send + Sync,
    {
        <T as FetchFromDatabase>::get::<E>(&self.arc, id).await
    }

    /// Count the number of `E`s in the database.
    async fn count<E>(&self) -> CryptoKeystoreResult<u32>
    where
        E: 'static + Entity + Clone + Send + Sync,
    {
        <T as FetchFromDatabase>::count::<E>(&self.arc).await
    }

    /// Load all `E`s from the database.
    async fn load_all<E>(&self) -> CryptoKeystoreResult<Vec<E>>
    where
        E: 'static + Entity + Clone + Send + Sync,
    {
        <T as FetchFromDatabase>::load_all::<E>(&self.arc).await
    }

    /// Get an instance of `E` from the database by the borrowed form of its primary key.
    async fn get_borrowed<E>(&self, id: &<E as BorrowPrimaryKey>::BorrowedPrimaryKey) -> CryptoKeystoreResult<Option<E>>
    where
        E: 'static + EntityGetBorrowed + Clone + Send + Sync,
        E::PrimaryKey: Borrow<E::BorrowedPrimaryKey>,
        for<'a> &'a E::BorrowedPrimaryKey: KeyType,
    {
        <T as FetchFromDatabase>::get_borrowed::<E>(&self.arc, id).await
    }

    /// Get the requested unique entity from the database.
    async fn get_unique<'a, U>(&self) -> CryptoKeystoreResult<Option<U>>
    where
        U: 'static + UniqueEntityExt + Entity + Clone + Send + Sync,
    {
        <T as FetchFromDatabase>::get_unique(&self.arc).await
    }

    /// Determine whether a unique entity is present in the database.
    async fn exists<'a, U>(&self) -> CryptoKeystoreResult<bool>
    where
        U: 'static + UniqueEntityExt + Entity + Clone + Send + Sync,
    {
        <T as FetchFromDatabase>::exists::<U>(&self.arc).await
    }

    /// Search for relevant instances of `E` given a search key.
    async fn search<E, SearchKey>(&self, search_key: &SearchKey) -> CryptoKeystoreResult<Vec<E>>
    where
        E: 'static + Entity + SearchableEntity<SearchKey> + Clone + Send + Sync,
        SearchKey: KeyType,
    {
        <T as FetchFromDatabase>::search::<E, SearchKey>(&self.arc, search_key).await
    }
}

#[cfg(all(test, not(target_os = "unknown")))]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use async_lock::Semaphore;
    use futures_lite::future;

    use super::UniqueArc;

    #[test]
    fn derefs_to_the_inner_value() {
        let arc = UniqueArc::from(vec![1, 2, 3]);
        // method resolves on `T` via the forwarded `Deref`
        assert_eq!(arc.len(), 3);
        assert_eq!(&*arc, &[1, 2, 3]);
    }

    #[test]
    fn into_inner_returns_the_value() {
        future::block_on(async {
            let arc = UniqueArc::from(String::from("hello"));
            assert_eq!(UniqueArc::into_inner(arc).await, "hello");
        });
    }

    #[test]
    fn outstanding_weaks_do_not_block_unpacking() {
        future::block_on(async {
            // A `UniqueWeak` that never upgrades holds no strong reference, so it must not prevent
            // `into_inner` from succeeding: weak references are fine, only live upgrades are not.
            let arc = UniqueArc::from(7_u32);
            let _weak = UniqueArc::downgrade(&arc);
            assert_eq!(UniqueArc::into_inner(arc).await, 7);
        });
    }

    #[test]
    fn upgrade_sees_the_value_while_alive() {
        future::block_on(async {
            let arc = UniqueArc::from(42_u32);
            let weak = UniqueArc::downgrade(&arc);

            // both variants hand back a guard that derefs to the live value
            assert_eq!(weak.upgrade().await.as_deref(), Some(&42));
            assert_eq!(weak.upgrade_sync().as_deref(), Some(&42));

            // keep `arc` alive until here
            assert_eq!(*arc, 42);
        });
    }

    #[test]
    fn upgrade_fails_once_unpacked() {
        future::block_on(async {
            let arc = UniqueArc::from(42_u32);
            let weak = UniqueArc::downgrade(&arc);

            assert_eq!(UniqueArc::into_inner(arc).await, 42);

            // the allocation is gone, so both variants report the value as unavailable
            assert!(weak.upgrade().await.is_none());
            assert!(weak.upgrade_sync().is_none());
        });
    }

    /// Regression test for the original soundness bug: an in-flight upgrade holds a temporary
    /// strong reference (behind the returned guard) across an `.await`, so a naive `into_inner`
    /// would observe two strong references and panic. `into_inner` must instead wait for the guard
    /// to be dropped.
    #[test]
    fn into_inner_waits_for_an_in_flight_upgrade() {
        future::block_on(async {
            let arc = UniqueArc::from(42_u32);
            let weak = UniqueArc::downgrade(&arc);

            // one-shot signals between the two concurrent futures
            let holding = Semaphore::new(0); // upgrade -> take: "I hold a temporary strong ref"
            let proceed = Semaphore::new(0); // take -> upgrade: "you may release it now"
            let unpacked = AtomicBool::new(false);

            let upgrade = async {
                let guard = weak.upgrade().await.expect("value is still alive");
                assert_eq!(*guard, 42);
                // announce that a temporary strong reference is now live, then hold it
                holding.add_permits(1);
                proceed.acquire().await;
                // `into_inner` must not have unpacked while we still hold the guard
                assert!(
                    !unpacked.load(Ordering::SeqCst),
                    "into_inner unpacked while an upgrade was still live"
                );
                *guard
                // `guard` drops here, releasing the strong reference and then the read lease
            };

            let take = async {
                // wait until the upgrade is definitely holding its strong reference ...
                holding.acquire().await;
                // ... release it, then take. `into_inner` must wait for the guard to drop
                // rather than panicking on the transiently-doubled strong count.
                proceed.add_permits(1);
                let value = UniqueArc::into_inner(arc).await;
                unpacked.store(true, Ordering::SeqCst);
                value
            };

            let (upgraded, taken) = future::zip(upgrade, take).await;
            assert_eq!(upgraded, 42);
            assert_eq!(taken, 42);
        });
    }
}
