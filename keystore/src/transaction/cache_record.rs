use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use async_lock::{RwLock, RwLockReadGuardArc, RwLockUpgradableReadGuard, RwLockWriteGuard};

/// Represents a cached db entity and it's persistence state.
/// `None` represents a deletion, a dirty `Some()` represents an upsert, a non-dirty `Some()` represents a read.
/// Accordingly, those operations will be executed when the transaction is finished.
/// A dirty record has to be persisted at the end of a transaction.
#[derive(Debug)]
pub(crate) struct CacheRecord<E> {
    lock: Arc<RwLock<Option<E>>>,
    dirty: AtomicBool,
}

impl<E> CacheRecord<E> {
    pub(crate) fn new(entity: Option<E>, dirty: bool) -> Self {
        Self {
            lock: Arc::new(RwLock::new(entity)),
            dirty: AtomicBool::new(dirty),
        }
    }

    /// we still want to allow upgradable read guards but it's the callers responsibility to set the record dirty
    pub async fn upgradable_read(&self) -> RwLockUpgradableReadGuard<Option<E>> {
        self.lock.upgradable_read().await
    }

    pub async fn read_arc(&self) -> RwLockReadGuardArc<Option<E>> {
        self.lock.read_arc().await
    }

    pub(crate) async fn write(&self) -> RwLockWriteGuard<Option<E>> {
        self.set_dirty();
        self.lock.write().await
    }

    pub(crate) fn set_dirty(&self) {
        self.dirty.store(true, Ordering::Release);
    }

    pub(crate) fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Acquire)
    }
}
