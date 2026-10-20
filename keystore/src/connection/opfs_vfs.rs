//! A minimal SQLite VFS storing files in OPFS.
//!
//! OPFS synchronous access handles are only available in dedicated workers, so a small worker
//! (see `opfs_vfs.js`) owns them. SQLite stays on the calling thread: each VFS callback makes one
//! request to the worker and suspends through JSPI until the reply arrives.
//!
//! Consequently, all SQLite entry must happen from within a JSPI export, and must hold
//! `SqliteGuard` so that no other JSPI export enters SQLite while a callback is suspended.
//!
//! Locks are no-ops: we use `locking_mode=EXCLUSIVE` and one connection per database. Another tab
//! (or a second connection) cannot open a file whose access handle is held, and gets `SQLITE_BUSY`.

#![allow(deprecated)] // wasm-bindgen's JSPI API is experimental.

use std::{cell::RefCell, collections::VecDeque};

use async_lock::{Mutex, MutexGuard};
use js_sys::futures::{future_to_promise, jspi_block_on_promise};
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

#[wasm_bindgen(module = "/src/connection/opfs_vfs.js")]
extern "C" {
    #[wasm_bindgen(js_name = scheduleCleanup)]
    fn schedule_cleanup(exports: &JsValue);
}

static SQLITE: Mutex<()> = Mutex::new(());

thread_local! {
    static CLEANUP: RefCell<VecDeque<Box<dyn FnOnce()>>> = RefCell::default();
}

/// Exclusive entry to SQLite for this Wasm instance.
///
/// Hold this around one complete SQLite operation.
/// It is non-reentrant. Contended acquisition suspends, so it must happen within a JSPI export.
pub(crate) struct SqliteGuard {
    _guard: MutexGuard<'static, ()>,
}

impl SqliteGuard {
    pub(crate) fn lock() -> Self {
        let guard = SQLITE.try_lock().unwrap_or_else(|| {
            let slot = std::rc::Rc::new(RefCell::new(None));
            let result = slot.clone();
            jspi_block_on_promise(&future_to_promise(async move {
                *result.borrow_mut() = Some(SQLITE.lock().await);
                Ok(JsValue::UNDEFINED)
            }))
            .expect("SQLite entry requires a JSPI boundary");
            slot.take().expect("SQLite lock acquired")
        });
        // Pop before invoking: cleanup may suspend or enqueue more cleanup.
        while let Some(cleanup) = CLEANUP.with_borrow_mut(VecDeque::pop_front) {
            cleanup();
        }
        Self { _guard: guard }
    }
}

/// Defers SQLite cleanup from `Drop`, which may run outside of a JSPI export.
///
/// The cleanup runs under `SqliteGuard`, within the next JSPI entry. It must not acquire the guard itself.
pub fn defer(cleanup: impl FnOnce() + 'static) {
    CLEANUP.with_borrow_mut(|queue| queue.push_back(Box::new(cleanup)));
    schedule_cleanup(&wasm_bindgen::exports());
}

#[wasm_bindgen(jspi)]
#[expect(
    unreachable_pub,
    reason = "called through the Wasm exports object by `scheduleCleanup`"
)]
pub fn core_crypto_keystore_sqlite_cleanup() {
    let _sqlite = SqliteGuard::lock();
}
