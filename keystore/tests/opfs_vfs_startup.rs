#![cfg(target_os = "unknown")]

use std::sync::Arc;

use core_crypto_keystore::{CryptoKeystoreError, Database, DatabaseKey};
use rsqlite_vfs::{VfsError, VfsErrorCode};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen_test::wasm_bindgen_test_configure;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen(module = "/src/connection/opfs_vfs_test.js")]
extern "C" {
    fn suppress_first_worker_init_reply();
    fn first_worker_init_reply_was_suppressed() -> bool;
    fn restore_worker_constructor();
}

struct WorkerInstrumentationCleanup;

impl Drop for WorkerInstrumentationCleanup {
    fn drop(&mut self) {
        restore_worker_constructor();
    }
}

#[wasm_bindgen_test::wasm_bindgen_test]
fn opfs_error_display_preserves_context_and_worker_failure_reason() {
    // `CoreCryptoError::generic()` forwards the keystore error's Display string through the database FFI.
    let timeout_error = CryptoKeystoreError::OpfsError {
        context: "installing the OPFS VFS",
        error: VfsError::new(
            VfsErrorCode::CantOpen,
            "OPFS worker initialization timed out after 2000 ms; retry failed: OpfsWorkerStartupTimeout: OPFS worker initialization timed out after 2000 ms".into(),
        ),
    };
    let visible_timeout_message = timeout_error.to_string();
    assert!(visible_timeout_message.contains("installing the OPFS VFS"));
    assert!(visible_timeout_message.contains("initialization timed out"));
    assert!(visible_timeout_message.contains("retry failed"));

    let explicit_failure = CryptoKeystoreError::OpfsError {
        context: "installing the OPFS VFS",
        error: VfsError::new(VfsErrorCode::CantOpen, "OPFS SecurityError: storage denied".into()),
    };
    let visible_explicit_failure_message = explicit_failure.to_string();
    assert!(visible_explicit_failure_message.contains("installing the OPFS VFS"));
    assert!(visible_explicit_failure_message.contains("SecurityError: storage denied"));
}

#[core_crypto_macros::jspi_wasm_bindgen_test]
async fn database_open_retries_after_first_worker_init_timeout() {
    let _instrumentation_cleanup = WorkerInstrumentationCleanup;
    suppress_first_worker_init_reply();

    let database_name = format!("opfs-startup-retry-{}.db", uuid::Uuid::new_v4());
    let database_key = DatabaseKey::generate();
    let database = Database::open(&database_name, &database_key)
        .await
        .expect("database open should succeed after one init timeout");

    assert!(first_worker_init_reply_was_suppressed());
    Arc::into_inner(database)
        .expect("the test owns the only database reference")
        .wipe()
        .await
        .expect("database cleanup should succeed");
}
