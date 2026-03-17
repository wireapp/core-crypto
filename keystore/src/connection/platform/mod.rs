#[cfg(not(target_os = "unknown"))]
mod generic;
#[cfg(target_os = "unknown")]
pub(crate) mod wasm;

#[cfg(all(test, not(target_os = "unknown")))]
pub(crate) use self::generic::MigrationTarget;
#[cfg(not(target_os = "unknown"))]
pub use self::generic::{SqlCipherConnection as KeystoreDatabaseConnection, TransactionWrapper};
#[cfg(target_os = "unknown")]
pub use self::wasm::{
    WasmConnection as KeystoreDatabaseConnection,
    storage::{self, WasmStorageTransaction as TransactionWrapper},
};
