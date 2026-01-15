#[cfg(not(target_family = "wasm"))]
mod generic;
#[cfg(target_family = "wasm")]
mod wasm;

#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) use self::generic::MigrationTarget;
#[cfg(not(target_family = "wasm"))]
pub use self::generic::{SqlCipherConnection as KeystoreDatabaseConnection, TransactionWrapper};
#[cfg(target_family = "wasm")]
pub use self::wasm::{
    WasmConnection as KeystoreDatabaseConnection,
    storage::{self, WasmStorageTransaction as TransactionWrapper},
};
