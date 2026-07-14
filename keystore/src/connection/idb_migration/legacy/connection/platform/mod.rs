pub(crate) mod wasm;

pub(crate) use self::wasm::{
    WasmConnection as KeystoreDatabaseConnection,
    storage::{self, WasmStorageTransaction as TransactionWrapper},
};
