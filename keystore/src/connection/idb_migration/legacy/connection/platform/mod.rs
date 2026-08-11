pub(crate) mod wasm;

pub(crate) use self::wasm::WasmConnection as KeystoreDatabaseConnection;
pub(crate) use self::wasm::storage::WasmStorageTransaction as TransactionWrapper;
pub(crate) use self::wasm::storage::{self};
