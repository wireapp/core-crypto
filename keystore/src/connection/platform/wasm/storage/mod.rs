// This isn't a problem because it's hidden from everyone outside this very local module:
// outside this scope, all internal modules are hidden, and everything appears flattened
// into here.
//
// These internal modules exist only for eufactorization. As such it doesn't really matter what they are named.
#[allow(clippy::module_inception)]
mod storage;
mod transaction;
mod wrapper;

use std::collections::HashMap;

use wasm_bindgen::JsValue;

pub use self::{storage::WasmEncryptedStorage, transaction::WasmStorageTransaction, wrapper::WasmStorageWrapper};

type InMemoryDB = HashMap<String, HashMap<Vec<u8>, JsValue>>;
