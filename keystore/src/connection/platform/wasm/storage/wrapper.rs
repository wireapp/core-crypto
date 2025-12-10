use std::{cell::RefCell, rc::Rc};

use super::InMemoryDB;

pub enum WasmStorageWrapper {
    Persistent(idb::Database),
    InMemory(Rc<RefCell<InMemoryDB>>),
}

impl std::fmt::Debug for WasmStorageWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::Persistent(idb) => f
                .debug_tuple("WasmStorageWrapper::Persistent")
                .field(&idb.name())
                .finish(),
            Self::InMemory(map) => f.debug_tuple("WasmStorageWrapper::InMemory").field(map).finish(),
        }
    }
}
