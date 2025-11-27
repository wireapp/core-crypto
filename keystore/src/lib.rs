#![doc = include_str!("../README.md")]
#![doc = include_str!("../../docs/KEYSTORE_IMPLEMENTATION.md")]

pub mod connection;
pub mod entities;
mod error;
pub(crate) mod migrations;
pub(crate) mod mls;
#[cfg(feature = "proteus-keystore")]
pub(crate) mod proteus;
mod traits;
pub mod transaction;

pub use self::connection::{ConnectionType, Database, DatabaseKey};
#[cfg(feature = "dummy-entity")]
pub use self::entities::{DummyStoreValue, DummyValue};
pub use self::error::*;
#[cfg(target_family = "wasm")]
pub use self::traits::EntityEncryptionExt;
pub use self::traits::{
    Entity, EntityBase, EntityGetBorrowed, EntityTransactionDeleteBorrowed, EntityTransactionExt, FetchFromDatabase,
    KeyType, UniqueEntity, UniqueEntityExt,
};

#[cfg(not(target_family = "wasm"))]
use sha2::{Digest, Sha256};

/// Used to calculate ID hashes for some MlsEntities' SQLite tables (not used on wasm).
/// We only use sha256 on platforms where we use SQLite.
/// On wasm, we use IndexedDB, a key-value store, via the idb crate.
#[cfg(not(target_family = "wasm"))]
pub(crate) fn sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
