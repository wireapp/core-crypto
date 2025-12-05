#![doc = include_str!("../README.md")]
#![doc = include_str!("../../docs/KEYSTORE_IMPLEMENTATION.md")]

pub mod connection;
pub mod entities;
mod error;
pub(crate) mod migrations;
pub(crate) mod mls;
#[cfg(feature = "proteus-keystore")]
pub(crate) mod proteus;
pub mod traits;
pub mod transaction;

#[cfg(not(target_family = "wasm"))]
use sha2::{Digest, Sha256};

#[cfg(feature = "dummy-entity")]
pub use self::entities::{DummyStoreValue, DummyValue, NewDummyStoreValue};
#[cfg(feature = "proteus-keystore")]
pub use self::proteus::CryptoKeystoreProteus;
pub use self::{
    connection::{ConnectionType, Database, DatabaseKey},
    error::{CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind},
    mls::{CryptoKeystoreMls, deser, ser},
};

/// Used to calculate ID hashes for some MlsEntities' SQLite tables (not used on wasm).
/// We only use sha256 on platforms where we use SQLite.
/// On wasm, we use IndexedDB, a key-value store, via the idb crate.
#[cfg(not(target_family = "wasm"))]
pub(crate) fn sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
