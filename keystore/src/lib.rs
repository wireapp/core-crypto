#![doc = include_str!("../README.md")]
#![doc = include_str!("../../docs/KEYSTORE_IMPLEMENTATION.md")]

mod error;
pub use error::*;

pub mod connection;
pub use connection::{ConnectionType, Database, DatabaseKey};
pub mod entities;
pub(crate) mod migrations;
pub mod transaction;

pub(crate) mod mls;
pub use self::mls::{CryptoKeystoreMls, deser, ser};

cfg_if::cfg_if! {
    if #[cfg(feature = "proteus-keystore")] {
        pub(crate) mod proteus;
        pub use self::proteus::CryptoKeystoreProteus;
    }
}
#[cfg(feature = "dummy-entity")]
pub use self::entities::{DummyStoreValue, DummyValue};

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
