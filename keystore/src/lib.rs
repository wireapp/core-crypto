// Lets `core_crypto_macros::jspi_wasm_bindgen_test` refer to this crate by name in its own unit tests.
#[cfg(all(test, target_os = "unknown"))]
extern crate self as core_crypto_keystore;

pub mod ancillary;
pub mod connection;
mod database_key;
pub mod entities;
mod error;
mod hash;
pub(crate) mod migrations;
pub mod traits;
pub mod transaction;
mod transactionlike;
mod unique_arc;

pub use hash::Sha256Hash;
pub(crate) use hash::sha256;
pub use unique_arc::UniqueArc;

#[cfg(feature = "dummy-entity")]
pub use self::entities::{DummyStoreValue, DummyValue};
pub use self::{
    connection::{Database, deser, ser},
    database_key::DatabaseKey,
    error::{CryptoKeystoreError, CryptoKeystoreResult, RusqliteError, RusqliteErrorCode},
    transaction::Transaction,
    transactionlike::Transactionlike,
};
