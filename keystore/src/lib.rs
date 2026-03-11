#![doc = include_str!("../README.md")]
#![doc = include_str!("../../docs/KEYSTORE_IMPLEMENTATION.md")]

pub mod connection;
mod database_key;
pub mod entities;
mod error;
mod hash;
pub(crate) mod migrations;
pub(crate) mod mls;
#[cfg(feature = "proteus-keystore")]
pub(crate) mod proteus;
pub mod traits;
pub mod transaction;

pub use hash::Sha256Hash;
pub(crate) use hash::sha256;

#[cfg(feature = "dummy-entity")]
pub use self::entities::{DummyStoreValue, DummyValue};
#[cfg(feature = "proteus-keystore")]
pub use self::proteus::CryptoKeystoreProteus;
pub use self::{
    connection::{ConnectionType, Database},
    database_key::DatabaseKey,
    error::{CryptoKeystoreError, CryptoKeystoreResult},
    mls::{CryptoKeystoreMls, deser, ser},
};
