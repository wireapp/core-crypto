#![doc = include_str!("../README.md")]
#![doc = include_str!("../../docs/KEYSTORE_IMPLEMENTATION.md")]

pub mod connection;
pub mod entities;
mod error;
mod hash;
pub(crate) mod migrations;
pub(crate) mod mls;
#[cfg(feature = "proteus-keystore")]
pub(crate) mod proteus;
pub mod traits;
pub mod transaction;

#[cfg(feature = "dummy-entity")]
pub use self::entities::{DummyStoreValue, DummyValue, NewDummyStoreValue};
#[cfg(feature = "proteus-keystore")]
pub use self::proteus::CryptoKeystoreProteus;
pub use self::{
    connection::{ConnectionType, Database, DatabaseKey},
    error::{CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind},
    mls::{CryptoKeystoreMls, deser, ser},
};
#[cfg(not(target_family = "wasm"))]
pub(crate) use hash::sha256;
