mod client;
pub(crate) mod command;
pub(crate) mod conversation;
pub(crate) mod e2ei;
pub(crate) mod epoch_observer;
pub(crate) mod history_observer;
pub(crate) mod logger;
pub(crate) mod mls_transport;
mod proteus;
mod randomness;

use core_crypto::{Session, SessionConfig, ValidatedSessionConfig};

use crate::{
    CoreCryptoResult,
    database::{DatabaseMaybeArc, ToCc as _},
};

/// In uniffi, a vector is the natural way to communicate a byte slice
pub(crate) type EntropySeed = Vec<u8>;

#[expect(dead_code)]
// Will be needed when implementing WPB-19570
pub(crate) fn entropy_seed_map(e: EntropySeed) -> Vec<u8> {
    e
}

/// CoreCrypto wraps around MLS and Proteus implementations and provides a transactional interface for each.
#[derive(Debug, uniffi::Object)]
pub struct CoreCryptoFfi {
    pub(crate) inner: core_crypto::CoreCrypto,
}

/// Free function to construct a new `CoreCryptoFfi` instance.
///
/// This is necessary because in uniffi async constructors are not supported.
///
/// MLS or proteus can be initialized  with [core_crypto::transaction_context::TransactionContext::mls_init] or
/// [core_crypto::transaction_context::TransactionContext::proteus_init], respectively.
#[uniffi::export]
pub async fn core_crypto_new(database: DatabaseMaybeArc) -> CoreCryptoResult<CoreCryptoFfi> {
    CoreCryptoFfi::new(database).await
}

impl CoreCryptoFfi {
    /// Instantiate CC
    pub async fn new(database: DatabaseMaybeArc) -> CoreCryptoResult<Self> {
        let configuration = SessionConfig::builder().database(database.to_cc()).build().validate()?;
        CoreCryptoFfi::from_config(configuration).await
    }

    async fn from_config(configuration: ValidatedSessionConfig) -> CoreCryptoResult<Self> {
        let client = Session::try_new(configuration).await?;
        let inner = core_crypto::CoreCrypto::from(client);

        Ok(Self { inner })
    }
}
