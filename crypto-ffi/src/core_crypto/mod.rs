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

use core_crypto::prelude::{Session, SessionConfig, ValidatedSessionConfig};
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    CoreCryptoError, CoreCryptoResult, DatabaseKey, ciphersuite::CiphersuitesMaybeArc, client_id::ClientIdMaybeArc,
};

/// In Wasm, boxed slices are the natural way to communicate an immutable byte slice
#[cfg(target_family = "wasm")]
pub(crate) type EntropySeed = Box<[u8]>;

/// In uniffi, a vector is the natural way to communicate a byte slice
#[cfg(not(target_family = "wasm"))]
pub(crate) type EntropySeed = Vec<u8>;

#[cfg(target_family = "wasm")]
pub(crate) fn entropy_seed_map(e: EntropySeed) -> Vec<u8> {
    e.into()
}

#[cfg(not(target_family = "wasm"))]
pub(crate) fn entropy_seed_map(e: EntropySeed) -> Vec<u8> {
    e
}

#[derive(Debug)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Object))]
pub struct CoreCrypto {
    pub(crate) inner: core_crypto::CoreCrypto,
}

/// Free function to construct a new `CoreCrypto` instance.
///
/// This is necessary because in uniffi async constructors are not supported.
///
/// See [Session::try_new]
#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
pub async fn core_crypto_new(
    path: String,
    key: DatabaseKey,
    client_id: ClientIdMaybeArc,
    ciphersuites: CiphersuitesMaybeArc,
    entropy_seed: Option<EntropySeed>,
    nb_key_package: Option<u32>,
) -> CoreCryptoResult<CoreCrypto> {
    CoreCrypto::new(
        path,
        key,
        Some(client_id),
        Some(ciphersuites),
        entropy_seed,
        nb_key_package,
    )
    .await
}

/// Free function to construct a new `CoreCrypto` instance.
///
/// Similar to [`core_crypto_new`] but defers MLS initialization. It can be initialized later
/// with [core_crypto::transaction_context::TransactionContext::mls_init].
#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
pub async fn core_crypto_deferred_init(
    path: String,
    key: DatabaseKey,
    entropy_seed: Option<EntropySeed>,
) -> CoreCryptoResult<CoreCrypto> {
    CoreCrypto::deferred_init_impl(path, key, entropy_seed).await
}

impl CoreCrypto {
    pub async fn new(
        path: String,
        key: DatabaseKey,
        client_id: Option<ClientIdMaybeArc>,
        ciphersuites: Option<CiphersuitesMaybeArc>,
        entropy_seed: Option<EntropySeed>,
        nb_key_packages: Option<u32>,
    ) -> CoreCryptoResult<Self> {
        let nb_key_packages = nb_key_packages
            .map(usize::try_from)
            .transpose()
            .map_err(CoreCryptoError::generic())?;
        let entropy_seed = entropy_seed.map(entropy_seed_map);
        let configuration = SessionConfig::builder()
            .persistent(&path)
            .database_key(key.into())
            .client_id_opt(client_id.map(|cid| cid.as_cc()))
            .ciphersuites(ciphersuites.unwrap_or_default().iter().map(Into::into))
            .external_entropy_opt(entropy_seed.as_deref())
            .nb_key_packages(nb_key_packages)
            .build()
            .validate()?;
        Self::from_config(configuration).await
    }

    async fn deferred_init_impl(
        path: String,
        key: DatabaseKey,
        entropy_seed: Option<EntropySeed>,
    ) -> CoreCryptoResult<Self> {
        let entropy_seed = entropy_seed.map(entropy_seed_map);
        let configuration = SessionConfig::builder()
            .persistent(&path)
            .database_key(key.into())
            .external_entropy_opt(entropy_seed.as_deref())
            .build()
            .validate()?;
        CoreCrypto::from_config(configuration).await
    }

    async fn from_config(configuration: ValidatedSessionConfig<'_>) -> CoreCryptoResult<Self> {
        #[cfg(target_family = "wasm")]
        console_error_panic_hook::set_once();

        let client = Session::try_new(configuration).await?;
        let inner = core_crypto::CoreCrypto::from(client);

        Ok(Self { inner })
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl CoreCrypto {
    pub async fn async_new(
        path: String,
        key: DatabaseKey,
        client_id: Option<ClientIdMaybeArc>,
        ciphersuites: Option<CiphersuitesMaybeArc>,
        entropy_seed: Option<EntropySeed>,
        nb_key_package: Option<u32>,
    ) -> CoreCryptoResult<Self> {
        Self::new(path, key, client_id, ciphersuites, entropy_seed, nb_key_package).await
    }

    pub async fn deferred_init(
        path: String,
        key: DatabaseKey,
        entropy_seed: Option<Box<[u8]>>,
    ) -> CoreCryptoResult<CoreCrypto> {
        CoreCrypto::deferred_init_impl(path, key, entropy_seed).await
    }

    /// See [Session::close]
    // Note that this is implemented only for Wasm; Uniffi already generates a `close` method which suffices.
    pub async fn close(self) -> CoreCryptoResult<()> {
        self.inner.take().close().await.map_err(Into::into)
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl CoreCrypto {
    /// See [Session::can_close]
    pub async fn can_close(&self) -> bool {
        self.inner.can_close().await
    }
}
