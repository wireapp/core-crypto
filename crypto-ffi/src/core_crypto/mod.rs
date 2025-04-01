mod client;
mod conversation;
pub mod logger;
pub mod mls_transport;

use core_crypto::prelude::{Client, MlsClientConfiguration};
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(target_family = "wasm")]
use crate::WasmCryptoResult;
use crate::{Ciphersuites, ClientId, CoreCryptoResult, DatabaseKey, error::internal::InternalError};

/// In Wasm, boxed slices are the natural way to communicate an immutable byte slice
#[cfg(target_family = "wasm")]
type EntropySeed = Box<[u8]>;

/// In uniffi, a vector is the natural way to communicate a byte slice
#[cfg(not(target_family = "wasm"))]
type EntropySeed = Vec<u8>;

#[cfg(target_family = "wasm")]
fn entropy_seed_map(e: EntropySeed) -> Vec<u8> {
    e.into()
}

#[cfg(not(target_family = "wasm"))]
fn entropy_seed_map(e: EntropySeed) -> Vec<u8> {
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
/// See [core_crypto::mls::MlsCentral::try_new]
#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
pub async fn core_crypto_new(
    path: String,
    key: DatabaseKey,
    client_id: ClientId,
    ciphersuites: Ciphersuites,
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
/// with [CoreCryptoContext::mls_init].
#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
pub async fn core_crypto_deferred_init(
    path: String,
    key: DatabaseKey,
    entropy_seed: Option<EntropySeed>,
) -> CoreCryptoResult<CoreCrypto> {
    let entropy_seed = entropy_seed.map(entropy_seed_map);
    let configuration = MlsClientConfiguration::try_new(path, key.into(), None, Vec::new(), entropy_seed, None)?;
    CoreCrypto::from_config(configuration).await
}

impl CoreCrypto {
    async fn from_config(configuration: MlsClientConfiguration) -> CoreCryptoResult<Self> {
        #[cfg(target_family = "wasm")]
        console_error_panic_hook::set_once();

        let central = Client::try_new(configuration).await?;
        let inner = core_crypto::CoreCrypto::from(central);

        Ok(Self { inner })
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl CoreCrypto {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
    #[cfg_attr(not(target_family = "wasm"), uniffi::constructor)]
    pub async fn new(
        path: String,
        key: DatabaseKey,
        client_id: Option<ClientId>,
        ciphersuites: Option<Ciphersuites>,
        entropy_seed: Option<EntropySeed>,
        nb_key_package: Option<u32>,
    ) -> CoreCryptoResult<Self> {
        let nb_key_package = nb_key_package
            .map(usize::try_from)
            .transpose()
            .map_err(InternalError::generic())?;
        let entropy_seed = entropy_seed.map(entropy_seed_map);
        let configuration = MlsClientConfiguration::try_new(
            path,
            key.into(),
            client_id.map(|cid| cid.0.clone()),
            (&ciphersuites.unwrap_or_default()).into(),
            entropy_seed,
            nb_key_package,
        )?;
        Self::from_config(configuration).await
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl CoreCrypto {
    pub async fn deferred_init(
        path: String,
        key: DatabaseKey,
        entropy_seed: Option<Box<[u8]>>,
    ) -> WasmCryptoResult<CoreCrypto> {
        let entropy_seed = entropy_seed.map(|s| s.to_vec());
        let configuration = MlsClientConfiguration::try_new(path, key.into(), None, vec![], entropy_seed, None)
            .map_err(InternalError::from)?;

        Self::from_config(configuration).await
    }
}
