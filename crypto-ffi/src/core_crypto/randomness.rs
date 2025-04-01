#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{CoreCrypto, CoreCryptoError, CoreCryptoResult};

use super::EntropySeed;

#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl CoreCrypto {
    /// See [core_crypto::mls::MlsCentral::random_bytes]
    pub async fn random_bytes(&self, len: u32) -> CoreCryptoResult<Vec<u8>> {
        let len = len.try_into().map_err(CoreCryptoError::generic())?;
        self.inner.random_bytes(len).map_err(Into::into)
    }

    /// see [core_crypto::prelude::MlsCryptoProvider::reseed]
    pub async fn reseed_rng(&self, seed: EntropySeed) -> CoreCryptoResult<()> {
        let seed = core_crypto::prelude::EntropySeed::try_from_slice(&seed).map_err(CoreCryptoError::generic())?;
        self.inner.reseed(Some(seed)).await?;

        Ok(())
    }
}
