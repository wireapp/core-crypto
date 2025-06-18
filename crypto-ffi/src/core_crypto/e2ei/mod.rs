use core_crypto::RecursiveError;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{Ciphersuite, CoreCrypto, CoreCryptoResult};

pub(crate) mod identities;

// End-to-end identity methods
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl CoreCrypto {
    /// See [core_crypto::prelude::Session::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> bool {
        self.inner.e2ei_is_pki_env_setup().await
    }

    /// See [core_crypto::prelude::Session::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> CoreCryptoResult<bool> {
        let signature_scheme =
            core_crypto::prelude::MlsCiphersuite::from(core_crypto::prelude::CiphersuiteName::from(ciphersuite))
                .signature_algorithm();
        self.inner
            .e2ei_is_enabled(signature_scheme)
            .await
            .map_err(RecursiveError::mls_client("checking if e2ei is enabled"))
            .map_err(Into::into)
    }
}
