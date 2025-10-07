use core_crypto::RecursiveError;

use crate::{Ciphersuite, CoreCryptoFfi, CoreCryptoResult};

pub(crate) mod identities;

// End-to-end identity methods
#[uniffi::export]
impl CoreCryptoFfi {
    /// See [core_crypto::Session::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> bool {
        self.inner.e2ei_is_pki_env_setup().await
    }

    /// See [core_crypto::Session::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> CoreCryptoResult<bool> {
        let signature_scheme = core_crypto::Ciphersuite::from(ciphersuite).signature_algorithm();
        self.inner
            .e2ei_is_enabled(signature_scheme)
            .await
            .map_err(RecursiveError::mls_client("checking if e2ei is enabled"))
            .map_err(Into::into)
    }
}
