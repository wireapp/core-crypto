use core_crypto::RecursiveError;

use crate::{Ciphersuite, CoreCryptoFfi, CoreCryptoResult};

pub(crate) mod identities;

// End-to-end identity methods
#[uniffi::export]
impl CoreCryptoFfi {
    /// See [core_crypto::Session::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> CoreCryptoResult<bool> {
        // TODO: don't depend on mls session WPB-19578
        let result = self.inner.mls_session().await?.e2ei_is_pki_env_setup().await;
        Ok(result)
    }

    /// See [core_crypto::Session::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> CoreCryptoResult<bool> {
        self.inner
            .mls_session()
            .await?
            .e2ei_is_enabled(ciphersuite.into())
            .await
            .map_err(RecursiveError::mls_client("checking if e2ei is enabled"))
            .map_err(Into::into)
    }
}
