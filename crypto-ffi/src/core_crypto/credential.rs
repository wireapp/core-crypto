use std::sync::Arc;

use crate::{CoreCryptoFfi, CoreCryptoResult, CredentialRef};

#[uniffi::export]
impl CoreCryptoFfi {
    /// Get the public key associated with this credential
    pub async fn public_key(&self, credential_ref: Arc<CredentialRef>) -> CoreCryptoResult<Vec<u8>> {
        self.inner.public_key(&credential_ref.0).await.map_err(Into::into)
    }
}
