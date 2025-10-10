use crate::{Ciphersuite, CoreCryptoFfi, CoreCryptoResult, CredentialType};

#[uniffi::export]
impl CoreCryptoFfi {
    /// See [core_crypto::transaction_context::TransactionContext::client_public_key]
    pub async fn client_public_key(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
    ) -> CoreCryptoResult<Vec<u8>> {
        self.inner
            .public_key(ciphersuite.into(), credential_type.into())
            .await
            .map_err(Into::into)
    }
}
