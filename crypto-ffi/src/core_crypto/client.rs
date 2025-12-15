use crate::{Ciphersuite, CoreCryptoFfi, CoreCryptoResult, CredentialType};

#[uniffi::export]
impl CoreCryptoFfi {
    /// Gets the public key from a [`Credential`][crate::Credential] which has been added to this client.
    ///
    /// The ciphersuite and credential type act as filters.
    ///
    /// If there exist multiple credentials which match these filters, this returns the one with
    /// the latest `earliest_validity`.
    ///
    /// See [core_crypto::transaction_context::TransactionContext::client_public_key]
    pub async fn client_public_key(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
    ) -> CoreCryptoResult<Vec<u8>> {
        self.inner
            .mls_session()
            .await?
            .public_key(ciphersuite.into(), credential_type.into())
            .await
            .map_err(Into::into)
    }
}
