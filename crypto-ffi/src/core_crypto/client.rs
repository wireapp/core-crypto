#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Ciphersuite, CoreCryptoFfi, CoreCryptoResult, CredentialType, credential_ref::CredentialRefMaybeArc,
    error::core_crypto::CoreCryptoError,
};

#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
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
            .public_key(ciphersuite.into(), credential_type.into())
            .await
            .map_err(Into::into)
    }

    /// Add a [`Credential`][crate::Credential] to this client.
    ///
    /// Note that while an arbitrary number of credentials can be generated,
    /// those which are added to a CC instance must be distinct in credential type,
    /// signature scheme, and the timestamp of creation. This timestamp has only
    /// 1 second of resolution, limiting the number of credentials which
    /// can be added. This is a known limitation and will be relaxed in the future.
    pub async fn add_credential(&self, credential_ref: &CredentialRefMaybeArc) -> CoreCryptoResult<()> {
        #[cfg(not(target_family = "wasm"))]
        let credential_ref = credential_ref.as_ref();
        self.inner
            .add_credential(&credential_ref.0)
            .await
            .map_err(CoreCryptoError::generic())?;
        Ok(())
    }
}
