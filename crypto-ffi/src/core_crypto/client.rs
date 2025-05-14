#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{Ciphersuite, CoreCrypto, CoreCryptoResult, CredentialType};

#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl CoreCrypto {
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
