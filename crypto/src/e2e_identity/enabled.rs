//! Utility for clients to get the current state of E2EI when the app resumes

use crate::context::CentralContext;
use crate::prelude::{Client, CryptoError, CryptoResult, MlsCentral, MlsCredentialType};
use openmls_traits::types::SignatureScheme;

impl CentralContext {
    /// See [MlsCentral::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, signature_scheme: SignatureScheme) -> CryptoResult<bool> {
        let client = self.mls_client().await?;
        client.e2ei_is_enabled(signature_scheme).await
    }
}

impl MlsCentral {
    /// Returns true when end-to-end-identity is enabled for the given SignatureScheme
    pub async fn e2ei_is_enabled(&self, signature_scheme: SignatureScheme) -> CryptoResult<bool> {
        self.mls_client.e2ei_is_enabled(signature_scheme).await
    }
}

impl Client {
    async fn e2ei_is_enabled(&self, signature_scheme: SignatureScheme) -> CryptoResult<bool> {
        let x509_result = self
            .find_most_recent_credential_bundle(signature_scheme, MlsCredentialType::X509)
            .await;
        match x509_result {
            Err(CryptoError::CredentialNotFound(MlsCredentialType::X509)) => {
                self.find_most_recent_credential_bundle(signature_scheme, MlsCredentialType::Basic)
                    .await?;
                Ok(false)
            }
            Err(e) => Err(e),
            Ok(_) => Ok(true),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{prelude::MlsCredentialType, test_utils::*, CryptoError};
    use openmls_traits::types::SignatureScheme;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_be_false_when_basic_and_true_when_x509(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice"], move |[cc]| {
            Box::pin(async move {
                let e2ei_is_enabled = cc.context.e2ei_is_enabled(case.signature_scheme()).await.unwrap();
                match case.credential_type {
                    MlsCredentialType::Basic => assert!(!e2ei_is_enabled),
                    MlsCredentialType::X509 => assert!(e2ei_is_enabled),
                };
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_no_client(case: TestCase) {
        run_test_wo_clients(case.clone(), move |cc| {
            Box::pin(async move {
                assert!(matches!(
                    cc.context.e2ei_is_enabled(case.signature_scheme()).await.unwrap_err(),
                    CryptoError::MlsNotInitialized
                ));
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_no_credential_for_given_signature_scheme(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice"], move |[cc]| {
            Box::pin(async move {
                // just return something different from the signature scheme the MlsCentral was initialized with
                let other_sc = match case.signature_scheme() {
                    SignatureScheme::ED25519 => SignatureScheme::ECDSA_SECP256R1_SHA256,
                    _ => SignatureScheme::ED25519,
                };
                assert!(matches!(
                    cc.context.e2ei_is_enabled(other_sc).await.unwrap_err(),
                    CryptoError::CredentialNotFound(_)
                ));
            })
        })
        .await
    }
}
