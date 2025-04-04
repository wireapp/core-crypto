//! Utility for clients to get the current state of E2EI when the app resumes

use super::Result;
use crate::{RecursiveError, transaction_context::TransactionContext};
use openmls_traits::types::SignatureScheme;

impl TransactionContext {
    /// See [Client::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, signature_scheme: SignatureScheme) -> Result<bool> {
        let client = self
            .session()
            .await
            .map_err(RecursiveError::transaction("getting mls client"))?;
        client
            .e2ei_is_enabled(signature_scheme)
            .await
            .map_err(RecursiveError::mls_client("is e2ei enabled for client?"))
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::super::Error;
    use crate::{RecursiveError, mls, prelude::MlsCredentialType, test_utils::*};
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
                    Error::Recursive(RecursiveError::MlsClient {  source, .. })
                    if matches!(*source, mls::session::Error::MlsNotInitialized)
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
                    Error::Recursive(RecursiveError::MlsClient {  source, .. })
                    if matches!(*source, mls::session::Error::CredentialNotFound(_))
                ));
            })
        })
        .await
    }
}
