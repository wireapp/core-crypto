//! Utility for clients to get the current state of E2EI when the app resumes

use super::Result;
use crate::{
    RecursiveError,
    context::CentralContext,
    mls,
    prelude::{Client, MlsCredentialType},
};
use openmls_traits::types::SignatureScheme;

impl CentralContext {
    /// See [Client::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, signature_scheme: SignatureScheme) -> Result<bool> {
        let client = self
            .mls_client()
            .await
            .map_err(RecursiveError::root("getting mls client"))?;
        client.e2ei_is_enabled(signature_scheme).await
    }
}

impl Client {
    /// Returns true when end-to-end-identity is enabled for the given SignatureScheme
    pub async fn e2ei_is_enabled(&self, signature_scheme: SignatureScheme) -> Result<bool> {
        let x509_result = self
            .find_most_recent_credential_bundle(signature_scheme, MlsCredentialType::X509)
            .await;
        match x509_result {
            Err(mls::client::Error::CredentialNotFound(MlsCredentialType::X509)) => {
                self.find_most_recent_credential_bundle(signature_scheme, MlsCredentialType::Basic)
                    .await
                    .map_err(RecursiveError::mls_client(
                        "finding most recent basic credential bundle after searching for x509",
                    ))?;
                Ok(false)
            }
            Err(e) => Err(RecursiveError::mls_client("finding most recent x509 credential bundle")(e).into()),
            Ok(_) => Ok(true),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{RecursiveError, e2e_identity::error::Error, mls, prelude::MlsCredentialType, test_utils::*};
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
                    if matches!(*source, mls::client::Error::MlsNotInitialized)
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
                    if matches!(*source, mls::client::Error::CredentialNotFound(_))
                ));
            })
        })
        .await
    }
}
