//! Utility for clients to get the current state of E2EI when the app resumes

use openmls_traits::types::SignatureScheme;

use super::Result;
use crate::{RecursiveError, transaction_context::TransactionContext};

impl TransactionContext {
    /// See [crate::mls::session::Session::e2ei_is_enabled]
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
    use openmls_traits::types::SignatureScheme;

    use super::super::Error;
    use crate::{CredentialType, RecursiveError, mls, test_utils::*};

    #[apply(all_cred_cipher)]
    async fn should_be_false_when_basic_and_true_when_x509(case: TestContext) {
        let [cc] = case.sessions().await;
        Box::pin(async move {
            let e2ei_is_enabled = cc.transaction.e2ei_is_enabled(case.signature_scheme()).await.unwrap();
            let expect_enabled = match case.credential_type {
                CredentialType::Basic => false,
                CredentialType::X509 => true,
            };
            assert_eq!(e2ei_is_enabled, expect_enabled);
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn should_fail_when_no_client(case: TestContext) {
        let cc = SessionContext::new_uninitialized(&case).await;
        let err = cc
            .transaction
            .e2ei_is_enabled(case.signature_scheme())
            .await
            .unwrap_err();
        assert!(innermost_source_matches!(err, mls::session::Error::MlsNotInitialized));
        Box::pin(async move {
            assert!(matches!(
                cc.transaction.e2ei_is_enabled(case.signature_scheme()).await.unwrap_err(),
                Error::Recursive(RecursiveError::MlsClient {  source, .. })
                if matches!(*source, mls::session::Error::MlsNotInitialized)
            ));
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn should_fail_when_no_credential_for_given_signature_scheme(case: TestContext) {
        let [cc] = case.sessions().await;
        Box::pin(async move {
            // just return something different from the signature scheme the MlsCentral was initialized with
            let other_sc = match case.signature_scheme() {
                SignatureScheme::ED25519 => SignatureScheme::ECDSA_SECP256R1_SHA256,
                _ => SignatureScheme::ED25519,
            };
            assert!(matches!(
                cc.transaction.e2ei_is_enabled(other_sc).await.unwrap_err(),
                Error::Recursive(RecursiveError::MlsClient {  source, .. })
                if matches!(*source, mls::session::Error::CredentialNotFound(..))
            ));
        })
        .await
    }
}
