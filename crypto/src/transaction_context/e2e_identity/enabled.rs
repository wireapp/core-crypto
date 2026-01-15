//! Whether e2ei is enabled

use super::Result;
use crate::{Ciphersuite, RecursiveError, transaction_context::TransactionContext};

impl TransactionContext {
    /// See [crate::mls::session::Session::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> Result<bool> {
        let client = self
            .session()
            .await
            .map_err(RecursiveError::transaction("getting mls client"))?;
        client
            .e2ei_is_enabled(ciphersuite)
            .await
            .map_err(RecursiveError::mls_client("is e2ei enabled for client?"))
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use openmls::prelude::Ciphersuite;

    use super::super::Error;
    use crate::{CredentialType, RecursiveError, mls, test_utils::*};

    #[apply(all_cred_cipher)]
    async fn should_be_false_when_basic_and_true_when_x509(case: TestContext) {
        let [cc] = case.sessions().await;
        Box::pin(async move {
            let e2ei_is_enabled = cc.transaction.e2ei_is_enabled(case.ciphersuite()).await.unwrap();
            let expect_enabled = match case.credential_type {
                CredentialType::Basic => false,
                CredentialType::X509 => true,
            };
            assert_eq!(e2ei_is_enabled, expect_enabled);
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn should_fail_when_no_credential_for_given_ciphersuite(case: TestContext) {
        let [cc] = case.sessions().await;
        Box::pin(async move {
            // just return something different from the ciphersuite mls was initialized with
            let other_ciphersuite = match *case.ciphersuite() {
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                    Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
                }
                _ => Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            };
            assert!(matches!(
                cc.transaction.e2ei_is_enabled(other_ciphersuite.into()).await.unwrap_err(),
                Error::Recursive(RecursiveError::MlsClient {  source, .. })
                if matches!(*source, mls::session::Error::CredentialNotFound(..))
            ));
        })
        .await
    }
}
