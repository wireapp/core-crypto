use super::Result;
use crate::{E2eiEnrollment, RecursiveError, e2e_identity::EnrollmentHandle, transaction_context::TransactionContext};

impl TransactionContext {
    /// Allows persisting an active enrollment (for example while redirecting the user during OAuth)
    /// in order to resume it later with [TransactionContext::e2ei_enrollment_stash_pop]
    ///
    /// # Arguments
    /// * `enrollment` - the enrollment instance to persist
    ///
    /// # Returns
    /// A handle for retrieving the enrollment later on
    pub async fn e2ei_enrollment_stash(&self, enrollment: E2eiEnrollment) -> Result<EnrollmentHandle> {
        enrollment
            .stash(
                &self
                    .mls_provider()
                    .await
                    .map_err(RecursiveError::transaction("getting mls provider"))?,
            )
            .await
            .map_err(RecursiveError::e2e_identity("stashing enrollment"))
            .map_err(Into::into)
    }

    /// Fetches the persisted enrollment and deletes it from the keystore
    ///
    /// # Arguments
    /// * `handle` - returned by [TransactionContext::e2ei_enrollment_stash]
    pub async fn e2ei_enrollment_stash_pop(&self, handle: EnrollmentHandle) -> Result<E2eiEnrollment> {
        E2eiEnrollment::stash_pop(
            &self
                .mls_provider()
                .await
                .map_err(RecursiveError::transaction("getting mls provider"))?,
            handle,
        )
        .await
        .map_err(RecursiveError::e2e_identity("popping stashed enrollment"))
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use core_crypto_keystore::{ConnectionType, DatabaseKey};
    use mls_crypto_provider::{Database, MlsCryptoProvider};

    use crate::{
        CoreCrypto, E2eiEnrollment,
        e2e_identity::{enrollment::test_utils::*, id::WireQualifiedClientId},
        test_utils::{x509::X509TestChain, *},
    };

    #[apply(all_cred_cipher)]
    async fn stash_and_pop_should_not_abort_enrollment(mut case: TestContext) {
        let db = case.create_in_memory_database().await;
        let cc = CoreCrypto::new(db);
        let tx = cc.new_transaction().await.unwrap();
        Box::pin(async move {
            use std::sync::Arc;

            let chain = X509TestChain::init_empty(case.signature_scheme());

            let is_renewal = false;
            let (mut enrollment, cert) = e2ei_enrollment(
                &tx,
                &case,
                &chain,
                E2EI_CLIENT_ID_URI,
                is_renewal,
                init_enrollment,
                |e, cc| {
                    Box::pin(async move {
                        let handle = cc.e2ei_enrollment_stash(e).await.unwrap();
                        cc.e2ei_enrollment_stash_pop(handle).await.unwrap()
                    })
                },
            )
            .await
            .unwrap();

            let transport = Arc::new(CoreCryptoTransportSuccessProvider::default());
            assert!(tx.e2ei_mls_init_only(&mut enrollment, cert, transport).await.is_ok());
        })
        .await;
    }

    // this ensures the nominal test does its job
    #[apply(all_cred_cipher)]
    async fn should_fail_when_restoring_invalid(mut case: TestContext) {
        let db = case.create_in_memory_database().await;
        let cc = CoreCrypto::new(db);
        let tx = cc.new_transaction().await.unwrap();
        Box::pin(async move {
            let chain = X509TestChain::init_empty(case.signature_scheme());

            let is_renewal = false;
            let result = e2ei_enrollment(
                &tx,
                &case,
                &chain,
                E2EI_CLIENT_ID_URI,
                is_renewal,
                init_enrollment,
                move |e, _cc| {
                    Box::pin(async move {
                        // this restore recreates a partial enrollment
                        let key = DatabaseKey::generate();
                        let key_store = Database::open(ConnectionType::InMemory, &key).await.unwrap();
                        let backend = MlsCryptoProvider::new(key_store);
                        backend.new_transaction().await.unwrap();
                        let client_id = e.client_id().parse::<WireQualifiedClientId>().unwrap();
                        E2eiEnrollment::try_new(
                            client_id.into(),
                            e.display_name().to_string(),
                            e.handle().to_string(),
                            e.team().map(ToString::to_string),
                            1,
                            &backend,
                            *e.ciphersuite(),
                            None,
                            false,
                        )
                        .unwrap()
                    })
                },
            )
            .await;
            assert!(result.is_err());
        })
        .await
    }
}
