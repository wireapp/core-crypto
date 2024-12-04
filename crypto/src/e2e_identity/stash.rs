use openmls_traits::{random::OpenMlsRand, OpenMlsCryptoProvider};

use super::{Error, Result};
use crate::context::CentralContext;
use crate::prelude::E2eiEnrollment;
use core_crypto_keystore::CryptoKeystoreMls;
use mls_crypto_provider::MlsCryptoProvider;

/// A unique identifier for an enrollment a consumer can use to fetch it from the keystore when he
/// wants to resume the process
pub(crate) type EnrollmentHandle = Vec<u8>;

impl E2eiEnrollment {
    pub(crate) async fn stash(self, backend: &MlsCryptoProvider) -> Result<EnrollmentHandle> {
        // should be enough to prevent collisions
        const HANDLE_SIZE: usize = 32;

        let content = serde_json::to_vec(&self)?;
        let handle = backend
            .crypto()
            .random_vec(HANDLE_SIZE)
            .map_err(Error::mls_operation("generating random vector of bytes"))?;
        backend
            .key_store()
            .save_e2ei_enrollment(&handle, &content)
            .await
            .map_err(Error::keystore("saving e2ei enrollment"))?;
        Ok(handle)
    }

    pub(crate) async fn stash_pop(backend: &MlsCryptoProvider, handle: EnrollmentHandle) -> Result<Self> {
        let content = backend
            .key_store()
            .pop_e2ei_enrollment(&handle)
            .await
            .map_err(Error::keystore("popping e2ei enrollment"))?;
        Ok(serde_json::from_slice(&content)?)
    }
}

impl CentralContext {
    /// Allows persisting an active enrollment (for example while redirecting the user during OAuth)
    /// in order to resume it later with [CentralContext::e2ei_enrollment_stash_pop]
    ///
    /// # Arguments
    /// * `enrollment` - the enrollment instance to persist
    ///
    /// # Returns
    /// A handle for retrieving the enrollment later on
    pub async fn e2ei_enrollment_stash(&self, enrollment: E2eiEnrollment) -> Result<EnrollmentHandle> {
        enrollment
            .stash(&self.mls_provider().await.map_err(Error::root("getting mls provider"))?)
            .await
    }

    /// Fetches the persisted enrollment and deletes it from the keystore
    ///
    /// # Arguments
    /// * `handle` - returned by [CentralContext::e2ei_enrollment_stash]
    pub async fn e2ei_enrollment_stash_pop(&self, handle: EnrollmentHandle) -> Result<E2eiEnrollment> {
        E2eiEnrollment::stash_pop(
            &self.mls_provider().await.map_err(Error::root("getting mls provider"))?,
            handle,
        )
        .await
    }
}

#[cfg(test)]
mod tests {

    use mls_crypto_provider::MlsCryptoProvider;
    use wasm_bindgen_test::*;

    use crate::{
        e2e_identity::id::WireQualifiedClientId,
        e2e_identity::tests::*,
        prelude::{E2eiEnrollment, INITIAL_KEYING_MATERIAL_COUNT},
        test_utils::{x509::X509TestChain, *},
    };

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn stash_and_pop_should_not_abort_enrollment(case: TestCase) {
        run_test_wo_clients(case.clone(), move |mut cc| {
            Box::pin(async move {
                let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

                let is_renewal = false;
                let (mut enrollment, cert) = e2ei_enrollment(
                    &mut cc,
                    &case,
                    &x509_test_chain,
                    Some(E2EI_CLIENT_ID_URI),
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

                assert!(cc
                    .context
                    .e2ei_mls_init_only(&mut enrollment, cert, Some(INITIAL_KEYING_MATERIAL_COUNT))
                    .await
                    .is_ok());
            })
        })
        .await
    }

    // this ensures the nominal test does its job
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_restoring_invalid(case: TestCase) {
        run_test_wo_clients(case.clone(), move |mut cc| {
            Box::pin(async move {
                let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

                let is_renewal = false;
                let result = e2ei_enrollment(
                    &mut cc,
                    &case,
                    &x509_test_chain,
                    Some(E2EI_CLIENT_ID_URI),
                    is_renewal,
                    init_enrollment,
                    move |e, _cc| {
                        Box::pin(async move {
                            // this restore recreates a partial enrollment
                            let backend = MlsCryptoProvider::try_new_in_memory("new").await.unwrap();
                            backend.new_transaction().await.unwrap();
                            let client_id = e.client_id.parse::<WireQualifiedClientId>().unwrap();
                            E2eiEnrollment::try_new(
                                client_id.into(),
                                e.display_name,
                                e.handle,
                                e.team,
                                1,
                                &backend,
                                e.ciphersuite,
                                None,
                                #[cfg(not(target_family = "wasm"))]
                                None,
                            )
                            .unwrap()
                        })
                    },
                )
                .await;
                assert!(result.is_err());
            })
        })
        .await
    }
}
