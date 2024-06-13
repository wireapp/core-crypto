use openmls_traits::{random::OpenMlsRand, OpenMlsCryptoProvider};

use core_crypto_keystore::CryptoKeystoreMls;
use mls_crypto_provider::MlsCryptoProvider;

use crate::prelude::{CryptoError, CryptoResult, E2eiEnrollment, MlsCentral};

/// A unique identifier for an enrollment a consumer can use to fetch it from the keystore when he
/// wants to resume the process
pub(crate) type EnrollmentHandle = Vec<u8>;

impl E2eiEnrollment {
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub(crate) async fn stash(self, backend: &MlsCryptoProvider) -> CryptoResult<EnrollmentHandle> {
        // should be enough to prevent collisions
        const HANDLE_SIZE: usize = 32;

        let content = serde_json::to_vec(&self)?;
        let handle = backend.crypto().random_vec(HANDLE_SIZE).map_err(CryptoError::from)?;
        backend
            .key_store()
            .save_e2ei_enrollment(&handle, &content)
            .await
            .map_err(CryptoError::from)?;
        Ok(handle)
    }

    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub(crate) async fn stash_pop(backend: &MlsCryptoProvider, handle: EnrollmentHandle) -> CryptoResult<Self> {
        let content = backend
            .key_store()
            .pop_e2ei_enrollment(&handle)
            .await
            .map_err(CryptoError::from)?;
        Ok(serde_json::from_slice(&content)?)
    }
}

impl MlsCentral {
    /// Allows persisting an active enrollment (for example while redirecting the user during OAuth)
    /// in order to resume it later with [MlsCentral::e2ei_enrollment_stash_pop]
    ///
    /// # Arguments
    /// * `enrollment` - the enrollment instance to persist
    ///
    /// # Returns
    /// A handle for retrieving the enrollment later on
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub async fn e2ei_enrollment_stash(&self, enrollment: E2eiEnrollment) -> CryptoResult<EnrollmentHandle> {
        enrollment.stash(&self.mls_backend).await
    }

    /// Fetches the persisted enrollment and deletes it from the keystore
    ///
    /// # Arguments
    /// * `handle` - returned by [MlsCentral::e2ei_enrollment_stash]
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub async fn e2ei_enrollment_stash_pop(&self, handle: EnrollmentHandle) -> CryptoResult<E2eiEnrollment> {
        E2eiEnrollment::stash_pop(&self.mls_backend, handle).await
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use super::*;

    use crate::{
        e2e_identity::id::WireQualifiedClientId,
        e2e_identity::tests::*,
        prelude::{E2eiEnrollment, INITIAL_KEYING_MATERIAL_COUNT},
        test_utils::{central::TEAM, x509::X509TestChain, *},
    };

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn stash_and_pop_should_not_abort_enrollment(case: TestCase) {
        run_test_wo_clients(case.clone(), move |mut cc| {
            Box::pin(async move {
                fn init(wrapper: E2eiInitWrapper) -> InitFnReturn<'_> {
                    Box::pin(async move {
                        let E2eiInitWrapper { cc, case } = wrapper;
                        let cs = case.ciphersuite();
                        cc.e2ei_new_enrollment(
                            E2EI_CLIENT_ID.into(),
                            E2EI_DISPLAY_NAME.to_string(),
                            E2EI_HANDLE.to_string(),
                            Some(TEAM.to_string()),
                            E2EI_EXPIRY,
                            cs,
                        )
                    })
                }

                let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

                let is_renewal = false;
                let (mut enrollment, cert) = e2ei_enrollment(
                    &mut cc,
                    &case,
                    &x509_test_chain,
                    Some(E2EI_CLIENT_ID_URI),
                    is_renewal,
                    init,
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
                    .mls_central
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
                fn init(wrapper: E2eiInitWrapper) -> InitFnReturn<'_> {
                    Box::pin(async move {
                        let E2eiInitWrapper { cc, case } = wrapper;
                        let cs = case.ciphersuite();
                        cc.e2ei_new_enrollment(
                            E2EI_CLIENT_ID.into(),
                            E2EI_DISPLAY_NAME.to_string(),
                            E2EI_HANDLE.to_string(),
                            Some(TEAM.to_string()),
                            E2EI_EXPIRY,
                            cs,
                        )
                    })
                }

                let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

                let is_renewal = false;
                let result = e2ei_enrollment(
                    &mut cc,
                    &case,
                    &x509_test_chain,
                    Some(E2EI_CLIENT_ID_URI),
                    is_renewal,
                    init,
                    move |e, _cc| {
                        Box::pin(async move {
                            // this restore recreates a partial enrollment
                            let backend = MlsCryptoProvider::try_new_in_memory("new").await.unwrap();
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
