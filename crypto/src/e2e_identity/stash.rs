use crate::prelude::{CryptoError, E2eIdentityResult, E2eiEnrollment, MlsCentral};
use core_crypto_keystore::CryptoKeystoreMls;
use mls_crypto_provider::MlsCryptoProvider;
use openmls_traits::{random::OpenMlsRand, OpenMlsCryptoProvider};

/// A unique identifier for an enrollment a consumer can use to fetch it from the keystore when he
/// wants to resume the process
pub(crate) type EnrollmentHandle = Vec<u8>;

impl E2eiEnrollment {
    pub(crate) async fn stash(self, backend: &MlsCryptoProvider) -> E2eIdentityResult<EnrollmentHandle> {
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

    pub(crate) async fn stash_pop(backend: &MlsCryptoProvider, handle: EnrollmentHandle) -> E2eIdentityResult<Self> {
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
    pub async fn e2ei_enrollment_stash(&self, enrollment: E2eiEnrollment) -> E2eIdentityResult<EnrollmentHandle> {
        enrollment.stash(&self.mls_backend).await
    }

    /// Fetches the persisted enrollment and deletes it from the keystore
    ///
    /// # Arguments
    /// * `handle` - returned by [MlsCentral::e2ei_enrollment_stash]
    pub async fn e2ei_enrollment_stash_pop(&self, handle: EnrollmentHandle) -> E2eIdentityResult<E2eiEnrollment> {
        E2eiEnrollment::stash_pop(&self.mls_backend, handle).await
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{
        e2e_identity::tests::*,
        prelude::{E2eiEnrollment, MlsCentral},
        test_utils::*,
    };
    use mls_crypto_provider::MlsCryptoProvider;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn stash_and_pop_should_not_abort_enrollment(case: TestCase) {
        run_test_wo_clients(case.clone(), move |cc| {
            Box::pin(async move {
                let init = |cc: &MlsCentral| {
                    cc.e2ei_new_enrollment(
                        E2EI_CLIENT_ID.into(),
                        E2EI_DISPLAY_NAME.to_string(),
                        E2EI_HANDLE.to_string(),
                        E2EI_EXPIRY,
                        case.ciphersuite(),
                    )
                };
                let (mut cc, enrollment, cert) = e2ei_enrollment(cc, Some(E2EI_CLIENT_ID_URI), init, |e, cc| {
                    Box::pin(async move {
                        let handle = cc.e2ei_enrollment_stash(e).await.unwrap();
                        let enrollment = cc.e2ei_enrollment_stash_pop(handle).await.unwrap();
                        (enrollment, cc)
                    })
                })
                .await
                .unwrap();
                assert!(cc.e2ei_mls_init_only(enrollment, cert).await.is_ok());
            })
        })
        .await
    }

    // this ensures the nominal test does its job
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn should_fail_when_restoring_invalid(case: TestCase) {
        run_test_wo_clients(case.clone(), move |cc| {
            Box::pin(async move {
                let init = |cc: &MlsCentral| {
                    cc.e2ei_new_enrollment(
                        E2EI_CLIENT_ID.into(),
                        E2EI_DISPLAY_NAME.to_string(),
                        E2EI_HANDLE.to_string(),
                        E2EI_EXPIRY,
                        case.ciphersuite(),
                    )
                };
                let result = e2ei_enrollment(cc, Some(E2EI_CLIENT_ID_URI), init, move |e, cc| {
                    Box::pin(async move {
                        // this restore recreates a partial enrollment
                        let backend = MlsCryptoProvider::try_new_in_memory("new").await.unwrap();
                        let enrollment = E2eiEnrollment::try_new(
                            e.client_id.as_str().into(),
                            e.display_name,
                            e.handle,
                            1,
                            &backend,
                            e.ciphersuite,
                            None,
                        )
                        .unwrap();
                        (enrollment, cc)
                    })
                })
                .await;
                assert!(result.is_err());
            })
        })
        .await
    }
}
