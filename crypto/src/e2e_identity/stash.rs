use crate::prelude::{CryptoError, E2eIdentityResult, MlsCentral, WireE2eIdentity};
use core_crypto_keystore::CryptoKeystoreMls;
use mls_crypto_provider::MlsCryptoProvider;
use openmls_traits::{crypto::OpenMlsCrypto, types::HashType, OpenMlsCryptoProvider};

/// A unique identifier for an enrollment a consumer can use to fetch it from the keystore when he
/// wants to resume the process
pub(crate) type EnrollmentHandle = Vec<u8>;

impl WireE2eIdentity {
    pub(crate) async fn stash(self, backend: &MlsCryptoProvider) -> E2eIdentityResult<EnrollmentHandle> {
        let content = serde_json::to_vec(&self)?;
        let handle = backend.crypto().hash(HashType::Sha2_256, &content)?;
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
    pub async fn e2ei_enrollment_stash(&self, enrollment: WireE2eIdentity) -> E2eIdentityResult<EnrollmentHandle> {
        enrollment.stash(&self.mls_backend).await
    }

    /// Fetches the persisted enrollment and deletes it from the keystore
    ///
    /// # Arguments
    /// * `handle` - returned by [MlsCentral::e2ei_enrollment_stash]
    pub async fn e2ei_enrollment_stash_pop(&self, handle: EnrollmentHandle) -> E2eIdentityResult<WireE2eIdentity> {
        WireE2eIdentity::stash_pop(&self.mls_backend, handle).await
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{e2e_identity::tests::e2ei_enrollment, prelude::WireE2eIdentity, test_utils::*};
    use mls_crypto_provider::MlsCryptoProvider;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    #[ignore]
    pub async fn e2e_identity_should_work(case: TestCase) {
        run_test_wo_clients(case.clone(), move |cc| {
            Box::pin(async move {
                let result = e2ei_enrollment(case, cc, |e, cc| {
                    Box::pin(async move {
                        let handle = cc.e2ei_enrollment_stash(e).await.unwrap();
                        let enrollment = cc.e2ei_enrollment_stash_pop(handle).await.unwrap();
                        (enrollment, cc)
                    })
                })
                .await;
                assert!(result.is_ok());
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
                let result = e2ei_enrollment(case, cc, move |e, cc| {
                    Box::pin(async move {
                        // this restore recreates a partial enrollment
                        let backend = MlsCryptoProvider::try_new_in_memory("new").await.unwrap();
                        let enrollment = WireE2eIdentity::try_new(
                            e.client_id.as_str().into(),
                            e.display_name,
                            e.handle,
                            1,
                            &backend,
                            e.ciphersuite,
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
