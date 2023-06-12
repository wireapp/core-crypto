use crate::prelude::{CryptoResult, MlsCentral, MlsCiphersuite, MlsCredentialType};
use crate::CryptoError;
use openmls::prelude::{KeyPackage, KeyPackageRef};

impl MlsCentral {
    /// Returns `amount_requested` OpenMLS [openmls::key_packages::KeyPackage]s.
    /// Will always return the requested amount as it will generate the necessary (lacking) amount on-the-fly
    ///
    /// Note: Keypackage pruning is performed as a first step
    ///
    /// # Arguments
    /// * `amount_requested` - number of KeyPackages to request and fill the `KeyPackageBundle`
    ///
    /// # Return type
    /// A vector of `KeyPackageBundle`
    ///
    /// # Errors
    /// Errors can happen when accessing the KeyStore
    pub async fn get_or_create_client_keypackages(
        &self,
        ciphersuite: MlsCiphersuite,
        credential_type: MlsCredentialType,
        amount_requested: usize,
    ) -> CryptoResult<Vec<KeyPackage>> {
        self.mls_client()?
            .request_key_packages(amount_requested, ciphersuite, credential_type, &self.mls_backend)
            .await
    }

    /// Returns the count of valid, non-expired, unclaimed keypackages in store for the given [MlsCiphersuite] and [MlsCredentialType]
    pub async fn client_valid_key_packages_count(
        &self,
        ciphersuite: MlsCiphersuite,
        credential_type: MlsCredentialType,
    ) -> CryptoResult<usize> {
        self.mls_client()?
            .valid_keypackages_count(&self.mls_backend, ciphersuite, credential_type)
            .await
    }

    /// Prunes local KeyPackages after making sure they also have been deleted on the backend side
    /// You should only use this after [MlsCentral::e2ei_rotate_all]
    pub async fn delete_keypackages(&mut self, refs: &[KeyPackageRef]) -> CryptoResult<()> {
        if refs.is_empty() {
            return Err(CryptoError::ImplementationError);
        }
        self.mls_client
            .as_mut()
            .ok_or(CryptoError::MlsNotInitialized)?
            .prune_keypackages_and_credential(&self.mls_backend, refs)
            .await
    }
}
