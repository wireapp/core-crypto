//! This module contains all transactional behavior related to key packages

use openmls::prelude::{KeyPackage, KeyPackageRef};

use crate::{
    RecursiveError,
    prelude::{MlsCiphersuite, MlsCredentialType},
};

use super::{Error, Result, TransactionContext};

impl TransactionContext {
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
    ) -> Result<Vec<KeyPackage>> {
        let session = self.session().await?;
        session
            .request_key_packages(
                amount_requested,
                ciphersuite,
                credential_type,
                &self.mls_provider().await?,
            )
            .await
            .map_err(RecursiveError::mls_client("requesting key packages"))
            .map_err(Into::into)
    }

    /// Returns the count of valid, non-expired, unclaimed keypackages in store for the given [MlsCiphersuite] and [MlsCredentialType]
    pub async fn client_valid_key_packages_count(
        &self,
        ciphersuite: MlsCiphersuite,
        credential_type: MlsCredentialType,
    ) -> Result<usize> {
        let session = self.session().await?;
        session
            .valid_keypackages_count(&self.mls_provider().await?, ciphersuite, credential_type)
            .await
            .map_err(RecursiveError::mls_client("counting valid key packages"))
            .map_err(Into::into)
    }

    /// Prunes local KeyPackages after making sure they also have been deleted on the backend side
    /// You should only use this after [TransactionContext::save_x509_credential]
    pub async fn delete_keypackages(&self, refs: &[KeyPackageRef]) -> Result<()> {
        if refs.is_empty() {
            return Err(Error::CallerError("The provided keypackage list was empty"));
        }
        let mut session = self.session().await?;
        session
            .prune_keypackages_and_credential(&self.mls_provider().await?, refs)
            .await
            .map_err(RecursiveError::mls_client("pruning key packages and credential"))
            .map_err(Into::into)
    }
}
