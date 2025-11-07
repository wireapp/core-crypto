//! This module contains all transactional behavior related to key packages

use std::time::Duration;

use openmls::prelude::{KeyPackage, KeyPackageRef};

use super::{Result, TransactionContext};
use crate::{Ciphersuite, CredentialRef, CredentialType, RecursiveError};

impl TransactionContext {
    /// Returns `amount_requested` OpenMLS [KeyPackage]s.
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
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
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

    /// Returns the count of valid, non-expired, unclaimed keypackages in store for the given [Ciphersuite] and [CredentialType]
    pub async fn client_valid_key_packages_count(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
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
    pub async fn delete_keypackages(&self, refs: impl IntoIterator<Item = KeyPackageRef>) -> Result<()> {
        let mut session = self.session().await?;
        session
            .prune_keypackages_and_credential(&self.mls_provider().await?, refs)
            .await
            .map_err(RecursiveError::mls_client("pruning key packages and credential"))
            .map_err(Into::into)
    }

    /// Generate a [KeyPackage] from the referenced credential.
    ///
    /// Makes no attempt to look up or prune existing keypackges.
    ///
    /// If `lifetime` is set, the keypackages will expire that span into the future.
    /// If it is unset, [`KEYPACKAGE_DEFAULT_LIFETIME`][crate::mls::session::key_package::KEYPACKAGE_DEFAULT_LIFETIME]
    /// is used.
    pub async fn generate_keypackage(
        &self,
        credential_ref: &CredentialRef,
        lifetime: Option<Duration>,
    ) -> Result<KeyPackage> {
        let session = self.session().await?;
        session
            .generate_keypackage(credential_ref, lifetime)
            .await
            .map_err(RecursiveError::mls_client("generating keypackages for transaction"))
            .map_err(Into::into)
    }
}
