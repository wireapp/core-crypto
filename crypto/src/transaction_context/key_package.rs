//! This module contains all transactional behavior related to key packages

use std::time::Duration;

use super::{Result, TransactionContext};
use crate::{CredentialRef, Keypackage, KeypackageRef, RecursiveError};

impl TransactionContext {
    /// Generate a [Keypackage] from the referenced credential.
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
    ) -> Result<Keypackage> {
        let session = self.session().await?;
        session
            .generate_keypackage(credential_ref, lifetime)
            .await
            .map_err(RecursiveError::mls_client("generating keypackages for transaction"))
            .map_err(Into::into)
    }

    /// Get all [`KeypackageRef`]s known to the keystore.
    pub async fn get_keypackage_refs(&self) -> Result<Vec<KeypackageRef>> {
        let session = self.session().await?;
        session
            .get_keypackage_refs()
            .await
            .map_err(RecursiveError::mls_client(
                "getting all key package refs for transaction",
            ))
            .map_err(Into::into)
    }

    /// Remove a [`Keypackage`] from the keystore.
    pub async fn remove_keypackage(&self, kp_ref: &KeypackageRef) -> Result<()> {
        let session = self.session().await?;
        session
            .remove_keypackage(kp_ref)
            .await
            .map_err(RecursiveError::mls_client("removing a keypackage for transaction"))
            .map_err(Into::into)
    }

    /// Remove all [`Keypackage`]s associated with this ref.
    pub async fn remove_keypackages_for(&self, credential_ref: &CredentialRef) -> Result<()> {
        let session = self.session().await?;
        session
            .remove_keypackages_for(credential_ref)
            .await
            .map_err(RecursiveError::mls_client(
                "removing all keypackages for credential ref for transaction",
            ))
            .map_err(Into::into)
    }
}
