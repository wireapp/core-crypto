//! This module contains all transactional behavior related to key packages

use std::time::Duration;

use core_crypto_keystore::{
    entities::StoredKeyPackage,
    traits::{DeletableBySearchKey, EntityDeleteBorrowed as _},
};
use openmls::prelude::{CryptoConfig, Lifetime};

use super::{Error, Result, TransactionContext};
use crate::{ConversationConfiguration, CredentialRef, Keypackage, KeypackageRef, KeystoreError, RecursiveError};

/// Default lifetime of all generated Keypackages. Matches the limit defined in openmls
/// Default lifetime of a generated key package.
///
/// Note that this sits exactly on the maximum lifetime range openmls will accept for a leaf node:
/// `Lifetime::new` extends `not_before` a further hour into the past for clock skew, and
/// `MAX_LEAF_NODE_LIFETIME_RANGE_SECONDS` is that margin plus this value. Raising this constant, or
/// passing a longer lifetime to [`TransactionContext::generate_key_package`], produces key packages
/// which `KeypackageExt::is_valid` reports as invalid from the moment they are created.
pub const KEYPACKAGE_DEFAULT_LIFETIME: Duration = Duration::from_secs(60 * 60 * 24 * 28 * 3); // ~3 months

impl TransactionContext {
    /// Generate a [Keypackage] from the referenced credential.
    ///
    /// Makes no attempt to look up or prune existing keypackges.
    ///
    /// If `lifetime` is set, the keypackages will expire that span into the future.
    /// If it is unset, [`KEYPACKAGE_DEFAULT_LIFETIME`]
    /// is used.
    ///
    /// As a side effect, stores the keypackages and some related data in the keystore.
    pub async fn generate_key_package(
        &self,
        credential_ref: &CredentialRef,
        lifetime: Option<Duration>,
    ) -> Result<Keypackage> {
        let inner = self.inner()?;
        let lifetime = Lifetime::new(lifetime.unwrap_or(KEYPACKAGE_DEFAULT_LIFETIME).as_secs());
        let credential = credential_ref
            .load(&inner.transaction)
            .await
            .map_err(RecursiveError::context("loading credential"))?;
        let config = CryptoConfig {
            ciphersuite: credential.cipher_suite.into(),
            version: openmls::versions::ProtocolVersion::default(),
        };

        Keypackage::builder()
            .leaf_node_capabilities(ConversationConfiguration::default_leaf_capabilities())
            .key_package_lifetime(lifetime)
            .build(
                config,
                &self.crypto_provider().await?,
                &credential.signature_key_pair,
                credential.to_mls_credential_with_key(),
            )
            .await
            .map_err(Error::key_package_new())
    }

    /// Get all [`KeypackageRef`]s known to the keystore.
    pub async fn get_key_package_refs(&self) -> Result<Vec<KeypackageRef>> {
        let session = self.session().await?;
        session
            .get_keypackage_refs()
            .await
            .map_err(RecursiveError::context("getting all key package refs for transaction"))
            .map_err(Into::into)
    }

    /// Remove one [`Keypackage`] from the database.
    ///
    /// Succeeds silently if the keypackage does not exist in the database.
    pub async fn remove_key_package(&self, kp_ref: &KeypackageRef) -> Result<()> {
        let inner = self.inner()?;
        let tx = inner.transaction();

        StoredKeyPackage::delete_borrowed(tx, kp_ref.hash_ref())
            .map_err(KeystoreError::wrap("removing key package from keystore"))?;

        Ok(())
    }

    /// Remove all keypackages associated with this credential.
    pub async fn remove_key_packages_for(&self, credential_ref: &CredentialRef) -> Result<()> {
        let inner = self.inner()?;
        let tx = inner.transaction();

        StoredKeyPackage::delete_all_matching(tx, &credential_ref.keystore_pk())
            .map_err(KeystoreError::wrap("removing key packages for credential"))?;

        Ok(())
    }
}
