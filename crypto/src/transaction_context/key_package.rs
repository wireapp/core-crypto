//! This module contains all transactional behavior related to key packages

use std::time::Duration;

use core_crypto_keystore::entities::{StoredEncryptionKeyPair, StoredHpkePrivateKey, StoredKeypackage};
use openmls::prelude::{CryptoConfig, Lifetime};

use super::{Error, Result, TransactionContext};
use crate::{
    CredentialRef, Keypackage, KeypackageRef, KeystoreError, MlsConversationConfiguration, RecursiveError,
    mls::key_package::KeypackageExt as _,
};

#[cfg(test)]
pub(crate) const INITIAL_KEYING_MATERIAL_COUNT: u32 = 10;

/// Default lifetime of all generated Keypackages. Matches the limit defined in openmls
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
    pub async fn generate_keypackage(
        &self,
        credential_ref: &CredentialRef,
        lifetime: Option<Duration>,
    ) -> Result<Keypackage> {
        let lifetime = Lifetime::new(lifetime.unwrap_or(KEYPACKAGE_DEFAULT_LIFETIME).as_secs());
        let database = &self.database().await?;
        let credential = credential_ref
            .load(database)
            .await
            .map_err(RecursiveError::mls_credential_ref("loading credential"))?;
        let config = CryptoConfig {
            ciphersuite: credential.ciphersuite.into(),
            version: openmls::versions::ProtocolVersion::default(),
        };

        Keypackage::builder()
            .leaf_node_capabilities(MlsConversationConfiguration::default_leaf_capabilities())
            .key_package_lifetime(lifetime)
            .build(
                config,
                &self.mls_provider().await?,
                &credential.signature_key_pair,
                credential.to_mls_credential_with_key(),
            )
            .await
            .map_err(Error::keypackage_new())
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

    /// Remove one [`Keypackage`] from the database.
    ///
    /// Succeeds silently if the keypackage does not exist in the database.
    ///
    /// Implementation note: this must first load and deserialize the keypackage,
    /// then remove items from three distinct tables.
    pub async fn remove_keypackage(&self, kp_ref: &KeypackageRef) -> Result<()> {
        let Some(kp) = self
            .session()
            .await?
            .load_keypackage(kp_ref)
            .await
            .map_err(RecursiveError::mls_client("loading key packages on session"))?
        else {
            return Ok(());
        };

        let db = self.database().await?;
        db.remove_borrowed::<StoredKeypackage>(kp_ref.hash_ref())
            .await
            .map_err(KeystoreError::wrap("removing key package from keystore"))?;
        db.remove_borrowed::<StoredHpkePrivateKey>(kp.hpke_init_key().as_slice())
            .await
            .map_err(KeystoreError::wrap("removing private key from keystore"))?;
        db.remove_borrowed::<StoredEncryptionKeyPair>(kp.leaf_node().encryption_key().as_slice())
            .await
            .map_err(KeystoreError::wrap("removing encryption keypair from keystore"))?;

        Ok(())
    }

    /// Remove all keypackages associated with this credential.
    ///
    /// This is fairly expensive as it must first load all keypackages, then delete those matching the credential.
    ///
    /// Implementation note: once it makes it as far as having a list of keypackages, does _not_ short-circuit
    /// if removing one returns an error. In that case, only the first produced error is returned.
    /// This helps ensure that as many keypackages for the given credential ref are removed as possible.
    pub async fn remove_keypackages_for(&self, credential_ref: &CredentialRef) -> Result<()> {
        let database = &self.database().await?;
        let credential = credential_ref
            .load(database)
            .await
            .map_err(RecursiveError::mls_credential_ref("loading credential"))?;
        let signature_public_key = credential.signature_key_pair.public();

        let mut first_err = None;
        macro_rules! try_retain_err {
            ($e:expr) => {
                match $e {
                    Err(err) => {
                        if first_err.is_none() {
                            first_err = Some(Error::from(err));
                        }
                        continue;
                    }
                    Ok(val) => val,
                }
            };
        }

        let session = self.session().await?;
        for keypackage in session
            .get_keypackages()
            .await
            .map_err(RecursiveError::mls_client("loading key packages"))?
            .into_iter()
            .filter(|keypackage| keypackage.leaf_node().signature_key().as_slice() == signature_public_key)
        {
            let kp_ref = try_retain_err!(keypackage.make_ref());
            try_retain_err!(self.remove_keypackage(&kp_ref).await);
        }

        match first_err {
            None => Ok(()),
            Some(err) => Err(err),
        }
    }
}
