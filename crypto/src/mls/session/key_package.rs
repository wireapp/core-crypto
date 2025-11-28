use std::{sync::Arc, time::Duration};

use core_crypto_keystore::{
    connection::FetchFromDatabase,
    entities::{EntityFindParams, StoredEncryptionKeyPair, StoredHpkePrivateKey, StoredKeypackage},
};
use openmls::prelude::{CryptoConfig, Lifetime};

use super::{Error, Result};
use crate::{
    Credential, CredentialRef, Keypackage, KeypackageRef, KeystoreError, MlsConversationConfiguration, Session,
    mls::key_package::KeypackageExt,
};

/// Default number of Keypackages a client generates the first time it's created
#[cfg(not(test))]
pub const INITIAL_KEYING_MATERIAL_COUNT: usize = 100;
/// Default number of Keypackages a client generates the first time it's created
#[cfg(test)]
pub const INITIAL_KEYING_MATERIAL_COUNT: usize = 10;

/// Default lifetime of all generated Keypackages. Matches the limit defined in openmls
pub const KEYPACKAGE_DEFAULT_LIFETIME: Duration = Duration::from_secs(60 * 60 * 24 * 28 * 3); // ~3 months

fn from_stored(stored_keypackage: &StoredKeypackage) -> Result<Keypackage> {
    core_crypto_keystore::deser::<Keypackage>(&stored_keypackage.keypackage)
        .map_err(KeystoreError::wrap("deserializing keypackage"))
        .map_err(Into::into)
}

impl Session {
    /// Get an unambiguous credential for the provided ref from the currently-loaded set.
    async fn credential_from_ref(&self, credential_ref: &CredentialRef) -> Result<Arc<Credential>> {
        let guard = self.inner.read().await;
        let identities = &guard.as_ref().ok_or(Error::MlsNotInitialized)?.identities;
        identities
            .find_credential_by_public_key(
                credential_ref.signature_scheme(),
                credential_ref.r#type(),
                &credential_ref.public_key().into(),
            )
            .await
            .ok_or(Error::CredentialNotFound(
                credential_ref.r#type(),
                credential_ref.signature_scheme(),
            ))
    }

    /// Generate a [Keypackage] from the referenced credential.
    ///
    /// Makes no attempt to look up or prune existing keypackges.
    ///
    /// If `lifetime` is set, the keypackages will expire that span into the future.
    /// If it is unset, [`KEYPACKAGE_DEFAULT_LIFETIME`] is used.
    ///
    /// As a side effect, stores the keypackages and some related data in the keystore.
    ///
    /// Must not be fully public, only crate-public, because as it mutates the keystore it must only ever happen within a transaction.
    pub(crate) async fn generate_keypackage(
        &self,
        credential_ref: &CredentialRef,
        lifetime: Option<Duration>,
    ) -> Result<Keypackage> {
        let lifetime = Lifetime::new(lifetime.unwrap_or(KEYPACKAGE_DEFAULT_LIFETIME).as_secs());
        let credential = self.credential_from_ref(credential_ref).await?;

        let config = CryptoConfig {
            ciphersuite: credential.ciphersuite.into(),
            version: openmls::versions::ProtocolVersion::default(),
        };

        Keypackage::builder()
            .leaf_node_capabilities(MlsConversationConfiguration::default_leaf_capabilities())
            .key_package_lifetime(lifetime)
            .build(
                config,
                &self.crypto_provider,
                &credential.signature_key_pair,
                credential.to_mls_credential_with_key(),
            )
            .await
            .map_err(Error::keypackage_new())
    }

    /// Get all [`Keypackage`]s in the database.
    pub(crate) async fn get_keypackages(&self) -> Result<Vec<Keypackage>> {
        let stored_keypackages: Vec<StoredKeypackage> = self
            .crypto_provider
            .keystore()
            .find_all(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all keypackages"))?;

        let keypackages = stored_keypackages
            .iter()
            .map(from_stored)
            // if any ref from loading all fails to load now, skip it
            // strictly we could panic, but this is safer--maybe someone removed it concurrently
            .filter_map(|kp| kp.ok())
            .collect();

        Ok(keypackages)
    }

    /// Get all [`KeypackageRef`]s in the database.
    pub async fn get_keypackage_refs(&self) -> Result<Vec<KeypackageRef>> {
        self.get_keypackages()
            .await?
            .iter()
            .map(|keypackage| keypackage.make_ref().map_err(Into::into))
            .collect()
    }

    /// Load one [`Keypackage`] from its [`KeypackageRef`]
    pub(crate) async fn load_keypackage(&self, kp_ref: &KeypackageRef) -> Result<Option<Keypackage>> {
        self.crypto_provider
            .keystore()
            .find::<StoredKeypackage>(kp_ref.hash_ref())
            .await
            .map_err(KeystoreError::wrap("loading keypackage from database"))?
            .map(|stored_keypackage| from_stored(&stored_keypackage))
            .transpose()
    }

    /// Remove one [`Keypackage`] from the database.
    ///
    /// Succeeds silently if the keypackage does not exist in the database.
    ///
    /// Implementation note: this must first load and deserialize the keypackage,
    /// then remove items from three distinct tables.
    pub async fn remove_keypackage(&self, kp_ref: &KeypackageRef) -> Result<()> {
        let Some(kp) = self.load_keypackage(kp_ref).await? else {
            return Ok(());
        };

        let db = self.crypto_provider.keystore();
        db.remove::<StoredKeypackage, _>(kp_ref.hash_ref())
            .await
            .map_err(KeystoreError::wrap("removing key package from keystore"))?;
        db.remove::<StoredHpkePrivateKey, _>(kp.hpke_init_key().as_slice())
            .await
            .map_err(KeystoreError::wrap("removing private key from keystore"))?;
        db.remove::<StoredEncryptionKeyPair, _>(kp.leaf_node().encryption_key().as_slice())
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
        let credential = self.credential_from_ref(credential_ref).await?;
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

        for keypackage in self
            .get_keypackages()
            .await?
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use core_crypto_keystore::{ConnectionType, DatabaseKey};
    use mls_crypto_provider::{Database, MlsCryptoProvider};
    use openmls::prelude::{KeyPackageIn, ProtocolVersion};
    use openmls_traits::types::VerifiableCiphersuite;

    use crate::{
        MlsConversationConfiguration,
        e2e_identity::enrollment::test_utils::{e2ei_enrollment, init_activation_or_rotation, noop_restore},
        mls::key_package::KeypackageExt as _,
        test_utils::*,
    };

    #[apply(all_cred_cipher)]
    async fn can_assess_keypackage_expiration(case: TestContext) {
        let [session_context] = case.sessions().await;
        let key = DatabaseKey::generate();
        let database = Database::open(ConnectionType::InMemory, &key).await.unwrap();
        let backend = MlsCryptoProvider::new(database);
        let x509_test_chain = if case.is_x509() {
            let x509_test_chain = crate::test_utils::x509::X509TestChain::init_empty(case.signature_scheme());
            x509_test_chain.register_with_provider(&backend).await;
            Some(x509_test_chain)
        } else {
            None
        };

        backend.new_transaction().await.unwrap();
        session_context
            .session
            .random_generate(
                &case,
                x509_test_chain.as_ref().map(|chain| chain.find_local_intermediate_ca()),
            )
            .await
            .unwrap();

        // 90-day standard expiration
        let kp_std_exp = session_context.new_keypackage(&case).await;
        assert!(kp_std_exp.is_valid());

        // 1-second expiration
        let kp_1s_exp = session_context
            .new_keypackage_with_lifetime(&case, Some(Duration::from_secs(1)))
            .await;

        // Sleep 2 seconds to make sure we make the kp expire
        smol::Timer::after(std::time::Duration::from_secs(2)).await;
        assert!(!kp_1s_exp.is_valid());
    }

    #[apply(all_cred_cipher)]
    async fn requesting_x509_key_packages_after_basic(case: TestContext) {
        // Basic test case
        if !case.is_basic() {
            return;
        }

        let [session_context] = case.sessions_basic_with_pki_env().await;
        Box::pin(async move {
            let signature_scheme = case.signature_scheme();

            // Generate 5 Basic key packages first
            let mut initial_kp_refs = Vec::new();
            for _ in 0..5 {
                let kp = session_context.new_keypackage(&case).await;
                initial_kp_refs.push(kp.make_ref().unwrap());
            }
            initial_kp_refs.sort_by_key(|kp_ref| kp_ref.hash_ref().to_owned());

            // Set up E2E identity
            let test_chain = session_context.x509_chain_unchecked();

            let (mut enrollment, cert_chain) = e2ei_enrollment(
                &session_context,
                &case,
                test_chain,
                None,
                false,
                init_activation_or_rotation,
                noop_restore,
            )
            .await
            .unwrap();

            let _rotate_bundle = session_context
                .transaction
                .save_x509_credential(&mut enrollment, cert_chain)
                .await
                .unwrap();

            // E2E identity has been set up correctly
            assert!(
                session_context
                    .transaction
                    .e2ei_is_enabled(signature_scheme)
                    .await
                    .unwrap()
            );

            // Request X509 key packages
            let key_packages = session_context.transaction.get_keypackage_refs().await.unwrap();
            let (mut from_initial_set, x509_key_packages) = key_packages
                .into_iter()
                .partition::<Vec<_>, _>(|kp_ref| initial_kp_refs.contains(kp_ref));

            from_initial_set.sort_by_key(|kp_ref| kp_ref.hash_ref().to_owned());
            assert_eq!(initial_kp_refs, from_initial_set);

            // Verify that the key packages are X509
            assert!(
                x509_key_packages
                    .iter()
                    .all(|kp| CredentialType::X509 == kp.credential_type())
            );
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn new_keypackage_has_correct_extensions(case: TestContext) {
        let [cc] = case.sessions().await;
        Box::pin(async move {
            let kp = cc.new_keypackage(&case).await;

            // make sure it's valid
            let _ = KeyPackageIn::from(kp.clone())
                .standalone_validate(
                    &cc.transaction.mls_provider().await.unwrap(),
                    ProtocolVersion::Mls10,
                    true,
                )
                .await
                .unwrap();

            // see https://www.rfc-editor.org/rfc/rfc9420.html#section-10-10
            assert!(kp.extensions().is_empty());

            assert_eq!(kp.leaf_node().capabilities().versions(), &[ProtocolVersion::Mls10]);
            assert_eq!(
                kp.leaf_node().capabilities().ciphersuites().to_vec(),
                MlsConversationConfiguration::DEFAULT_SUPPORTED_CIPHERSUITES
                    .iter()
                    .map(|c| VerifiableCiphersuite::from(*c))
                    .collect::<Vec<_>>()
            );
            assert!(kp.leaf_node().capabilities().proposals().is_empty());
            assert!(kp.leaf_node().capabilities().extensions().is_empty());
            assert_eq!(
                kp.leaf_node().capabilities().credentials(),
                MlsConversationConfiguration::DEFAULT_SUPPORTED_CREDENTIALS
            );
        })
        .await
    }
}
