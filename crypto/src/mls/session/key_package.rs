use openmls::prelude::{Credential, CredentialWithKey, CryptoConfig, KeyPackage, KeyPackageRef, Lifetime};
use openmls_traits::OpenMlsCryptoProvider;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use tls_codec::{Deserialize, Serialize};

use core_crypto_keystore::{
    connection::FetchFromDatabase,
    entities::{EntityFindParams, MlsEncryptionKeyPair, MlsHpkePrivateKey, MlsKeyPackage},
};
use mls_crypto_provider::{CryptoKeystore, MlsCryptoProvider};

use super::{Error, Result};
use crate::{
    KeystoreError, MlsError, RecursiveError,
    mls::{credential::CredentialBundle, session::SessionInner},
    prelude::{MlsCiphersuite, MlsConversationConfiguration, MlsCredentialType, Session},
    transaction_context::TransactionContext,
};

/// Default number of KeyPackages a client generates the first time it's created
#[cfg(not(test))]
pub const INITIAL_KEYING_MATERIAL_COUNT: usize = 100;
/// Default number of KeyPackages a client generates the first time it's created
#[cfg(test)]
pub const INITIAL_KEYING_MATERIAL_COUNT: usize = 10;

/// Default lifetime of all generated KeyPackages. Matches the limit defined in openmls
pub(crate) const KEYPACKAGE_DEFAULT_LIFETIME: std::time::Duration =
    std::time::Duration::from_secs(60 * 60 * 24 * 28 * 3); // ~3 months

impl Session {
    /// Generates a single new keypackage
    ///
    /// # Arguments
    /// * `backend` - the KeyStorage to load the keypackages from
    ///
    /// # Errors
    /// KeyStore and OpenMls errors
    pub async fn generate_one_keypackage_from_credential_bundle(
        &self,
        backend: &MlsCryptoProvider,
        cs: MlsCiphersuite,
        cb: &CredentialBundle,
    ) -> Result<KeyPackage> {
        match self.inner.read().await.deref() {
            None => Err(Error::MlsNotInitialized),
            Some(SessionInner {
                keypackage_lifetime, ..
            }) => {
                let keypackage = KeyPackage::builder()
                    .leaf_node_capabilities(MlsConversationConfiguration::default_leaf_capabilities())
                    .key_package_lifetime(Lifetime::new(keypackage_lifetime.as_secs()))
                    .build(
                        CryptoConfig {
                            ciphersuite: cs.into(),
                            version: openmls::versions::ProtocolVersion::default(),
                        },
                        backend,
                        &cb.signature_key,
                        CredentialWithKey {
                            credential: cb.credential.clone(),
                            signature_key: cb.signature_key.public().into(),
                        },
                    )
                    .await
                    .map_err(KeystoreError::wrap("building keypackage"))?;

                Ok(keypackage)
            }
        }
    }

    /// Requests `count` keying material to be present and returns
    /// a reference to it for the consumer to copy/clone.
    ///
    /// # Arguments
    /// * `count` - number of [openmls::key_packages::KeyPackage] to generate
    /// * `ciphersuite` - of [openmls::key_packages::KeyPackage] to generate
    /// * `backend` - the KeyStorage to load the keypackages from
    ///
    /// # Errors
    /// KeyStore and OpenMls errors
    pub async fn request_key_packages(
        &self,
        count: usize,
        ciphersuite: MlsCiphersuite,
        credential_type: MlsCredentialType,
        backend: &MlsCryptoProvider,
    ) -> Result<Vec<KeyPackage>> {
        // Auto-prune expired keypackages on request
        self.prune_keypackages(backend, &[]).await?;
        use core_crypto_keystore::CryptoKeystoreMls as _;

        let mut existing_kps = backend
            .key_store()
            .mls_fetch_keypackages::<KeyPackage>(count as u32)
            .await.map_err(KeystoreError::wrap("fetching mls keypackages"))?
            .into_iter()
            // TODO: do this filtering in SQL when the schema is updated. Tracking issue: WPB-9599
            .filter(|kp|
                kp.ciphersuite() == ciphersuite.0 && MlsCredentialType::from(kp.leaf_node().credential().credential_type()) == credential_type)
            .collect::<Vec<_>>();

        let kpb_count = existing_kps.len();
        let mut kps = if count > kpb_count {
            let to_generate = count - kpb_count;
            let cb = self
                .find_most_recent_credential_bundle(ciphersuite.signature_algorithm(), credential_type)
                .await?;
            self.generate_new_keypackages(backend, ciphersuite, &cb, to_generate)
                .await?
        } else {
            vec![]
        };

        existing_kps.reverse();

        kps.append(&mut existing_kps);
        Ok(kps)
    }

    pub(crate) async fn generate_new_keypackages(
        &self,
        backend: &MlsCryptoProvider,
        ciphersuite: MlsCiphersuite,
        cb: &CredentialBundle,
        count: usize,
    ) -> Result<Vec<KeyPackage>> {
        let mut kps = Vec::with_capacity(count);

        for _ in 0..count {
            let kp = self
                .generate_one_keypackage_from_credential_bundle(backend, ciphersuite, cb)
                .await?;
            kps.push(kp);
        }

        Ok(kps)
    }

    /// Returns the count of valid, non-expired, unclaimed keypackages in store
    pub async fn valid_keypackages_count(
        &self,
        backend: &MlsCryptoProvider,
        ciphersuite: MlsCiphersuite,
        credential_type: MlsCredentialType,
    ) -> Result<usize> {
        let kps: Vec<MlsKeyPackage> = backend
            .key_store()
            .find_all(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all key packages"))?;

        let mut valid_count = 0;
        for kp in kps
            .into_iter()
            .map(|kp| core_crypto_keystore::deser::<KeyPackage>(&kp.keypackage))
            // TODO: do this filtering in SQL when the schema is updated. Tracking issue: WPB-9599
            .filter(|kp| {
                kp.as_ref()
                    .map(|b| b.ciphersuite() == ciphersuite.0 && MlsCredentialType::from(b.leaf_node().credential().credential_type()) == credential_type)
                    .unwrap_or_default()
            })
        {
            let kp = kp.map_err(KeystoreError::wrap("counting valid keypackages"))?;
            if !Self::is_mls_keypackage_expired(&kp) {
                valid_count += 1;
            }
        }

        Ok(valid_count)
    }

    /// Checks if a given OpenMLS [`KeyPackage`] is expired by looking through its extensions,
    /// finding a lifetime extension and checking if it's valid.
    fn is_mls_keypackage_expired(kp: &KeyPackage) -> bool {
        let Some(lifetime) = kp.leaf_node().life_time() else {
            return false;
        };

        !(lifetime.has_acceptable_range() && lifetime.is_valid())
    }

    /// Prune the provided KeyPackageRefs from the keystore
    ///
    /// Warning: Despite this API being public, the caller should know what they're doing.
    /// Provided KeypackageRefs **will** be purged regardless of their expiration state, so please be wary of what you are doing if you directly call this API.
    /// This could result in still valid, uploaded keypackages being pruned from the system and thus being impossible to find when referenced in a future Welcome message.
    pub async fn prune_keypackages(&self, backend: &MlsCryptoProvider, refs: &[KeyPackageRef]) -> Result<()> {
        let keystore = backend.keystore();
        let kps = self.find_all_keypackages(&keystore).await?;
        let _ = self._prune_keypackages(&kps, &keystore, refs).await?;
        Ok(())
    }

    pub(crate) async fn prune_keypackages_and_credential(
        &mut self,
        backend: &MlsCryptoProvider,
        refs: &[KeyPackageRef],
    ) -> Result<()> {
        match self.inner.write().await.deref_mut() {
            None => Err(Error::MlsNotInitialized),
            Some(SessionInner { identities, .. }) => {
                let keystore = backend.key_store();
                let kps = self.find_all_keypackages(keystore).await?;
                let kp_to_delete = self._prune_keypackages(&kps, keystore, refs).await?;

                // Let's group KeyPackages by Credential
                let mut grouped_kps = HashMap::<Vec<u8>, Vec<KeyPackageRef>>::new();
                for (_, kp) in &kps {
                    let cred = kp
                        .leaf_node()
                        .credential()
                        .tls_serialize_detached()
                        .map_err(Error::tls_serialize("keypackage"))?;
                    let kp_ref = kp
                        .hash_ref(backend.crypto())
                        .map_err(MlsError::wrap("computing keypackage hashref"))?;
                    grouped_kps
                        .entry(cred)
                        .and_modify(|kprfs| kprfs.push(kp_ref.clone()))
                        .or_insert(vec![kp_ref]);
                }

                for (credential, kps) in &grouped_kps {
                    // If all KeyPackages are to be deleted for this given Credential
                    let all_to_delete = kps.iter().all(|kpr| kp_to_delete.contains(&kpr.as_slice()));
                    if all_to_delete {
                        // then delete this Credential
                        backend
                            .keystore()
                            .cred_delete_by_credential(credential.clone())
                            .await
                            .map_err(KeystoreError::wrap("deleting credential"))?;
                        let credential = Credential::tls_deserialize(&mut credential.as_slice())
                            .map_err(Error::tls_deserialize("credential"))?;
                        identities.remove(&credential).await?;
                    }
                }
                Ok(())
            }
        }
    }

    /// Deletes all expired KeyPackages plus the ones in `refs`. It also deletes all associated:
    /// * HPKE private keys
    /// * HPKE Encryption KeyPairs
    /// * Signature KeyPairs & Credentials (use [Self::prune_keypackages_and_credential])
    async fn _prune_keypackages<'a>(
        &self,
        kps: &'a [(MlsKeyPackage, KeyPackage)],
        keystore: &CryptoKeystore,
        refs: &[KeyPackageRef],
    ) -> Result<Vec<&'a [u8]>, Error> {
        let kp_to_delete: Vec<_> = kps
            .iter()
            .filter_map(|(store_kp, kp)| {
                let is_expired = Self::is_mls_keypackage_expired(kp);
                let mut to_delete = is_expired;
                if !(is_expired || refs.is_empty()) {
                    // not expired and there are some refs to check
                    // then delete it when it's found in the refs
                    to_delete = refs.iter().any(|r| r.as_slice() == store_kp.keypackage_ref);
                }

                to_delete.then_some((kp, &store_kp.keypackage_ref))
            })
            .collect();

        for (kp, kp_ref) in &kp_to_delete {
            // TODO: maybe rewrite this to optimize it. But honestly it's called so rarely and on a so tiny amount of data. Tacking issue: WPB-9600
            keystore
                .remove::<MlsKeyPackage, &[u8]>(kp_ref.as_slice())
                .await
                .map_err(KeystoreError::wrap("removing key package from keystore"))?;
            keystore
                .remove::<MlsHpkePrivateKey, &[u8]>(kp.hpke_init_key().as_slice())
                .await
                .map_err(KeystoreError::wrap("removing private key from keystore"))?;
            keystore
                .remove::<MlsEncryptionKeyPair, &[u8]>(kp.leaf_node().encryption_key().as_slice())
                .await
                .map_err(KeystoreError::wrap("removing encryption keypair from keystore"))?;
        }

        let kp_to_delete = kp_to_delete
            .into_iter()
            .map(|(_, kpref)| &kpref[..])
            .collect::<Vec<_>>();

        Ok(kp_to_delete)
    }

    async fn find_all_keypackages(&self, keystore: &CryptoKeystore) -> Result<Vec<(MlsKeyPackage, KeyPackage)>> {
        let kps: Vec<MlsKeyPackage> = keystore
            .find_all(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all keypackages"))?;

        let kps = kps
            .into_iter()
            .map(|raw_kp| -> Result<_> {
                let kp = core_crypto_keystore::deser::<KeyPackage>(&raw_kp.keypackage)
                    .map_err(KeystoreError::wrap("deserializing keypackage"))?;
                Ok((raw_kp, kp))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(kps)
    }

    /// Allows to set the current default keypackage lifetime extension duration.
    /// It will be embedded in the [openmls::key_packages::KeyPackage]'s [openmls::extensions::LifetimeExtension]
    #[cfg(test)]
    pub async fn set_keypackage_lifetime(&self, duration: std::time::Duration) -> Result<()> {
        use std::ops::DerefMut;
        match self.inner.write().await.deref_mut() {
            None => Err(Error::MlsNotInitialized),
            Some(SessionInner {
                keypackage_lifetime, ..
            }) => {
                *keypackage_lifetime = duration;
                Ok(())
            }
        }
    }
}

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
        let client = self
            .session()
            .await
            .map_err(RecursiveError::transaction("getting mls client"))?;
        client
            .request_key_packages(
                amount_requested,
                ciphersuite,
                credential_type,
                &self
                    .mls_provider()
                    .await
                    .map_err(RecursiveError::transaction("getting mls provider"))?,
            )
            .await
    }

    /// Returns the count of valid, non-expired, unclaimed keypackages in store for the given [MlsCiphersuite] and [MlsCredentialType]
    #[cfg_attr(test, crate::idempotent)]
    pub async fn client_valid_key_packages_count(
        &self,
        ciphersuite: MlsCiphersuite,
        credential_type: MlsCredentialType,
    ) -> Result<usize> {
        let client = self
            .session()
            .await
            .map_err(RecursiveError::transaction("getting mls client"))?;
        client
            .valid_keypackages_count(
                &self
                    .mls_provider()
                    .await
                    .map_err(RecursiveError::transaction("getting mls provider"))?,
                ciphersuite,
                credential_type,
            )
            .await
    }

    /// Prunes local KeyPackages after making sure they also have been deleted on the backend side
    /// You should only use this after [TransactionContext::save_x509_credential]
    #[cfg_attr(test, crate::dispotent)]
    pub async fn delete_keypackages(&self, refs: &[KeyPackageRef]) -> Result<()> {
        if refs.is_empty() {
            return Err(Error::EmptyKeypackageList);
        }
        let mut client = self
            .session()
            .await
            .map_err(RecursiveError::transaction("getting mls client"))?;
        client
            .prune_keypackages_and_credential(
                &self
                    .mls_provider()
                    .await
                    .map_err(RecursiveError::transaction("getting mls provider"))?,
                refs,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use openmls::prelude::{KeyPackage, KeyPackageIn, KeyPackageRef, ProtocolVersion};
    use openmls_traits::OpenMlsCryptoProvider;
    use openmls_traits::types::VerifiableCiphersuite;
    use wasm_bindgen_test::*;

    use mls_crypto_provider::MlsCryptoProvider;

    use crate::e2e_identity::enrollment::test_utils::{e2ei_enrollment, init_activation_or_rotation, noop_restore};
    use crate::prelude::MlsConversationConfiguration;
    use crate::prelude::key_package::INITIAL_KEYING_MATERIAL_COUNT;
    use crate::test_utils::*;
    use core_crypto_keystore::DatabaseKey;

    use super::Session;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_assess_keypackage_expiration(case: TestCase) {
        run_test_with_central(case.clone(), move |[central]| {
            Box::pin(async move {
                let (cs, ct) = (case.ciphersuite(), case.credential_type);
                let key = DatabaseKey::generate();
                let backend = MlsCryptoProvider::try_new_in_memory(&key).await.unwrap();
                let x509_test_chain = if case.is_x509() {
                    let x509_test_chain = crate::test_utils::x509::X509TestChain::init_empty(case.signature_scheme());
                    x509_test_chain.register_with_provider(&backend).await;
                    Some(x509_test_chain)
                } else {
                    None
                };

                backend.new_transaction().await.unwrap();
                let client = central.session;
                client
                    .random_generate(
                        &case,
                        x509_test_chain.as_ref().map(|chain| chain.find_local_intermediate_ca()),
                        false,
                    )
                    .await
                    .unwrap();

                // 90-day standard expiration
                let kp_std_exp = client.generate_one_keypackage(&backend, cs, ct).await.unwrap();
                assert!(!Session::is_mls_keypackage_expired(&kp_std_exp));

                // 1-second expiration
                client
                    .set_keypackage_lifetime(std::time::Duration::from_secs(1))
                    .await
                    .unwrap();
                let kp_1s_exp = client.generate_one_keypackage(&backend, cs, ct).await.unwrap();
                // Sleep 2 seconds to make sure we make the kp expire
                async_std::task::sleep(std::time::Duration::from_secs(2)).await;
                assert!(Session::is_mls_keypackage_expired(&kp_1s_exp));
            })
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn requesting_x509_key_packages_after_basic(case: TestCase) {
        // Basic test case
        if !case.is_basic() {
            return;
        }
        run_test_with_client_ids(case.clone(), ["alice"], move |[mut session_context]| {
            Box::pin(async move {
                let signature_scheme = case.signature_scheme();
                let cipher_suite = case.ciphersuite();

                // Generate 5 Basic key packages first
                let _basic_key_packages = session_context
                    .context
                    .get_or_create_client_keypackages(cipher_suite, MlsCredentialType::Basic, 5)
                    .await
                    .unwrap();

                // Set up E2E identity
                let test_chain = x509::X509TestChain::init_for_random_clients(signature_scheme, 1);

                let (mut enrollment, cert_chain) = e2ei_enrollment(
                    &mut session_context,
                    &case,
                    &test_chain,
                    None,
                    false,
                    init_activation_or_rotation,
                    noop_restore,
                )
                .await
                .unwrap();

                let _rotate_bundle = session_context
                    .context
                    .save_x509_credential(&mut enrollment, cert_chain)
                    .await
                    .unwrap();

                // E2E identity has been set up correctly
                assert!(session_context.context.e2ei_is_enabled(signature_scheme).await.unwrap());

                // Request X509 key packages
                let x509_key_packages = session_context
                    .context
                    .get_or_create_client_keypackages(cipher_suite, MlsCredentialType::X509, 5)
                    .await
                    .unwrap();

                // Verify that the key packages are X509
                assert!(x509_key_packages.iter().all(|kp| MlsCredentialType::X509
                    == MlsCredentialType::from(kp.leaf_node().credential().credential_type())));
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn generates_correct_number_of_kpbs(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice"], move |[cc]| {
            Box::pin(async move {
                const N: usize = 2;
                const COUNT: usize = 109;

                let init = cc.context.count_entities().await;
                assert_eq!(init.key_package, INITIAL_KEYING_MATERIAL_COUNT);
                assert_eq!(init.encryption_keypair, INITIAL_KEYING_MATERIAL_COUNT);
                assert_eq!(init.hpke_private_key, INITIAL_KEYING_MATERIAL_COUNT);
                assert_eq!(init.credential, 1);
                assert_eq!(init.signature_keypair, 1);

                // since 'delete_keypackages' will evict all Credentials unlinked to a KeyPackage, each iteration
                // generates 1 extra KeyPackage in order for this Credential no to be evicted and next iteration sto succeed.
                let transactional_provider = cc.context.mls_provider().await.unwrap();
                let crypto_provider = transactional_provider.crypto();
                let mut pinned_kp = None;

                let mut prev_kps: Option<Vec<KeyPackage>> = None;
                for _ in 0..N {
                    let mut kps = cc
                        .context
                        .get_or_create_client_keypackages(case.ciphersuite(), case.credential_type, COUNT + 1)
                        .await
                        .unwrap();

                    // this will always be the same, first KeyPackage
                    pinned_kp = Some(kps.pop().unwrap());

                    assert_eq!(kps.len(), COUNT);
                    let after_creation = cc.context.count_entities().await;
                    assert_eq!(after_creation.key_package, COUNT + 1);
                    assert_eq!(after_creation.encryption_keypair, COUNT + 1);
                    assert_eq!(after_creation.hpke_private_key, COUNT + 1);
                    assert_eq!(after_creation.credential, 1);

                    let kpbs_refs = kps
                        .iter()
                        .map(|kp| kp.hash_ref(crypto_provider).unwrap())
                        .collect::<Vec<KeyPackageRef>>();

                    if let Some(pkpbs) = prev_kps.replace(kps) {
                        let pkpbs_refs = pkpbs
                            .into_iter()
                            .map(|kpb| kpb.hash_ref(crypto_provider).unwrap())
                            .collect::<Vec<KeyPackageRef>>();

                        let has_duplicates = kpbs_refs.iter().any(|href| pkpbs_refs.contains(href));
                        // Make sure we have no previous keypackages found (that were pruned) in our new batch of KPs
                        assert!(!has_duplicates);
                    }
                    cc.context.delete_keypackages(&kpbs_refs).await.unwrap();
                }

                let count = cc
                    .context
                    .client_valid_key_packages_count(case.ciphersuite(), case.credential_type)
                    .await
                    .unwrap();
                assert_eq!(count, 1);

                let pinned_kpr = pinned_kp.unwrap().hash_ref(crypto_provider).unwrap();
                cc.context.delete_keypackages(&[pinned_kpr]).await.unwrap();
                let count = cc
                    .context
                    .client_valid_key_packages_count(case.ciphersuite(), case.credential_type)
                    .await
                    .unwrap();
                assert_eq!(count, 0);
                let after_delete = cc.context.count_entities().await;
                assert_eq!(after_delete.key_package, 0);
                assert_eq!(after_delete.encryption_keypair, 0);
                assert_eq!(after_delete.hpke_private_key, 0);
                assert_eq!(after_delete.credential, 0);
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn automatically_prunes_lifetime_expired_keypackages(case: TestCase) {
        run_test_with_central(case.clone(), move |[central]| {
            Box::pin(async move {
                const UNEXPIRED_COUNT: usize = 125;
                const EXPIRED_COUNT: usize = 200;
                let key = DatabaseKey::generate();
                let backend = MlsCryptoProvider::try_new_in_memory(&key).await.unwrap();
                let x509_test_chain = if case.is_x509() {
                    let x509_test_chain = crate::test_utils::x509::X509TestChain::init_empty(case.signature_scheme());
                    x509_test_chain.register_with_provider(&backend).await;
                    Some(x509_test_chain)
                } else {
                    None
                };
                backend.new_transaction().await.unwrap();
                let client = central.session().await;
                client
                    .random_generate(
                        &case,
                        x509_test_chain.as_ref().map(|chain| chain.find_local_intermediate_ca()),
                        false,
                    )
                    .await
                    .unwrap();

                // Generate `UNEXPIRED_COUNT` kpbs that are with default 3 months expiration. We *should* keep them for the duration of the test
                let unexpired_kpbs = client
                    .request_key_packages(UNEXPIRED_COUNT, case.ciphersuite(), case.credential_type, &backend)
                    .await
                    .unwrap();
                let len = client
                    .valid_keypackages_count(&backend, case.ciphersuite(), case.credential_type)
                    .await
                    .unwrap();
                assert_eq!(len, unexpired_kpbs.len());
                assert_eq!(len, UNEXPIRED_COUNT);

                // Set the keypackage expiration to be in 2 seconds
                client
                    .set_keypackage_lifetime(std::time::Duration::from_secs(10))
                    .await
                    .unwrap();

                // Generate new keypackages that are normally partially expired 2s after they're requested
                let partially_expired_kpbs = client
                    .request_key_packages(EXPIRED_COUNT, case.ciphersuite(), case.credential_type, &backend)
                    .await
                    .unwrap();
                assert_eq!(partially_expired_kpbs.len(), EXPIRED_COUNT);

                // Sleep to trigger the expiration
                async_std::task::sleep(std::time::Duration::from_secs(10)).await;

                // Request the same number of keypackages. The automatic lifetime-based expiration should take
                // place and remove old expired keypackages and generate fresh ones instead
                let fresh_kpbs = client
                    .request_key_packages(EXPIRED_COUNT, case.ciphersuite(), case.credential_type, &backend)
                    .await
                    .unwrap();
                let len = client
                    .valid_keypackages_count(&backend, case.ciphersuite(), case.credential_type)
                    .await
                    .unwrap();
                assert_eq!(len, fresh_kpbs.len());
                assert_eq!(len, EXPIRED_COUNT);

                // Try to deep compare and find kps matching expired and non-expired ones
                let (unexpired_match, expired_match) =
                    fresh_kpbs
                        .iter()
                        .fold((0usize, 0usize), |(mut unexpired_match, mut expired_match), fresh| {
                            if unexpired_kpbs.iter().any(|kp| kp == fresh) {
                                unexpired_match += 1;
                            } else if partially_expired_kpbs.iter().any(|kpb| kpb == fresh) {
                                expired_match += 1;
                            }

                            (unexpired_match, expired_match)
                        });

                // TADA!
                assert_eq!(unexpired_match, UNEXPIRED_COUNT);
                assert_eq!(expired_match, 0);
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn new_keypackage_has_correct_extensions(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice"], move |[cc]| {
            Box::pin(async move {
                let kps = cc
                    .context
                    .get_or_create_client_keypackages(case.ciphersuite(), case.credential_type, 1)
                    .await
                    .unwrap();
                let kp = kps.first().unwrap();

                // make sure it's valid
                let _ = KeyPackageIn::from(kp.clone())
                    .standalone_validate(&cc.context.mls_provider().await.unwrap(), ProtocolVersion::Mls10, true)
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
        })
        .await
    }
}
