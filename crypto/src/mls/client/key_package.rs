// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::{
    mls::credential::CredentialBundle,
    prelude::{Client, CryptoError, CryptoResult, MlsCiphersuite, MlsCredentialType, MlsError},
};
use core_crypto_keystore::connection::KeystoreDatabaseConnection;
use openmls::prelude::{CredentialWithKey, CryptoConfig, KeyPackage, KeyPackageRef, Lifetime};
use openmls_traits::OpenMlsCryptoProvider;
use std::collections::{HashMap, HashSet};
use tls_codec::Serialize;

use core_crypto_keystore::entities::{
    EntityBase, EntityFindParams, MlsCredential, MlsCredentialExt, MlsEncryptionKeyPair, MlsHpkePrivateKey,
    MlsKeyPackage, MlsSignatureKeyPair,
};
use mls_crypto_provider::MlsCryptoProvider;

/// Default number of KeyPackages a client generates the first time it's created
#[cfg(not(test))]
pub(crate) const INITIAL_KEYING_MATERIAL_COUNT: usize = 100;
#[cfg(test)]
pub(crate) const INITIAL_KEYING_MATERIAL_COUNT: usize = 10;

/// Default lifetime of all generated KeyPackages. Matches the limit defined in openmls
pub(crate) const KEYPACKAGE_DEFAULT_LIFETIME: std::time::Duration =
    std::time::Duration::from_secs(60 * 60 * 24 * 28 * 3); // ~3 months

impl Client {
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
    ) -> CryptoResult<KeyPackage> {
        let keypackage = KeyPackage::builder()
            .key_package_lifetime(Lifetime::new(self.keypackage_lifetime.as_secs()))
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
            .map_err(MlsError::from)?;

        Ok(keypackage)
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
    ) -> CryptoResult<Vec<KeyPackage>> {
        // Auto-prune expired keypackages on request
        self.prune_keypackages(backend, &[]).await?;
        use core_crypto_keystore::CryptoKeystoreMls as _;

        let mut existing_kps = backend
            .key_store()
            .mls_fetch_keypackages::<KeyPackage>(count as u32)
            .await?
            .into_iter()
            // TODO: do this filtering in SQL when the schema is updated
            .filter(|kp| kp.ciphersuite() == ciphersuite.0)
            .collect::<Vec<_>>();

        let kpb_count = existing_kps.len();
        let mut kps = if count > kpb_count {
            let to_generate = count - kpb_count;
            let cb = self
                .find_most_recent_credential_bundle(ciphersuite.signature_algorithm(), credential_type)
                .ok_or(CryptoError::MlsNotInitialized)?;
            self.generate_new_keypackages(backend, ciphersuite, cb, to_generate)
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
    ) -> CryptoResult<Vec<KeyPackage>> {
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
    ) -> CryptoResult<usize> {
        use core_crypto_keystore::entities::EntityBase as _;
        let keystore = backend.key_store();

        let mut conn = keystore.borrow_conn().await?;
        let kps = MlsKeyPackage::find_all(&mut conn, EntityFindParams::default()).await?;

        let valid_count = kps
            .into_iter()
            .map(|kp| core_crypto_keystore::deser::<KeyPackage>(&kp.keypackage))
            // TODO: do this filtering in SQL when the schema is updated
            .filter(|kp| {
                kp.as_ref()
                    .map(|b| b.ciphersuite() == ciphersuite.0 && MlsCredentialType::from(b.leaf_node().credential().credential_type()) == credential_type)
                    .unwrap_or_default()
            })
            .try_fold(0usize, |mut valid_count, kp| {
                if !Self::is_mls_keypackage_expired(&kp?) {
                    valid_count += 1;
                }
                CryptoResult::Ok(valid_count)
            })?;

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
    pub async fn prune_keypackages(&self, backend: &MlsCryptoProvider, refs: &[KeyPackageRef]) -> CryptoResult<()> {
        let mut conn = backend.key_store().borrow_conn().await?;
        let _ = self._prune_keypackages(&mut conn, refs, false).await?;
        Ok(())
    }

    pub(crate) async fn prune_keypackages_and_credential(
        &mut self,
        backend: &MlsCryptoProvider,
        refs: &[KeyPackageRef],
    ) -> CryptoResult<()> {
        let mut conn = backend.key_store().borrow_conn().await?;
        let credentials_to_remove = self._prune_keypackages(&mut conn, refs, true).await?;

        for (credential, kps) in credentials_to_remove {
            MlsCredential::delete_by_credential(&mut conn, credential).await?;

            let sign_kp_to_delete = kps.iter().map(|k| k[..].into()).collect::<Vec<_>>();
            MlsSignatureKeyPair::delete(&mut conn, &sign_kp_to_delete).await?;

            let sign_kp_to_delete = kps.into_iter().collect::<Vec<_>>();
            self.identities
                .remove_credential_bundles(sign_kp_to_delete.as_slice())?;
        }

        Ok(())
    }

    /// Deletes all expired KeyPackages plus the ones in `refs`. It also deletes all associated:
    /// * HPKE private keys
    /// * HPKE Encryption KeyPairs
    /// * Signature KeyPairs & Credentials (use [Self::prune_keypackages_and_credential])
    async fn _prune_keypackages(
        &self,
        conn: &mut KeystoreDatabaseConnection,
        refs: &[KeyPackageRef],
        mut prune_credential: bool,
    ) -> CryptoResult<HashMap<Vec<u8>, HashSet<Vec<u8>>>> {
        use core_crypto_keystore::entities::EntityBase as _;

        let kps = MlsKeyPackage::find_all(conn, EntityFindParams::default()).await?;

        prune_credential = prune_credential && !refs.is_empty();

        let (kp_refs_to_delete, sign_kp_to_delete, sign_kp_to_keep, hpke_sk_to_delete, hpke_encryption_kp_to_delete) =
            kps.iter().try_fold(
                (
                    vec![],
                    HashMap::<Vec<u8>, HashSet<Vec<u8>>>::new(),
                    HashSet::new(),
                    HashSet::new(),
                    HashSet::new(),
                ),
                |(
                    mut kp_refs_to_delete,
                    mut sign_kp_to_delete,
                    mut sign_kp_to_keep,
                    mut hpke_sk_to_delete,
                    mut hpke_encryption_kp_to_delete,
                ),
                 store_kp| {
                    let kp = core_crypto_keystore::deser::<KeyPackage>(&store_kp.keypackage)?;

                    let is_expired = Self::is_mls_keypackage_expired(&kp);
                    let mut to_delete = is_expired;
                    if !(is_expired || refs.is_empty()) {
                        // not expired and there are some refs to check
                        // then delete it when it's found in the refs
                        to_delete = refs.iter().any(|r| r.as_slice() == store_kp.keypackage_ref);
                    }

                    let leaf_node = kp.leaf_node();
                    let sign_pk = leaf_node.signature_key().as_slice();
                    if to_delete {
                        kp_refs_to_delete.push(store_kp.keypackage_ref.as_slice().into());
                        hpke_sk_to_delete.insert(kp.hpke_init_key().as_slice().to_vec());
                        hpke_encryption_kp_to_delete.insert(leaf_node.encryption_key().as_slice().to_vec());

                        // Just stack all the credential and its associated signature keys to delete
                        let credential = leaf_node.credential();
                        let raw_credential = credential.tls_serialize_detached().map_err(MlsError::from)?;

                        sign_kp_to_delete
                            .entry(raw_credential)
                            .and_modify(|c| {
                                c.insert(sign_pk.to_vec());
                            })
                            .or_insert_with(|| HashSet::from([sign_pk.to_vec()]));
                    } else if prune_credential {
                        sign_kp_to_keep.insert(sign_pk.to_vec());
                    }
                    CryptoResult::Ok((
                        kp_refs_to_delete,
                        sign_kp_to_delete,
                        sign_kp_to_keep,
                        hpke_sk_to_delete,
                        hpke_encryption_kp_to_delete,
                    ))
                },
            )?;

        if !kp_refs_to_delete.is_empty() {
            MlsKeyPackage::delete(conn, &kp_refs_to_delete).await?;
        }

        let hpke_sk_to_delete = hpke_sk_to_delete.iter().map(|k| k[..].into()).collect::<Vec<_>>();
        if !hpke_sk_to_delete.is_empty() {
            MlsHpkePrivateKey::delete(conn, &hpke_sk_to_delete).await?;
        }

        let hpke_encryption_kp_to_delete = hpke_encryption_kp_to_delete
            .iter()
            .map(|k| k[..].into())
            .collect::<Vec<_>>();
        if !hpke_encryption_kp_to_delete.is_empty() {
            MlsEncryptionKeyPair::delete(conn, &hpke_encryption_kp_to_delete).await?;
        }

        // Delete all the credentials except those whose signature keypair is referenced by a KeyPackage
        let credentials_to_delete = sign_kp_to_delete
            .into_iter()
            .filter(|(_, kps)| {
                let to_keep = kps.iter().any(|kp| sign_kp_to_keep.contains(kp.as_slice()));
                !to_keep
            })
            .collect();

        Ok(credentials_to_delete)
    }

    /// Allows to set the current default keypackage lifetime extension duration.
    /// It will be embedded in the [openmls::key_packages::KeyPackage]'s [openmls::extensions::LifetimeExtension]
    #[cfg(test)]
    pub fn set_keypackage_lifetime(&mut self, duration: std::time::Duration) {
        self.keypackage_lifetime = duration;
    }
}

#[cfg(test)]
pub mod tests {
    use openmls::prelude::{KeyPackage, KeyPackageRef};
    use wasm_bindgen_test::*;

    use mls_crypto_provider::MlsCryptoProvider;

    use super::Client;
    use crate::test_utils::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn can_assess_keypackage_expiration(case: TestCase) {
        let (cs, ct) = (case.ciphersuite(), case.credential_type);
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        let mut client = Client::random_generate(&case, &backend, false).await.unwrap();

        // 90-day standard expiration
        let kp_std_exp = client.generate_one_keypackage(&backend, cs, ct).await.unwrap();
        assert!(!Client::is_mls_keypackage_expired(&kp_std_exp));

        // 1-second expiration
        client.set_keypackage_lifetime(std::time::Duration::from_secs(1));
        let kp_1s_exp = client.generate_one_keypackage(&backend, cs, ct).await.unwrap();
        // Sleep 2 seconds to make sure we make the kp expire
        async_std::task::sleep(std::time::Duration::from_secs(2)).await;
        assert!(Client::is_mls_keypackage_expired(&kp_1s_exp));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn client_generates_correct_number_of_kpbs(case: TestCase) {
        use openmls_traits::OpenMlsCryptoProvider as _;
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        let client = Client::random_generate(&case, &backend, false).await.unwrap();

        const COUNT: usize = 124;

        let mut prev_kps: Option<Vec<KeyPackage>> = None;
        for _ in 0..50 {
            let kps = client
                .request_key_packages(COUNT, case.ciphersuite(), case.credential_type, &backend)
                .await
                .unwrap();
            assert_eq!(kps.len(), COUNT);

            let kpbs_refs: Vec<KeyPackageRef> = kps.iter().map(|kp| kp.hash_ref(backend.crypto()).unwrap()).collect();

            if let Some(pkpbs) = prev_kps.replace(kps) {
                let crypto = backend.crypto();
                let pkpbs_refs: Vec<KeyPackageRef> =
                    pkpbs.into_iter().map(|kpb| kpb.hash_ref(crypto).unwrap()).collect();

                let has_duplicates = kpbs_refs.iter().any(|href| pkpbs_refs.contains(href));
                // Make sure we have no previous keypackages found (that were pruned) in our new batch of KPs
                assert!(!has_duplicates);
            }
            client.prune_keypackages(&backend, &kpbs_refs).await.unwrap();
        }
        let count = client
            .valid_keypackages_count(&backend, case.ciphersuite(), case.credential_type)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn client_automatically_prunes_lifetime_expired_keypackages(case: TestCase) {
        const UNEXPIRED_COUNT: usize = 125;
        const EXPIRED_COUNT: usize = 200;
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        let mut client = Client::random_generate(&case, &backend, false).await.unwrap();

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
        client.set_keypackage_lifetime(std::time::Duration::from_secs(2));

        // Generate new keypackages that are normally partially expired 2s after they're requested
        let partially_expired_kpbs = client
            .request_key_packages(EXPIRED_COUNT, case.ciphersuite(), case.credential_type, &backend)
            .await
            .unwrap();
        assert_eq!(partially_expired_kpbs.len(), EXPIRED_COUNT);

        // Sleep to trigger the expiration
        async_std::task::sleep(std::time::Duration::from_secs(5)).await;

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
    }
}
