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

use openmls::prelude::{CredentialBundle, KeyPackage};
use openmls::{
    extensions::Extension,
    prelude::{KeyPackageBundle, KeyPackageRef},
};
use openmls_traits::{
    key_store::{FromKeyStoreValue, OpenMlsKeyStore},
    OpenMlsCryptoProvider,
};

use crate::{
    mls::credential::typ::MlsCredentialType,
    prelude::{identities::ClientIdentities, Client, CryptoError, CryptoResult, MlsCiphersuite, MlsError},
};
use core_crypto_keystore::{
    entities::{EntityFindParams, MlsKeypackage, StringEntityId},
    CryptoKeystoreError, CryptoKeystoreResult,
};
use mls_crypto_provider::MlsCryptoProvider;

///
pub(crate) const INITIAL_KEYING_MATERIAL_COUNT: usize = 100;

///
pub(crate) const KEYPACKAGE_DEFAULT_LIFETIME: std::time::Duration = std::time::Duration::from_secs(60 * 60 * 24 * 90); // 3 months

impl Client {
    /// This method returns the hash of the oldest available KeyPackageBundle for the Client
    /// and if necessary regenerates a new keypackage for immediate use
    ///
    /// # Arguments
    /// * `backend` - the KeyStorage to load the keypackages from
    ///
    /// # Errors
    /// KeyStore errors
    pub async fn oldest_keypackage_hash(
        &self,
        backend: &MlsCryptoProvider,
        cs: MlsCiphersuite,
        ct: MlsCredentialType,
    ) -> CryptoResult<KeyPackageRef> {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        let kpb_result: CryptoKeystoreResult<KeyPackageBundle> = backend.key_store().mls_get_keypackage().await;
        let kp = match kpb_result {
            Ok(kpb) => Ok(kpb.key_package().clone()),
            Err(CryptoKeystoreError::OutOfKeyPackageBundles) => Ok(self.generate_keypackage(backend, cs, ct).await?),
            Err(e) => Err(CryptoError::KeyStoreError(e)),
        }?;
        Ok(kp.hash_ref(backend.crypto()).map_err(MlsError::from)?)
    }

    /// Generates a single new keypackage
    ///
    /// # Arguments
    /// * `backend` - the KeyStorage to load the keypackages from
    ///
    /// # Errors
    /// KeyStore and OpenMls errors
    pub async fn generate_keypackages(&self, backend: &MlsCryptoProvider) -> CryptoResult<Vec<KeyPackage>> {
        use futures_util::{StreamExt as _, TryStreamExt as _};
        futures_util::stream::iter(self.identities.iter())
            .map(Ok::<_, CryptoError>)
            .try_fold(
                Vec::with_capacity(ClientIdentities::MAX_DISTINCT_SIZE),
                |mut acc, (cs, cred)| async move {
                    let lifetime = Extension::LifeTime(openmls::prelude::LifetimeExtension::new(
                        self.keypackage_lifetime.as_secs(),
                    ));
                    let kpb = KeyPackageBundle::new(&[*cs], cred, backend, vec![lifetime]).map_err(MlsError::from)?;

                    let href = kpb.key_package().hash_ref(backend.crypto()).map_err(MlsError::from)?;
                    backend.key_store().store(href.value(), &kpb).await?;

                    acc.push(kpb.key_package().clone());
                    Ok(acc)
                },
            )
            .await
    }

    /// Generates a single new keypackage
    ///
    /// # Arguments
    /// * `backend` - the KeyStorage to load the keypackages from
    ///
    /// # Errors
    /// KeyStore and OpenMls errors
    pub async fn generate_keypackage(
        &self,
        backend: &MlsCryptoProvider,
        cs: MlsCiphersuite,
        ct: MlsCredentialType,
    ) -> CryptoResult<KeyPackage> {
        let cb = self
            .identities
            .find_credential_bundle(cs, ct)
            .ok_or(CryptoError::ImplementationError)?;
        self.generate_keypackage_from_credential_bundle(backend, cb, cs).await
    }

    /// Generates a single new keypackage
    ///
    /// # Arguments
    /// * `backend` - the KeyStorage to load the keypackages from
    ///
    /// # Errors
    /// KeyStore and OpenMls errors
    pub async fn generate_keypackage_from_credential_bundle(
        &self,
        backend: &MlsCryptoProvider,
        cb: &CredentialBundle,
        cs: MlsCiphersuite,
    ) -> CryptoResult<KeyPackage> {
        let lifetime = Extension::LifeTime(openmls::prelude::LifetimeExtension::new(
            self.keypackage_lifetime.as_secs(),
        ));
        let kpb = KeyPackageBundle::new(&[*cs], cb, backend, vec![lifetime]).map_err(MlsError::from)?;

        let href = kpb.key_package().hash_ref(backend.crypto()).map_err(MlsError::from)?;
        backend.key_store().store(href.value(), &kpb).await?;
        Ok(kpb.key_package().clone())
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
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Vec<KeyPackage>> {
        // Auto-prune expired keypackages on request
        self.prune_keypackages(&[], backend).await?;
        use core_crypto_keystore::CryptoKeystoreMls as _;

        let mut existing_kps = backend
            .key_store()
            .mls_fetch_keypackage_bundles::<KeyPackageBundle>(count as u32)
            .await?
            .into_iter()
            .map(|kpb| kpb.key_package().clone())
            // TODO: do this filtering in SQL when the schema is updated
            .filter(|kp| kp.ciphersuite() == ciphersuite.0)
            .collect::<Vec<_>>();

        let kpb_count = existing_kps.len();
        let mut kps = if count > kpb_count {
            let to_generate = count - kpb_count;
            // Requires 1 KeyPackageBundle per supported Ciphersuite and per CredentialType
            // let nb_kpb = to_generate * self.identities.count();

            let nb_kpb = to_generate;

            use futures_util::{StreamExt as _, TryStreamExt as _};
            futures_util::stream::iter(0..nb_kpb)
                .map(Ok::<_, CryptoError>)
                .try_fold(Vec::with_capacity(nb_kpb), |mut acc, _| async move {
                    let mut kpb = self.generate_keypackages(backend).await?;
                    acc.append(&mut kpb);
                    Ok(acc)
                })
                .await?
        } else {
            vec![]
        };
        kps.append(&mut existing_kps);
        Ok(kps)
    }

    /// Returns the count of valid, non-expired, unclaimed keypackages in store
    pub async fn valid_keypackages_count(
        &self,
        backend: &MlsCryptoProvider,
        ciphersuite: MlsCiphersuite,
    ) -> CryptoResult<usize> {
        use core_crypto_keystore::entities::EntityBase as _;
        let keystore = backend.key_store();

        let mut conn = keystore.borrow_conn().await?;
        let kps = MlsKeypackage::find_all(&mut conn, EntityFindParams::default()).await?;

        let valid_count = kps
            .into_iter()
            .map(|kp| KeyPackageBundle::from_key_store_value(&kp.key).map_err(MlsError::from))
            // TODO: do this filtering in SQL when the schema is updated
            .filter(|kpb| {
                kpb.as_ref()
                    .map(|b| b.key_package().ciphersuite() == ciphersuite.0)
                    .unwrap_or_default()
            })
            .try_fold(0usize, |mut valid_count, kpb| {
                if !Self::is_mls_keypackage_expired(kpb?.key_package()) {
                    valid_count += 1;
                }
                CryptoResult::Ok(valid_count)
            })?;

        Ok(valid_count)
    }

    /// Checks if a given OpenMLS [`KeyPackage`] is expired by looking through its extensions,
    /// finding a lifetime extension and checking if it's valid.
    fn is_mls_keypackage_expired(kp: &KeyPackage) -> bool {
        kp.extensions()
            .iter()
            .find_map(|e| {
                if let Extension::LifeTime(lifetime_ext) = e {
                    if !lifetime_ext.is_valid() {
                        Some(true)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }

    /// Prune the provided KeyPackageRefs from the keystore
    ///
    /// Warning: Despite this API being public, the caller should know what they're doing.
    /// Provided KeypackageRefs **will** be purged regardless of their expiration state, so please be wary of what you are doing if you directly call this API.
    /// This could result in still valid, uploaded keypackages being pruned from the system and thus being impossible to find when referenced in a future Welcome message.
    pub async fn prune_keypackages(&self, refs: &[KeyPackageRef], backend: &MlsCryptoProvider) -> CryptoResult<()> {
        use core_crypto_keystore::entities::EntityBase as _;
        let keystore = backend.key_store();

        let mut conn = keystore.borrow_conn().await?;

        let kps = MlsKeypackage::find_all(&mut conn, EntityFindParams::default()).await?;

        let ids_to_delete = kps.into_iter().try_fold(Vec::new(), |mut acc, kp| {
            let kpb = KeyPackageBundle::from_key_store_value(&kp.key).map_err(MlsError::from)?;
            let mut is_expired = Self::is_mls_keypackage_expired(kpb.key_package());
            if !is_expired && !refs.is_empty() {
                const HASH_REF_VALUE_LEN: usize = 16;
                let href: [u8; HASH_REF_VALUE_LEN] = hex::decode(&kp.id)
                    .map_err(CryptoKeystoreError::from)?
                    .as_slice()
                    .try_into()
                    .map_err(CryptoKeystoreError::from)?;
                let href = KeyPackageRef::from(href);
                is_expired = refs.contains(&href);
            }

            if is_expired {
                acc.push(kp.id.clone());
            }

            CryptoResult::Ok(acc)
        })?;

        let entity_ids_to_delete: Vec<StringEntityId> = ids_to_delete.iter().map(|e| e.as_bytes().into()).collect();

        MlsKeypackage::delete(&mut conn, &entity_ids_to_delete).await?;

        Ok(())
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
        let kp_std_exp = client.generate_keypackage(&backend, cs, ct).await.unwrap();
        assert!(!Client::is_mls_keypackage_expired(&kp_std_exp));

        // 1-second expiration
        client.set_keypackage_lifetime(std::time::Duration::from_secs(1));
        let kp_1s_exp = client.generate_keypackage(&backend, cs, ct).await.unwrap();
        // Sleep 2 seconds to make sure we make the kp expire
        async_std::task::sleep(std::time::Duration::from_secs(2)).await;
        assert!(Client::is_mls_keypackage_expired(&kp_1s_exp));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn client_never_runs_out_of_keypackages(case: TestCase) {
        let (cs, ct) = (case.ciphersuite(), case.credential_type);
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        let client = Client::random_generate(&case, &backend, true).await.unwrap();
        for _ in 0..100 {
            assert!(client.oldest_keypackage_hash(&backend, cs, ct).await.is_ok())
        }
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
                .request_key_packages(COUNT, case.ciphersuite(), &backend)
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

            client.prune_keypackages(&kpbs_refs, &backend).await.unwrap();
        }
    }

    // #[apply(all_cred_cipher)]
    // #[wasm_bindgen_test]
    #[async_std::test]
    pub async fn client_automatically_prunes_lifetime_expired_keypackages(/*case: TestCase*/) {
        let case = TestCase::default();
        const UNEXPIRED_COUNT: usize = 125;
        const EXPIRED_COUNT: usize = 200;
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        let mut client = Client::random_generate(&case, &backend, false).await.unwrap();

        // Generate `UNEXPIRED_COUNT` kpbs that are with default 3 months expiration. We *should* keep them for the duration of the test
        let unexpired_kpbs = client
            .request_key_packages(UNEXPIRED_COUNT, case.ciphersuite(), &backend)
            .await
            .unwrap();
        let len = client
            .valid_keypackages_count(&backend, case.ciphersuite())
            .await
            .unwrap();
        assert_eq!(len, unexpired_kpbs.len());
        assert_eq!(len, UNEXPIRED_COUNT);

        // Set the keypackage expiration to be in 2 seconds
        client.set_keypackage_lifetime(std::time::Duration::from_secs(2));

        // Generate new keypackages that are normally partially expired 2s after they're requested
        let partially_expired_kpbs = client
            .request_key_packages(EXPIRED_COUNT, case.ciphersuite(), &backend)
            .await
            .unwrap();
        assert_eq!(partially_expired_kpbs.len(), EXPIRED_COUNT);

        // Sleep to trigger the expiration
        async_std::task::sleep(std::time::Duration::from_secs(5)).await;

        // Request the same number of keypackages. The automatic lifetime-based expiration should take
        // place and remove old expired keypackages and generate fresh ones instead
        let fresh_kpbs = client
            .request_key_packages(EXPIRED_COUNT, case.ciphersuite(), &backend)
            .await
            .unwrap();
        let len = client
            .valid_keypackages_count(&backend, case.ciphersuite())
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