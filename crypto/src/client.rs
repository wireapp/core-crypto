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

use crate::{CryptoError, CryptoResult, MlsCiphersuite, MlsError};
use core_crypto_keystore::{CryptoKeystoreError, CryptoKeystoreResult};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::{
    credentials::CredentialBundle,
    extensions::{Extension, ExternalKeyIdExtension, LifetimeExtension},
    prelude::{KeyPackageBundle, KeyPackageRef, TlsSerializeTrait},
};
use openmls_traits::{key_store::OpenMlsKeyStore, OpenMlsCryptoProvider};
use tls_codec::Deserialize;

pub(crate) const INITIAL_KEYING_MATERIAL_COUNT: usize = 100;
const KEYPACKAGE_DEFAULT_LIFETIME: std::time::Duration = std::time::Duration::from_secs(60 * 60 * 24 * 90); // 3 months

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientId(Vec<u8>);

impl std::ops::Deref for ClientId {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&[u8]> for ClientId {
    fn from(value: &[u8]) -> Self {
        Self(value.into())
    }
}

impl From<Vec<u8>> for ClientId {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_slice()))
    }
}

impl std::str::FromStr for ClientId {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.as_bytes().to_vec()))
    }
}

#[derive(Debug, tls_codec::TlsSize, tls_codec::TlsDeserialize)]
struct LifetimeExtensionHack {
    not_before: u64,
    not_after: u64,
}

impl LifetimeExtensionHack {
    fn is_valid(&self) -> bool {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|dur| {
                let now = dur.as_secs();
                self.not_before < now && now < self.not_after
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct Client {
    id: ClientId,
    credentials: CredentialBundle,
    ciphersuite: MlsCiphersuite,
    package_lifetime: std::time::Duration,
}

#[inline(always)]
fn identity_key(credentials: &CredentialBundle) -> Result<Vec<u8>, MlsError> {
    credentials
        .credential()
        .signature_key()
        .tls_serialize_detached()
        .map_err(MlsError::from)
}

impl Client {
    /// Initializes the client.
    /// If the client's cryptographic material is already stored in the keystore, it loads it
    /// Otherwise, it is being created.
    pub fn init(id: ClientId, backend: &MlsCryptoProvider) -> CryptoResult<Self> {
        let id_str: String = id.to_string();
        let (client, generated) = if let Some(signature) = backend.key_store().mls_load_identity_signature(&id_str)? {
            match Self::load(id.clone(), &signature, backend) {
                Ok(client) => (client, false),
                Err(CryptoError::ClientSignatureNotFound) => (Self::generate(id, backend)?, true),
                Err(e) => return Err(e),
            }
        } else {
            (Self::generate(id, backend)?, true)
        };

        if generated {
            backend
                .key_store()
                .mls_save_identity_signature(&id_str, &identity_key(&client.credentials)?)?;
        }

        Ok(client)
    }

    /// Generates a brand new client from scratch
    pub(crate) fn generate(id: ClientId, backend: &MlsCryptoProvider) -> CryptoResult<Self> {
        let ciphersuite = MlsCiphersuite::default();
        let id_bytes = &*id;
        let credentials = CredentialBundle::new(
            id_bytes.to_vec(),
            openmls::credentials::CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .map_err(MlsError::from)?;

        backend
            .key_store()
            .store(&identity_key(&credentials)?, &credentials)
            .map_err(eyre::Report::msg)?;

        let client = Self {
            id,
            credentials,
            ciphersuite,
            package_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        };

        client.request_keying_material(INITIAL_KEYING_MATERIAL_COUNT, backend)?;

        Ok(client)
    }

    /// Loads the client from the keystore.
    pub(crate) fn load(id: ClientId, signature_public_key: &[u8], backend: &MlsCryptoProvider) -> CryptoResult<Self> {
        let ciphersuite = MlsCiphersuite::default();
        let credentials: CredentialBundle = backend
            .key_store()
            .read(signature_public_key)
            .ok_or(CryptoError::ClientSignatureNotFound)?;

        Ok(Self {
            id,
            credentials,
            ciphersuite,
            package_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        })
    }

    /// Retrieves the client's client id. This is free-form and not inspected.
    pub fn id(&self) -> &ClientId {
        &self.id
    }

    /// Retrieves the client's public key
    pub fn public_key(&self) -> &[u8] {
        self.credentials.credential().signature_key().as_slice()
    }

    /// Client's `CredentialBundle` accessor
    pub fn credentials(&self) -> &CredentialBundle {
        &self.credentials
    }

    pub fn keypackage_lifetime(&mut self, duration: std::time::Duration) {
        self.package_lifetime = duration;
    }

    /// This method returns the hash of the oldest available KeyPackageBundle for the Client
    /// and if necessary regenerates a new keypackage for immediate use
    pub fn keypackage_hash(&self, backend: &MlsCryptoProvider) -> CryptoResult<Vec<u8>> {
        let kpb_result: CryptoKeystoreResult<KeyPackageBundle> = backend.key_store().mls_get_keypackage();

        match kpb_result {
            Ok(kpb) => Ok(kpb
                .key_package()
                .hash_ref(backend.crypto())
                .map(|href| href.value().to_vec())
                .map_err(MlsError::from)?),
            Err(CryptoKeystoreError::OutOfKeyPackageBundles) => {
                self.gen_keypackage(backend)?;
                Ok(self.keypackage_hash(backend)?)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Generates a single keypackage
    pub fn gen_keypackage(&self, backend: &MlsCryptoProvider) -> CryptoResult<KeyPackageBundle> {
        let kpb = KeyPackageBundle::new(
            &[*self.ciphersuite],
            &self.credentials,
            backend,
            vec![
                Extension::ExternalKeyId(ExternalKeyIdExtension::new(&self.id)),
                Extension::LifeTime(LifetimeExtension::new(self.package_lifetime.as_secs())),
            ],
        )
        .map_err(MlsError::from)?;

        let href = kpb.key_package().hash_ref(backend.crypto()).map_err(MlsError::from)?;

        backend
            .key_store()
            .store(href.value(), &kpb)
            .map_err(eyre::Report::msg)?;

        Ok(kpb)
    }

    /// Requests `count` keying material to be present and returns
    /// a reference to it for the consumer to copy/clone.
    pub fn request_keying_material(
        &self,
        count: usize,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Vec<KeyPackageBundle>> {
        // Auto-prune expired keypackages on request
        self.prune_keypackages(&[], backend)?;

        let kpb_count = backend.key_store().mls_keypackagebundle_count()?;
        if count > kpb_count {
            let to_generate = count - kpb_count;
            for _ in 0..=to_generate {
                self.gen_keypackage(backend)?;
            }
        }

        let kpbs = backend
            .key_store()
            .mls_fetch_keypackage_bundles(count as u32)?
            .map(|(kp, _)| kp)
            .collect();

        Ok(kpbs)
    }

    /// Prune the provided KeyPackageRefs from the keystore
    pub fn prune_keypackages(&self, refs: &[KeyPackageRef], backend: &MlsCryptoProvider) -> CryptoResult<()> {
        let keystore = backend.key_store();
        let crypto = backend.crypto();
        let count = keystore.mls_keypackagebundle_count()?;
        let ids: Vec<i64> = keystore
            .mls_fetch_keypackage_bundles(count as u32)?
            .filter_map(|(kp, rowid): (KeyPackageBundle, i64)| {
                kp.key_package()
                    .extensions()
                    .iter()
                    .find_map(|e| {
                        if let Extension::LifeTime(lifetime_ext) = e {
                            // ? LifetimeExtension::is_valid() is private so we have to do this very dumb thing
                            let lifetime_ext_hack = LifetimeExtensionHack::tls_deserialize(
                                &mut &lifetime_ext.tls_serialize_detached().ok()?[..],
                            )
                            .ok()?;

                            if !lifetime_ext_hack.is_valid() {
                                Some(rowid)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .or_else(|| {
                        kp.key_package()
                            .hash_ref(crypto)
                            .ok()
                            .filter(|href| refs.contains(href))
                            .map(|_| rowid)
                    })
            })
            .collect();

        keystore.mls_remove_keypackage_bundles(&ids)?;

        Ok(())
    }
}

impl PartialEq for Client {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Client {}

#[cfg(test)]
impl Client {
    pub fn random_generate(backend: &MlsCryptoProvider) -> CryptoResult<Self> {
        let user_uuid = uuid::Uuid::new_v4();
        let client_id = rand::random::<usize>();
        Self::generate(
            format!("{}:{client_id:x}@members.wire.com", user_uuid.hyphenated())
                .as_bytes()
                .into(),
            &backend,
        )
    }

    pub fn keypackages(&self, backend: &MlsCryptoProvider) -> CryptoResult<Vec<openmls::prelude::KeyPackage>> {
        let kps = backend.key_store().mls_fetch_keypackage_bundles(u32::MAX)?.try_fold(
            vec![],
            |mut acc, (kpb, _): (KeyPackageBundle, _)| -> CryptoResult<_> {
                acc.push(kpb.key_package().clone());
                Ok(acc)
            },
        )?;

        Ok(kps)
    }
}

#[cfg(test)]
mod tests {
    use mls_crypto_provider::MlsCryptoProvider;
    use openmls::prelude::KeyPackageRef;

    use super::Client;

    #[test]
    fn can_generate_client() {
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        assert!(Client::random_generate(&backend).is_ok());
    }

    #[test]
    fn client_never_runs_out_of_keypackages() {
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        let client = Client::random_generate(&backend).unwrap();
        for _ in 0..100 {
            assert!(client.keypackage_hash(&backend).is_ok())
        }
    }

    #[test]
    fn client_generates_correct_number_of_kpbs() {
        use openmls_traits::OpenMlsCryptoProvider as _;
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        let client = Client::random_generate(&backend).unwrap();

        const COUNT: usize = 124;

        let mut prev_kpbs: Option<Vec<openmls::prelude::KeyPackageBundle>> = None;
        for _ in 0..50 {
            let kpbs = client.request_keying_material(COUNT, &backend).unwrap();
            assert_eq!(kpbs.len(), COUNT);

            let kpbs_refs: Vec<KeyPackageRef> = kpbs
                .iter()
                .map(|kpb| kpb.key_package().hash_ref(backend.crypto()).unwrap())
                .collect();

            if let Some(pkpbs) = prev_kpbs.take() {
                let crypto = backend.crypto();
                let pkpbs_refs: Vec<KeyPackageRef> = pkpbs
                    .into_iter()
                    .map(|kpb| kpb.key_package().hash_ref(crypto).unwrap())
                    .collect();

                let has_duplicates = kpbs_refs.iter().any(|href| pkpbs_refs.contains(href));
                // Make sure we have no previous keypackages found (that were pruned) in our new batch of KPs
                assert!(!has_duplicates);
            }

            prev_kpbs = Some(kpbs);
            client.prune_keypackages(&kpbs_refs, &backend).unwrap();
        }
    }

    #[test]
    fn client_prunes_expired_keypackages() {
        const UNEXPIRED_COUNT: usize = 125;
        const EXPIRED_COUNT: usize = 200;
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        let mut client = Client::random_generate(&backend).unwrap();

        // Generate `UNEXPIRED_COUNT` kpbs that are with default 3 months expiration. We *should* keep them for the duration of the test
        let unexpired_kpbs = client.request_keying_material(UNEXPIRED_COUNT, &backend).unwrap();
        assert_eq!(unexpired_kpbs.len(), UNEXPIRED_COUNT);

        // Set the keypackage expiration to be immediate
        client.keypackage_lifetime(std::time::Duration::from_millis(500));

        // Generate new keypackages that are normally partially expired 0.5s after they're requested
        let partially_expired_kpbs = client.request_keying_material(EXPIRED_COUNT, &backend).unwrap();
        assert_eq!(partially_expired_kpbs.len(), EXPIRED_COUNT);

        // Sleep to trigger the expiration
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Request the same number of keypackages. The automatic lifetime-based expiration should take
        // place and remove old expired keypackages and generate fresh ones instead
        let fresh_kpbs = client.request_keying_material(EXPIRED_COUNT, &backend).unwrap();
        assert_eq!(fresh_kpbs.len(), EXPIRED_COUNT);

        // Try to deep compare and find kps matching expired and non-expired ones
        let (unexpired_match, expired_match) =
            fresh_kpbs
                .iter()
                .fold((0usize, 0usize), |(mut unexpired_match, mut expired_match), fresh| {
                    if unexpired_kpbs
                        .iter()
                        .find(|kpb| kpb.key_package() == fresh.key_package())
                        .is_some()
                    {
                        unexpired_match += 1;
                    } else if partially_expired_kpbs
                        .iter()
                        .find(|kpb| kpb.key_package() == fresh.key_package())
                        .is_some()
                    {
                        expired_match += 1;
                    }

                    (unexpired_match, expired_match)
                });

        // TADA!
        assert_eq!(unexpired_match, UNEXPIRED_COUNT);
        assert_eq!(expired_match, 0);
    }
}
