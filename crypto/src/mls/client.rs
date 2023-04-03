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

use openmls::{
    credentials::CredentialBundle,
    extensions::Extension,
    prelude::{KeyPackageBundle, KeyPackageRef, LifetimeExtension, TlsSerializeTrait},
};
use openmls_traits::{
    key_store::{FromKeyStoreValue, OpenMlsKeyStore, ToKeyStoreValue},
    OpenMlsCryptoProvider,
};
use std::borrow::Cow;

use core_crypto_keystore::{
    entities::{EntityFindParams, MlsIdentity, MlsKeypackage, StringEntityId},
    CryptoKeystoreError, CryptoKeystoreResult,
};
use mls_crypto_provider::MlsCryptoProvider;

use crate::{mls::CertificateBundle, mls::MlsCiphersuite, CryptoError, CryptoResult, MlsError};

pub(crate) const INITIAL_KEYING_MATERIAL_COUNT: usize = 100;

const KEYPACKAGE_DEFAULT_LIFETIME: std::time::Duration = std::time::Duration::from_secs(60 * 60 * 24 * 90); // 3 months

/// A unique identifier for clients. A client is an identifier for each App a user is using, such as desktop,
/// mobile, etc. Users can have multiple clients.
/// More information [here](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html#name-group-members-and-clients)
#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_more::Deref)]
pub struct ClientId(pub(crate) Vec<u8>);

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

impl From<Box<[u8]>> for ClientId {
    fn from(value: Box<[u8]>) -> Self {
        Self(value.into())
    }
}

impl From<ClientId> for Box<[u8]> {
    fn from(value: ClientId) -> Self {
        value.0.into_boxed_slice()
    }
}

#[cfg(test)]
impl From<&str> for ClientId {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().into())
    }
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for ClientId {
    fn into(self) -> Vec<u8> {
        self.0
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
        Ok(Self(
            hex::decode(s).map_or_else(|_| s.as_bytes().to_vec(), std::convert::identity),
        ))
    }
}

/// Represents a MLS client which in our case is the equivalent of a device.
/// It can be the Android, iOS, web or desktop application which the authenticated user is using.
/// A user has many client, a client has only one user.
/// A client can belong to many MLS groups
#[derive(Debug, Clone)]
pub struct Client {
    id: ClientId,
    credentials: CredentialBundle,
    ciphersuite: MlsCiphersuite,
    keypackage_lifetime: std::time::Duration,
}

#[inline(always)]
pub(super) fn identity_key(credentials: &CredentialBundle) -> Result<Vec<u8>, MlsError> {
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
    ///
    /// # Arguments
    /// * `id` - id of the client
    /// * `certificate_bundle` - an optional x509 certificate
    /// * `ciphersuites` - all ciphersuites this client is supposed to support
    /// * `backend` - the KeyStore and crypto provider to read identities from
    ///
    /// # Errors
    /// KeyStore and OpenMls errors can happen
    pub async fn init(
        identity: either::Either<ClientId, CertificateBundle>,
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        use core_crypto_keystore::CryptoKeystoreMls as _;

        let id = match identity.as_ref() {
            either::Either::Left(id) => Cow::Borrowed(id),
            either::Either::Right(c) => Cow::Owned(c.get_client_id()?),
        };
        let id_str: String = id.to_string();
        let client = if let Some(signature) = backend.key_store().mls_load_identity_signature(&id_str).await? {
            match Self::load(id.as_ref(), &signature, ciphersuites, backend).await {
                Ok(client) => client,
                Err(CryptoError::ClientSignatureNotFound) => {
                    Self::generate(identity, backend, ciphersuites, true).await?
                }
                Err(e) => return Err(e),
            }
        } else {
            Self::generate(identity, backend, ciphersuites, true).await?
        };

        Ok(client)
    }

    /// Initializes a raw MLS keypair without an associated client ID
    /// Returns the raw bytes of the public key
    ///
    /// # Arguments
    /// * `ciphersuites` - all ciphersuites this client is supposed to support
    /// * `backend` - the KeyStore and crypto provider to read identities from
    ///
    /// # Errors
    /// KeyStore and OpenMls errors can happen
    pub async fn generate_raw_keypair(
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Vec<u8>> {
        let identity_count = backend.key_store().count::<MlsIdentity>().await?;
        if identity_count > 0 {
            return Err(CryptoError::IdentityAlreadyPresent);
        }

        use openmls_traits::random::OpenMlsRand as _;
        // Here we generate a provisional, random, uuid-like random Client ID for no purpose other than database/store constraints
        let provisional_client_id = backend.rand().random_vec(16)?.into();

        // TODO: support many ciphersuites
        let ciphersuite = *ciphersuites.first().ok_or(CryptoError::ImplementationError)?;
        let credentials = Self::generate_basic_credential_bundle(&provisional_client_id, ciphersuite, backend)?;

        let signature = identity_key(&credentials)?;

        let identity = MlsIdentity {
            id: provisional_client_id.to_string(),
            signature: signature.clone(),
            credential: credentials.to_key_store_value().map_err(MlsError::from)?,
        };

        backend.key_store().save(identity).await?;

        Ok(signature)
    }

    /// Finalizes initialization using a 2-step process of uploading first a public key and then associating a new Client ID to that keypair
    ///
    /// # Arguments
    /// * `client_id` - The client ID you have fetched from the MLS Authentication Service
    /// * `signature_public_key` - The client's public key. We need it to make sure
    /// * `backend` - the KeyStore and crypto provider to read identities from
    ///
    /// **WARNING**: You have absolutely NO reason to call this if you didn't call [Client::generate_raw_keypair] first. You have been warned!
    pub async fn init_with_external_client_id(
        client_id: ClientId,
        signature_public_key: &[u8],
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        // TODO: support many ciphersuites
        let ciphersuite = *ciphersuites.first().ok_or(CryptoError::ImplementationError)?;

        let keystore = backend.key_store();

        // Find all the identities, get the only one that exists (or bail), then insert the new one + delete the provisional one
        let mut store_identities: Vec<MlsIdentity> = keystore.find_all(EntityFindParams::default()).await?;

        if store_identities.len() > 1 {
            return Err(CryptoError::TooManyIdentitiesPresent);
        }

        let Some(provisional_identity) = store_identities.pop() else {
            return Err(CryptoError::NoProvisionalIdentityFound);
        };

        if signature_public_key != provisional_identity.signature {
            return Err(CryptoError::ClientSignatureMismatch);
        }

        // Now we restore the provisional credential from the store
        let provisional_credentials: CredentialBundle =
            CredentialBundle::from_key_store_value(&provisional_identity.credential).map_err(MlsError::from)?;

        // Extract what's interesting from it
        let (cred, sk) = provisional_credentials.into_parts();
        let pk = cred.signature_key().as_slice();
        let keypair =
            openmls::ciphersuite::signature::SignatureKeypair::from_bytes(sk.signature_scheme, sk.value, pk.to_vec());

        // Then rebuild a proper credential with the new client ID
        let credentials = CredentialBundle::from_parts(client_id.0.clone(), keypair);

        // Delete the old identity optimistically
        keystore
            .delete::<CredentialBundle>(provisional_identity.id.as_bytes())
            .await?;

        // And now we save the new one
        keystore
            .save(MlsIdentity {
                id: client_id.to_string(),
                signature: identity_key(&credentials)?,
                credential: credentials.to_key_store_value().map_err(MlsError::from)?,
            })
            .await?;

        Ok(Self {
            id: client_id,
            credentials,
            ciphersuite,
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        })
    }

    /// Generates a brand new client from scratch
    pub(crate) async fn generate(
        identity: either::Either<ClientId, CertificateBundle>,
        backend: &MlsCryptoProvider,
        ciphersuites: &[MlsCiphersuite],
        provision: bool,
    ) -> CryptoResult<Self> {
        // TODO: support many ciphersuites
        let ciphersuite = *ciphersuites.first().ok_or(CryptoError::ImplementationError)?;

        let (id, credentials) = match identity {
            either::Either::Left(id) => {
                let cred = Self::generate_basic_credential_bundle(&id, ciphersuite, backend)?;
                (id, cred)
            }
            either::Either::Right(cert) => (cert.get_client_id()?, Self::generate_x509_credential_bundle(cert)?),
        };

        let identity = MlsIdentity {
            id: id.to_string(),
            signature: identity_key(&credentials)?,
            credential: credentials.to_key_store_value().map_err(MlsError::from)?,
        };

        backend.key_store().save(identity).await?;

        let client = Self {
            id,
            credentials,
            ciphersuite,
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        };

        if provision {
            client
                .request_keying_material(INITIAL_KEYING_MATERIAL_COUNT, backend)
                .await?;
        }

        Ok(client)
    }

    /// Loads the client from the keystore.
    pub(crate) async fn load(
        id: &ClientId,
        signature_public_key: &[u8],
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        // TODO: support many ciphersuites
        let ciphersuite = *ciphersuites.first().ok_or(CryptoError::ImplementationError)?;

        let identity: MlsIdentity = backend
            .key_store()
            .find(id.to_string())
            .await?
            .ok_or(CryptoError::ClientSignatureNotFound)?;

        if signature_public_key != identity.signature {
            return Err(CryptoError::ClientSignatureMismatch);
        }

        let credentials: CredentialBundle =
            CredentialBundle::from_key_store_value(&identity.credential).map_err(MlsError::from)?;

        Ok(Self {
            id: identity.id.as_bytes().into(),
            credentials,
            ciphersuite,
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        })
    }

    #[allow(dead_code)]
    pub(crate) async fn load_credential_bundle(
        &self,
        signature_public_key: &[u8],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<CredentialBundle> {
        let credentials: CredentialBundle = backend
            .key_store()
            .read(signature_public_key)
            .await
            .ok_or(CryptoError::ClientSignatureNotFound)?;
        Ok(credentials)
    }

    /// Retrieves the client's client id. This is free-form and not inspected.
    pub fn id(&self) -> &ClientId {
        &self.id
    }

    /// Returns the client's public signature key from its [openmls::credentials::Credential]
    pub fn public_key(&self) -> &[u8] {
        self.credentials.credential().signature_key().as_slice()
    }

    /// Returns the client's [`CredentialBundle`] ([openmls::credentials::Credential] + private signature key)
    pub fn credentials(&self) -> &CredentialBundle {
        &self.credentials
    }

    /// Returns the Ciphersuite from the client
    pub fn ciphersuite(&self) -> &MlsCiphersuite {
        &self.ciphersuite
    }

    /// Allows to set the current default keypackage lifetime extension duration.
    /// It will be embedded in the [openmls::key_packages::KeyPackage]'s [openmls::extensions::LifetimeExtension]
    pub fn keypackage_lifetime(&mut self, duration: std::time::Duration) {
        self.keypackage_lifetime = duration;
    }

    /// This method returns the hash of the oldest available [KeyPackageBundle] as a byte array for the Client
    /// and if necessary regenerates a new keypackage for immediate use
    ///
    /// # Arguments
    /// * `backend` - the KeyStorage to load the keypackages from
    ///
    /// # Errors
    /// KeyStore errors
    pub async fn keypackage_raw_hash(&self, backend: &MlsCryptoProvider) -> CryptoResult<Vec<u8>> {
        Ok(self.keypackage_hash(backend).await?.value().to_vec())
    }

    /// This method returns the hash of the oldest available KeyPackageBundle for the Client
    /// and if necessary regenerates a new keypackage for immediate use
    ///
    /// # Arguments
    /// * `backend` - the KeyStorage to load the keypackages from
    ///
    /// # Errors
    /// KeyStore errors
    #[async_recursion::async_recursion(?Send)]
    pub async fn keypackage_hash(&self, backend: &MlsCryptoProvider) -> CryptoResult<KeyPackageRef> {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        let kpb_result: CryptoKeystoreResult<KeyPackageBundle> = backend.key_store().mls_get_keypackage().await;
        match kpb_result {
            Ok(kpb) => Ok(kpb.key_package().hash_ref(backend.crypto()).map_err(MlsError::from)?),
            Err(CryptoKeystoreError::OutOfKeyPackageBundles) => {
                self.gen_keypackage(backend).await?;
                Ok(self.keypackage_hash(backend).await?)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Generates a single new keypackage
    ///
    /// # Arguments
    /// * `backend` - the KeyStorage to load the keypackages from
    ///
    /// # Errors
    /// KeyStore and OpenMls errors
    pub async fn gen_keypackage(&self, backend: &MlsCryptoProvider) -> CryptoResult<KeyPackageBundle> {
        let kpb = KeyPackageBundle::new(
            &[*self.ciphersuite],
            &self.credentials,
            backend,
            vec![Extension::LifeTime(LifetimeExtension::new(
                self.keypackage_lifetime.as_secs(),
            ))],
        )
        .map_err(MlsError::from)?;

        let href = kpb.key_package().hash_ref(backend.crypto()).map_err(MlsError::from)?;

        backend.key_store().store(href.value(), &kpb).await?;

        Ok(kpb)
    }

    /// Requests `count` keying material to be present and returns
    /// a reference to it for the consumer to copy/clone.
    ///
    /// # Arguments
    /// * `count` - number of [openmls::key_packages::KeyPackage] to generate
    /// * `backend` - the KeyStorage to load the keypackages from
    ///
    /// # Errors
    /// KeyStore and OpenMls errors
    pub async fn request_keying_material(
        &self,
        count: usize,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Vec<KeyPackageBundle>> {
        // Auto-prune expired keypackages on request
        self.prune_keypackages(&[], backend).await?;

        use core_crypto_keystore::CryptoKeystoreMls as _;
        let kpb_count = backend.key_store().mls_keypackagebundle_count().await?;
        if count > kpb_count {
            let to_generate = count - kpb_count;
            for _ in 0..to_generate {
                self.gen_keypackage(backend).await?;
            }
        }

        let kpbs: Vec<KeyPackageBundle> = backend.key_store().mls_fetch_keypackage_bundles(count as u32).await?;

        Ok(kpbs)
    }

    /// Returns the count of valid, non-expired, unclaimed keypackages in store
    pub async fn valid_keypackages_count(&self, backend: &MlsCryptoProvider) -> CryptoResult<usize> {
        use core_crypto_keystore::entities::EntityBase as _;
        let keystore = backend.key_store();

        let mut conn = keystore.borrow_conn().await?;
        let kps = MlsKeypackage::find_all(&mut conn, EntityFindParams::default()).await?;

        let valid_count = kps.into_iter().try_fold(0usize, |mut valid_count, kp| {
            let kpb = KeyPackageBundle::from_key_store_value(&kp.key).map_err(MlsError::from)?;

            if !Self::is_mls_keypackage_expired(&kpb) {
                valid_count += 1;
            }

            CryptoResult::Ok(valid_count)
        })?;

        Ok(valid_count)
    }

    /// Checks if a given OpenMLS [`KeyPackageBundle`] is expired by looking through its extensions,
    /// finding a lifetime extension and checking if it's valid.
    fn is_mls_keypackage_expired(kpb: &KeyPackageBundle) -> bool {
        kpb.key_package()
            .extensions()
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
            let mut is_expired = Self::is_mls_keypackage_expired(&kpb);
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
}

impl PartialEq for Client {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Client {}

#[cfg(test)]
impl Client {
    pub async fn random_generate(
        case: &crate::test_utils::TestCase,
        backend: &MlsCryptoProvider,
        provision: bool,
    ) -> CryptoResult<Self> {
        let user_uuid = uuid::Uuid::new_v4();
        let rnd_id = rand::random::<usize>();
        let client_id: ClientId = format!("{}:{rnd_id:x}@members.wire.com", user_uuid.hyphenated())
            .as_bytes()
            .into();
        let identity = match case.credential_type {
            openmls::credentials::CredentialType::Basic => either::Left(client_id),
            openmls::credentials::CredentialType::X509 => {
                either::Right(CertificateBundle::rand(case.ciphersuite(), client_id))
            }
        };
        Self::generate(identity, backend, &[case.ciphersuite()], provision).await
    }

    pub async fn keypackages(&self, backend: &MlsCryptoProvider) -> CryptoResult<Vec<openmls::prelude::KeyPackage>> {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        let kps = backend
            .key_store()
            .mls_fetch_keypackage_bundles(u32::MAX)
            .await?
            .into_iter()
            .try_fold(vec![], |mut acc, kpb: KeyPackageBundle| -> CryptoResult<_> {
                acc.push(kpb.key_package().clone());
                Ok(acc)
            })?;

        Ok(kps)
    }
}

#[cfg(test)]
pub mod tests {
    use openmls::prelude::{KeyPackageBundle, KeyPackageRef};
    use wasm_bindgen_test::*;

    use mls_crypto_provider::MlsCryptoProvider;

    use crate::test_utils::*;

    use super::identity_key;
    use super::Client;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn can_assess_keypackage_expiration(case: TestCase) {
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        let mut client = Client::random_generate(&case, &backend, false).await.unwrap();

        // 90-day standard expiration
        let kp_std_exp = client.gen_keypackage(&backend).await.unwrap();
        assert!(!Client::is_mls_keypackage_expired(&kp_std_exp));

        // 1-second expiration
        client.keypackage_lifetime(std::time::Duration::from_secs(1));
        let kp_1s_exp = client.gen_keypackage(&backend).await.unwrap();
        // Sleep 2 seconds to make sure we make the kp expire
        async_std::task::sleep(std::time::Duration::from_secs(2)).await;
        assert!(Client::is_mls_keypackage_expired(&kp_1s_exp));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn can_generate_client(case: TestCase) {
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        assert!(Client::random_generate(&case, &backend, false).await.is_ok());
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn can_externally_generate_client(case: TestCase) {
        run_tests(move |[tmp_dir_argument]| {
            Box::pin(async move {
                let backend = MlsCryptoProvider::try_new(tmp_dir_argument, "test").await.unwrap();
                // phase 1: generate standalone keypair
                let keypair_sig_pk = Client::generate_raw_keypair(&[case.ciphersuite()], &backend)
                    .await
                    .unwrap();

                let mut identities: Vec<core_crypto_keystore::entities::MlsIdentity> = backend
                    .borrow_keystore()
                    .find_all(core_crypto_keystore::entities::EntityFindParams::default())
                    .await
                    .unwrap();

                assert_eq!(identities.len(), 1);

                let prov_identity = identities.pop().unwrap();

                // Make sure we are actually returning the signature public key
                assert_eq!(prov_identity.signature, keypair_sig_pk);

                // phase 2: pretend we have a new client ID from the backend, and try to init the client this way
                let client_id: super::ClientId = b"whatever:my:client:is@wire.com".to_vec().into();
                let alice = Client::init_with_external_client_id(
                    client_id.clone(),
                    &keypair_sig_pk,
                    &[case.ciphersuite()],
                    &backend,
                )
                .await
                .unwrap();

                // Make sure both client id and PK are intact
                assert_eq!(alice.id, client_id);
                assert_eq!(identity_key(alice.credentials()).unwrap(), keypair_sig_pk.as_slice());
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn client_never_runs_out_of_keypackages(case: TestCase) {
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        let client = Client::random_generate(&case, &backend, true).await.unwrap();
        for _ in 0..100 {
            assert!(client.keypackage_raw_hash(&backend).await.is_ok())
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn client_generates_correct_number_of_kpbs(case: TestCase) {
        use openmls_traits::OpenMlsCryptoProvider as _;
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        let client = Client::random_generate(&case, &backend, false).await.unwrap();

        const COUNT: usize = 124;

        let mut prev_kpbs: Option<Vec<KeyPackageBundle>> = None;
        for _ in 0..50 {
            let kpbs = client.request_keying_material(COUNT, &backend).await.unwrap();
            assert_eq!(kpbs.len(), COUNT);

            let kpbs_refs: Vec<KeyPackageRef> = kpbs
                .iter()
                .map(|kpb| kpb.key_package().hash_ref(backend.crypto()).unwrap())
                .collect();

            if let Some(pkpbs) = prev_kpbs.replace(kpbs) {
                let crypto = backend.crypto();
                let pkpbs_refs: Vec<KeyPackageRef> = pkpbs
                    .into_iter()
                    .map(|kpb| kpb.key_package().hash_ref(crypto).unwrap())
                    .collect();

                let has_duplicates = kpbs_refs.iter().any(|href| pkpbs_refs.contains(href));
                // Make sure we have no previous keypackages found (that were pruned) in our new batch of KPs
                assert!(!has_duplicates);
            }

            client.prune_keypackages(&kpbs_refs, &backend).await.unwrap();
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn client_automatically_prunes_lifetime_expired_keypackages(case: TestCase) {
        const UNEXPIRED_COUNT: usize = 125;
        const EXPIRED_COUNT: usize = 200;
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        let mut client = Client::random_generate(&case, &backend, false).await.unwrap();

        // Generate `UNEXPIRED_COUNT` kpbs that are with default 3 months expiration. We *should* keep them for the duration of the test
        let unexpired_kpbs = client.request_keying_material(UNEXPIRED_COUNT, &backend).await.unwrap();
        let len = client.valid_keypackages_count(&backend).await.unwrap();
        assert_eq!(len, unexpired_kpbs.len());
        assert_eq!(len, UNEXPIRED_COUNT);

        // Set the keypackage expiration to be in 2 seconds
        client.keypackage_lifetime(std::time::Duration::from_secs(2));

        // Generate new keypackages that are normally partially expired 2s after they're requested
        let partially_expired_kpbs = client.request_keying_material(EXPIRED_COUNT, &backend).await.unwrap();
        assert_eq!(partially_expired_kpbs.len(), EXPIRED_COUNT);

        // Sleep to trigger the expiration
        async_std::task::sleep(std::time::Duration::from_secs(5)).await;

        // Request the same number of keypackages. The automatic lifetime-based expiration should take
        // place and remove old expired keypackages and generate fresh ones instead
        let fresh_kpbs = client.request_keying_material(EXPIRED_COUNT, &backend).await.unwrap();
        let len = client.valid_keypackages_count(&backend).await.unwrap();
        assert_eq!(len, fresh_kpbs.len());
        assert_eq!(len, EXPIRED_COUNT);

        // Try to deep compare and find kps matching expired and non-expired ones
        let (unexpired_match, expired_match) =
            fresh_kpbs
                .iter()
                .fold((0usize, 0usize), |(mut unexpired_match, mut expired_match), fresh| {
                    if unexpired_kpbs
                        .iter()
                        .any(|kpb| kpb.key_package() == fresh.key_package())
                    {
                        unexpired_match += 1;
                    } else if partially_expired_kpbs
                        .iter()
                        .any(|kpb| kpb.key_package() == fresh.key_package())
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
