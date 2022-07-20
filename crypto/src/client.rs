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

use crate::{CertificateBundle, CryptoError, CryptoResult, MlsCiphersuite, MlsError};
use core_crypto_keystore::{entities::MlsIdentity, CryptoKeystoreError, CryptoKeystoreResult};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::KeyPackageRef;
use openmls::{
    credentials::CredentialBundle,
    extensions::{Extension, ExternalKeyIdExtension},
    prelude::{KeyPackageBundle, TlsSerializeTrait},
};
use openmls_traits::{
    key_store::{FromKeyStoreValue, OpenMlsKeyStore, ToKeyStoreValue},
    OpenMlsCryptoProvider,
};

pub(crate) const INITIAL_KEYING_MATERIAL_COUNT: usize = 100;

/// A unique identifier for clients. A client is an identifier for each App a user is using, such as desktop,
/// mobile, etc. Users can have multiple clients.
/// More information [here](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html#name-group-members-and-clients)
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

impl From<Box<[u8]>> for ClientId {
    fn from(value: Box<[u8]>) -> Self {
        Self(value.into())
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

/// Represents a client within a group
#[derive(Debug, Clone)]
pub struct Client {
    id: ClientId,
    credentials: CredentialBundle,
    ciphersuite: MlsCiphersuite,
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
    /// Initialize a new client.
    ///
    /// # Arguments
    /// * `id` - id of the client
    /// * `certificate_bundle` - an optional x509 certificate
    /// * `backend` - the KeyStore and crypto provider to read identities from
    ///
    /// # Errors
    /// KeyStore and OpenMls errors can happen
    pub async fn init(
        id: ClientId,
        certificate_bundle: Option<CertificateBundle>,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        let id_str: String = id.to_string();
        let client = if let Some(signature) = backend.key_store().mls_load_identity_signature(&id_str).await? {
            match Self::load(id.clone(), &signature, backend).await {
                Ok(client) => client,
                Err(CryptoError::ClientSignatureNotFound) => {
                    Self::generate(id, certificate_bundle, backend, true).await?
                }
                Err(e) => return Err(e),
            }
        } else {
            Self::generate(id, certificate_bundle, backend, true).await?
        };

        Ok(client)
    }

    pub(crate) async fn generate(
        id: ClientId,
        certificate_bundle: Option<CertificateBundle>,
        backend: &MlsCryptoProvider,
        provision: bool,
    ) -> CryptoResult<Self> {
        let ciphersuite = MlsCiphersuite::default();

        let credentials = if let Some(cert) = certificate_bundle {
            Self::generate_x509_credential_bundle(&id, cert.certificate_chain, cert.private_key)?
        } else {
            Self::generate_basic_credential_bundle(&id, backend)?
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
        };

        if provision {
            client
                .provision_keying_material(INITIAL_KEYING_MATERIAL_COUNT, backend)
                .await?;
        }

        Ok(client)
    }

    pub(crate) async fn load(
        id: ClientId,
        signature_public_key: &[u8],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        let ciphersuite = MlsCiphersuite::default();
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
            id,
            credentials,
            ciphersuite,
        })
    }

    /// Returns the client id
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

    /// Generates a new keypackage
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
            vec![Extension::ExternalKeyId(ExternalKeyIdExtension::new(&self.id))],
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
        let kpbs = self.provision_keying_material(count, backend).await?;
        Ok(kpbs)
    }

    async fn provision_keying_material(
        &self,
        count: usize,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Vec<KeyPackageBundle>> {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        let kpb_count = backend.key_store().mls_keypackagebundle_count().await?;
        if count > kpb_count {
            let to_generate = count - kpb_count;
            for _ in 0..=to_generate {
                self.gen_keypackage(backend).await?;
            }
        }

        let kpbs: Vec<KeyPackageBundle> = backend.key_store().mls_fetch_keypackage_bundles(count as u32).await?;

        Ok(kpbs)
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
        backend: &MlsCryptoProvider,
        provision: bool,
        certificate_bundle: Option<CertificateBundle>,
    ) -> CryptoResult<Self> {
        let user_uuid = uuid::Uuid::new_v4();
        let rnd_id = rand::random::<usize>();
        let client_id = format!("{}:{rnd_id:x}@members.wire.com", user_uuid.hyphenated())
            .as_bytes()
            .into();
        Self::generate(client_id, certificate_bundle, backend, provision).await
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
    use super::Client;
    use crate::{credential::CertificateBundle, credential::CredentialSupplier, test_fixture_utils::*};
    use mls_crypto_provider::MlsCryptoProvider;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn can_generate_client(credential: CredentialSupplier) {
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        assert!(Client::random_generate(&backend, false, credential()).await.is_ok());
    }

    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn client_never_runs_out_of_keypackages(credential: CredentialSupplier) {
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        let client = Client::random_generate(&backend, true, credential()).await.unwrap();
        for _ in 0..100 {
            assert!(client.keypackage_raw_hash(&backend).await.is_ok())
        }
    }

    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn client_generates_correct_number_of_kpbs(credential: CredentialSupplier) {
        // use openmls_traits::OpenMlsCryptoProvider as _;
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        let client = Client::random_generate(&backend, true, credential()).await.unwrap();

        const COUNT: usize = 124;

        let mut _prev_kpbs: Option<Vec<openmls::prelude::KeyPackageBundle>> = None;
        for _ in 0..50 {
            let kpbs = client.request_keying_material(COUNT, &backend).await.unwrap();
            assert_eq!(kpbs.len(), COUNT);

            // FIXME: This part of the test should be enabled after pruning is implemented.
            // if let Some(pkpbs) = prev_kpbs.take() {
            //     let crypto = backend.crypto();
            //     let pkpbs_refs = pkpbs.into_iter().map(|kpb| kpb.key_package().hash_ref(crypto).unwrap());
            //     let kpbs_refs = kpbs.iter().map(|kpb| kpb.key_package().hash_ref(crypto).unwrap());
            //     let number_same_kpbs = pkpbs_refs.zip(kpbs_refs).filter(|&(a, b)| a == b).count();
            //     assert_eq!(number_same_kpbs, 0);
            // }

            // prev_kpbs = Some(kpbs);
        }
    }
}
