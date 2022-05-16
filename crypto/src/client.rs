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
use openmls::credentials::CredentialType;
use openmls::prelude::KeyPackageRef;
use openmls::{
    credentials::CredentialBundle,
    extensions::{Extension, ExternalKeyIdExtension},
    prelude::{KeyPackageBundle, TlsSerializeTrait},
};
use openmls_traits::{key_store::OpenMlsKeyStore, OpenMlsCryptoProvider};

pub(crate) const INITIAL_KEYING_MATERIAL_COUNT: usize = 100;

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
    pub fn init(id: ClientId, backend: &MlsCryptoProvider) -> CryptoResult<Self> {
        let id_str: String = id.to_string();
        let (client, generated) = if let Some(signature) = backend.key_store().mls_load_identity_signature(&id_str)? {
            match Self::load(id.clone(), &signature, backend) {
                Ok(client) => (client, false),
                Err(CryptoError::ClientSignatureNotFound) => (Self::generate(id, backend, true)?, true),
                Err(e) => return Err(e),
            }
        } else {
            (Self::generate(id, backend, true)?, true)
        };

        if generated {
            backend
                .key_store()
                .mls_save_identity_signature(&id_str, &identity_key(&client.credentials)?)?;
        }

        Ok(client)
    }

    pub(crate) fn generate(id: ClientId, backend: &MlsCryptoProvider, provision: bool) -> CryptoResult<Self> {
        let ciphersuite = MlsCiphersuite::default();
        let credentials = CredentialBundle::new(
            id.to_vec(),
            CredentialType::Basic,
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
        };

        if provision {
            client.provision_keying_material(INITIAL_KEYING_MATERIAL_COUNT, backend)?;
        }

        Ok(client)
    }

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
        })
    }

    pub(crate) fn load_credential_bundle(
        &self,
        signature_public_key: &[u8],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<CredentialBundle> {
        let credentials: CredentialBundle = backend
            .key_store()
            .read(signature_public_key)
            .ok_or(CryptoError::ClientSignatureNotFound)?;
        Ok(credentials)
    }

    pub fn id(&self) -> &ClientId {
        &self.id
    }

    pub fn public_key(&self) -> &[u8] {
        self.credentials.credential().signature_key().as_slice()
    }

    pub fn credentials(&self) -> &CredentialBundle {
        &self.credentials
    }

    pub fn ciphersuite(&self) -> &MlsCiphersuite {
        &self.ciphersuite
    }

    /// This method returns the hash of the oldest available KeyPackageBundle for the Client
    /// and if necessary regenerates a new keypackage for immediate use
    pub fn keypackage_raw_hash(&self, backend: &MlsCryptoProvider) -> CryptoResult<Vec<u8>> {
        Ok(self.keypackage_hash(backend)?.value().to_vec())
    }

    pub fn keypackage_hash(&self, backend: &MlsCryptoProvider) -> CryptoResult<KeyPackageRef> {
        let kpb_result: CryptoKeystoreResult<KeyPackageBundle> = backend.key_store().mls_get_keypackage();
        match kpb_result {
            Ok(kpb) => Ok(kpb.key_package().hash_ref(backend.crypto()).map_err(MlsError::from)?),
            Err(CryptoKeystoreError::OutOfKeyPackageBundles) => {
                self.gen_keypackage(backend)?;
                Ok(self.keypackage_hash(backend)?)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn gen_keypackage(&self, backend: &MlsCryptoProvider) -> CryptoResult<KeyPackageBundle> {
        let kpb = KeyPackageBundle::new(
            &[*self.ciphersuite],
            &self.credentials,
            backend,
            vec![Extension::ExternalKeyId(ExternalKeyIdExtension::new(&self.id))],
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
        let kpbs = self.provision_keying_material(count, backend)?;
        Ok(kpbs)
    }

    fn provision_keying_material(
        &self,
        count: usize,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Vec<KeyPackageBundle>> {
        let kpb_count = backend.key_store().mls_keypackagebundle_count()?;
        if count > kpb_count {
            let to_generate = count - kpb_count;
            for _ in 0..=to_generate {
                self.gen_keypackage(backend)?;
            }
        }

        let kpbs: Vec<KeyPackageBundle> = backend
            .key_store()
            .mls_fetch_keypackage_bundles(count as u32)?
            .collect();

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
    pub fn random_generate(backend: &MlsCryptoProvider, provision: bool) -> CryptoResult<Self> {
        let user_uuid = uuid::Uuid::new_v4();
        let client_id = rand::random::<usize>();
        Self::generate(
            format!("{}:{client_id:x}@members.wire.com", user_uuid.hyphenated())
                .as_bytes()
                .into(),
            &backend,
            provision,
        )
    }

    pub fn keypackages(&self, backend: &MlsCryptoProvider) -> CryptoResult<Vec<openmls::prelude::KeyPackage>> {
        let kps = backend.key_store().mls_fetch_keypackage_bundles(u32::MAX)?.try_fold(
            vec![],
            |mut acc, kpb: KeyPackageBundle| -> CryptoResult<_> {
                acc.push(kpb.key_package().clone());
                Ok(acc)
            },
        )?;

        Ok(kps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_generate_client() {
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        assert!(Client::random_generate(&backend, false).is_ok());
    }

    #[test]
    fn client_never_runs_out_of_keypackages() {
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        let client = Client::random_generate(&backend, true).unwrap();
        for _ in 0..100 {
            assert!(client.keypackage_raw_hash(&backend).is_ok())
        }
    }

    #[test]
    fn client_generates_correct_number_of_kpbs() {
        // use openmls_traits::OpenMlsCryptoProvider as _;
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        let client = Client::random_generate(&backend, true).unwrap();

        const COUNT: usize = 124;

        let mut _prev_kpbs: Option<Vec<openmls::prelude::KeyPackageBundle>> = None;
        for _ in 0..50 {
            let kpbs = client.request_keying_material(COUNT, &backend).unwrap();
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
