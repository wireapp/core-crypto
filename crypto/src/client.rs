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

        let mut client = Self {
            id,
            credentials,
            ciphersuite,
        };

        client.provision_keying_material(INITIAL_KEYING_MATERIAL_COUNT, backend)?;
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

    pub fn id(&self) -> &ClientId {
        &self.id
    }

    pub fn public_key(&self) -> &[u8] {
        self.credentials.credential().signature_key().as_slice()
    }

    pub fn credentials(&self) -> &CredentialBundle {
        &self.credentials
    }

    /// This method returns the hash of the oldest available KeyPackageBundle for the Client
    /// and if necessary regenerates a new keypackage for immediate use
    pub fn keypackage_hash(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<Vec<u8>> {
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

    pub fn gen_keypackage(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<KeyPackageBundle> {
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
        &mut self,
        count: usize,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Vec<KeyPackageBundle>> {
        let kpbs = self.provision_keying_material(count, backend)?;
        Ok(kpbs)
    }

    fn provision_keying_material(
        &mut self,
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

        let kpbs: Vec<KeyPackageBundle> = backend.key_store().mls_all_keypackage_bundles()?.collect();

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
        let kps = backend.key_store().mls_all_keypackage_bundles()?.try_fold(
            vec![],
            |mut acc, kpb: KeyPackageBundle| -> crate::CryptoResult<_> {
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

    use super::Client;

    #[test]
    fn can_generate_client() {
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        assert!(Client::random_generate(&backend).is_ok());
    }

    #[test]
    fn client_never_runs_out_of_keypackages() {
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        let mut client = Client::random_generate(&backend).unwrap();
        for _ in 0..100 {
            assert!(client.keypackage_hash(&backend).is_ok())
        }
    }
}
