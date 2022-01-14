use mls_crypto_provider::MlsCryptoProvider;
use openmls::{
    ciphersuite::{ciphersuites::CiphersuiteName, Ciphersuite},
    credentials::CredentialBundle,
    extensions::{Extension, KeyIdExtension},
    prelude::{KeyPackage, KeyPackageBundle},
};
use openmls_traits::{key_store::OpenMlsKeyStore, OpenMlsCryptoProvider};

use crate::{CryptoResult, MlsError};

#[cfg(not(debug_assertions))]
pub type ClientId = crate::identifiers::ZeroKnowledgeUuid;
#[cfg(debug_assertions)]
pub type ClientId = crate::identifiers::QualifiedUuid;

#[derive(Debug, Clone)]
pub struct Client {
    id: ClientId,
    credentials: CredentialBundle,
    keypackage_bundles: Vec<KeyPackageBundle>,
    ciphersuite: Ciphersuite,
}

impl Client {
    pub fn generate(id: ClientId, backend: &MlsCryptoProvider) -> CryptoResult<Self> {
        let ciphersuite = Ciphersuite::new(CiphersuiteName::default()).map_err(MlsError::from)?;
        let credentials = CredentialBundle::new(
            id.as_bytes(),
            openmls::credentials::CredentialType::Basic,
            ciphersuite.signature_scheme(),
            backend,
        )
        .map_err(MlsError::from)?;

        backend
            .key_store()
            .store(credentials.credential().signature_key(), &credentials)
            .map_err(eyre::Report::msg)?;

        let mut client = Self {
            id,
            credentials,
            keypackage_bundles: vec![],
            ciphersuite,
        };

        client.gen_keypackage(backend)?;
        Ok(client)
    }

    /// This method consumes a KeyPackageBundle for the Client, hashes it and returns the hash,
    /// and if necessary regenerates a new keypackage for immediate use
    pub fn keypackage_hash(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<Vec<u8>> {
        if let Some(kpb) = self.keypackage_bundles.pop() {
            Ok(kpb.key_package().hash(backend).map_err(MlsError::from)?)
        } else {
            self.gen_keypackage(backend)?;
            self.keypackage_hash(backend)
        }
    }

    #[cfg(test)]
    pub fn random_generate(backend: &MlsCryptoProvider) -> CryptoResult<Self> {
        let uuid = uuid::Uuid::new_v4();
        Self::generate(format!("{}@clients.wire.com", uuid.to_hyphenated()).parse()?, &backend)
    }

    pub(crate) fn gen_keypackage(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<()> {
        let kpb = KeyPackageBundle::new(
            &[self.ciphersuite.name()],
            &self.credentials,
            backend,
            vec![Extension::KeyPackageId(KeyIdExtension::new(&self.id.as_bytes()))],
        )
        .map_err(MlsError::from)?;

        backend
            .key_store()
            .store(&kpb.key_package().hash(backend).map_err(MlsError::from)?, &kpb)
            .map_err(eyre::Report::msg)?;

        self.keypackage_bundles.push(kpb);
        Ok(())
    }

    pub(crate) fn keypackages(&self) -> Vec<&KeyPackage> {
        self.keypackage_bundles.iter().map(|kpb| kpb.key_package()).collect()
    }

    /// Requests additional `count` keying material and returns
    /// a reference to it for the consumer to copy/clone.
    // TODO: Re-examine this
    pub fn request_keying_material(
        &mut self,
        backend: &MlsCryptoProvider,
        count: usize,
    ) -> CryptoResult<&Vec<KeyPackageBundle>> {
        for _ in 0..count {
            self.gen_keypackage(backend)?;
        }

        Ok(&self.keypackage_bundles)
    }
}

impl PartialEq for Client {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Client {}

#[cfg(test)]
mod tests {
    use mls_crypto_provider::MlsCryptoProvider;

    use super::Client;

    #[test]
    fn can_generate_member() {
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        assert!(Client::random_generate(&backend).is_ok());
    }

    #[test]
    fn never_run_out_of_keypackages() {
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        let mut client = Client::random_generate(&backend).unwrap();
        for _ in 0..100 {
            assert!(client.keypackage_hash(&backend).is_ok())
        }
    }
}
