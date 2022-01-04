#![allow(dead_code)]

use mls_crypto_provider::MlsCryptoProvider;
use openmls::{credentials::CredentialBundle, prelude::KeyPackageBundle, ciphersuite::{Ciphersuite, ciphersuites::CiphersuiteName}, extensions::{Extension, KeyIdExtension}};
use openmls_traits::{OpenMlsCryptoProvider, key_store::OpenMlsKeyStore};

use crate::{CryptoResult, MlsError};


#[cfg(not(debug_assertions))]
pub type UserId = ZeroKnowledgeUuid;
#[cfg(debug_assertions)]
pub type UserId = crate::identifiers::QualifiedUuid;

#[derive(Debug)]
pub struct ConversationMember {
    id: UserId,
    credentials: CredentialBundle,
    keypackage_bundles: Vec<KeyPackageBundle>,
    ciphersuite: Ciphersuite,
}

impl ConversationMember {
    pub fn new(id: UserId, credentials: CredentialBundle, kpb: KeyPackageBundle) -> CryptoResult<Self> {
        Ok(Self {
            id,
            credentials,
            keypackage_bundles: vec![kpb],
            ciphersuite: Ciphersuite::new(CiphersuiteName::default()).map_err(MlsError::from)?,
        })
    }

    pub fn generate(id: UserId, backend: &MlsCryptoProvider) -> CryptoResult<Self> {
        let ciphersuite = Ciphersuite::new(CiphersuiteName::default()).map_err(MlsError::from)?;
        let credentials = CredentialBundle::new(
            id.to_bytes(),
            openmls::credentials::CredentialType::Basic,
            ciphersuite.signature_scheme(),
            backend
        ).map_err(MlsError::from)?;

        backend
            .key_store()
            .store(credentials.credential().signature_key(), &credentials)
            .map_err(eyre::Report::msg)?;

        let mut member = Self {
            id,
            credentials,
            keypackage_bundles: vec![],
            ciphersuite,
        };

        member.gen_keypackage(backend)?;
        Ok(member)
    }

    // pub fn load(id: UserId, backend: &MlsCryptoProvider) -> CryptoResult<Self> {

    // }

    fn gen_keypackage(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<()> {
        let kpb = KeyPackageBundle::new(
            &[self.ciphersuite.name()],
            &self.credentials,
            backend,
            vec![Extension::KeyPackageId(KeyIdExtension::new(
                &self.id.to_bytes(),
            ))],
        ).map_err(MlsError::from)?;

        backend
            .key_store()
            .store(
                &kpb.key_package().hash(backend).map_err(MlsError::from)?,
                &kpb,
            ).map_err(eyre::Report::msg)?;

        self.keypackage_bundles.push(kpb);
        Ok(())
    }

    pub fn keypackage_hash(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<Vec<u8>> {
        if let Some(kpb) = self.keypackage_bundles.pop() {
            Ok(kpb.key_package().hash(backend).map_err(MlsError::from)?)
        } else {
            self.gen_keypackage(backend)?;
            self.keypackage_hash(backend)
        }
    }
}

impl PartialEq for ConversationMember {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for ConversationMember {}

#[cfg(test)]
mod tests {
    #[test]
    fn can_generate_member() {

    }
}
