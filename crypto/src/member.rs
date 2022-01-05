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
pub type UserId = crate::identifiers::ZeroKnowledgeUuid;
#[cfg(debug_assertions)]
pub type UserId = crate::identifiers::QualifiedUuid;

#[derive(Debug, Clone)]
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

        let mut member = Self {
            id,
            credentials,
            keypackage_bundles: vec![],
            ciphersuite,
        };

        member.gen_keypackage(backend)?;
        Ok(member)
    }

    #[cfg(test)]
    pub fn random_generate(backend: &MlsCryptoProvider) -> CryptoResult<Self> {
        let uuid = uuid::Uuid::new_v4();
        Self::generate(format!("{}@members.wire.com", uuid.to_hyphenated()).parse()?, &backend)
    }

    fn gen_keypackage(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<()> {
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

    pub fn keypackage_hash(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<Vec<u8>> {
        if let Some(kpb) = self.keypackage_bundles.pop() {
            Ok(kpb.key_package().hash(backend).map_err(MlsError::from)?)
        } else {
            self.gen_keypackage(backend)?;
            self.keypackage_hash(backend)
        }
    }

    pub fn current_keypackage(&self) -> &KeyPackage {
        self.keypackage_bundles[0].key_package()
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
    use mls_crypto_provider::MlsCryptoProvider;

    use super::ConversationMember;

    #[test]
    fn can_generate_member() {
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        assert!(ConversationMember::random_generate(&backend).is_ok());
    }

    #[test]
    fn never_run_out_of_keypackages() {
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        let mut member = ConversationMember::random_generate(&backend).unwrap();
        for _ in 0..100 {
            assert!(member.keypackage_hash(&backend).is_ok())
        }
    }
}
