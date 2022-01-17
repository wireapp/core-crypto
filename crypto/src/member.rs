use crate::{client::Client, CryptoError, CryptoResult, MlsError};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::KeyPackage;

#[cfg(not(debug_assertions))]
pub type MemberId = crate::identifiers::ZeroKnowledgeUuid;
#[cfg(debug_assertions)]
pub type MemberId = crate::identifiers::QualifiedUuid;

#[derive(Debug, Clone)]
pub struct ConversationMember {
    id: MemberId,
    keypackages: Vec<KeyPackage>,
    #[allow(dead_code)]
    client: Option<Client>,
}

impl ConversationMember {
    pub fn new(id: MemberId, kp: KeyPackage) -> CryptoResult<Self> {
        Ok(Self {
            id,
            keypackages: vec![kp],
            client: None,
        })
    }

    pub fn id(&self) -> &MemberId {
        &self.id
    }

    /// This method consumes a KeyPackageBundle for the Member, hashes it and returns the hash,
    /// and if necessary regenerates a new keypackage for immediate use
    pub fn keypackage_hash(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<Vec<u8>> {
        let kp = self
            .keypackages
            .pop()
            .ok_or_else(|| CryptoError::OutOfKeyPackage(self.id.clone()))?;

        Ok(kp.hash(backend).map_err(MlsError::from)?)
    }

    pub fn current_keypackage(&self) -> &KeyPackage {
        &self.keypackages[0]
    }
}

impl PartialEq for ConversationMember {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for ConversationMember {}

#[cfg(test)]
impl ConversationMember {
    pub fn generate(id: MemberId, backend: &MlsCryptoProvider) -> CryptoResult<Self> {
        let mut client = Client::generate(id.clone(), backend)?;
        client.gen_keypackage(backend)?;

        let member = Self {
            id,
            keypackages: client.keypackages().into_iter().cloned().collect(),
            client: Some(client),
        };

        Ok(member)
    }

    pub fn random_generate(backend: &MlsCryptoProvider) -> CryptoResult<Self> {
        let uuid = uuid::Uuid::new_v4();
        Self::generate(format!("{}@members.wire.com", uuid.to_hyphenated()).parse()?, &backend)
    }
}

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
    #[should_panic]
    fn can_run_out_of_keypackage_hashes() {
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        let mut member = ConversationMember::random_generate(&backend).unwrap();
        for _ in 0..100 {
            assert!(member.keypackage_hash(&backend).is_ok())
        }
    }
}
