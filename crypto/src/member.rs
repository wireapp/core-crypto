use crate::{
    client::{Client, ClientId},
    CryptoError, CryptoResult, MlsError,
};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::KeyPackage;
use openmls_traits::OpenMlsCryptoProvider;

// #[cfg(not(debug_assertions))]
// pub type MemberId = crate::identifiers::ZeroKnowledgeUuid;
// #[cfg(debug_assertions)]
pub type MemberId = crate::identifiers::QualifiedUuid;

#[derive(Debug, Clone)]
pub struct ConversationMember {
    id: MemberId,
    client_ids: Vec<ClientId>,
    keypackages: Vec<KeyPackage>,
    #[allow(dead_code)]
    client: Option<Client>,
}

impl ConversationMember {
    pub fn new_raw(client_id: ClientId, kp_ser: Vec<u8>) -> CryptoResult<Self> {
        use openmls::prelude::TlsDeserializeTrait as _;
        let kp = KeyPackage::tls_deserialize(&mut &kp_ser[..]).map_err(|e| MlsError::MlsKeyPackageError(e.into()))?;

        Ok(Self {
            id: client_id.clone().into(),
            client_ids: vec![client_id],
            keypackages: vec![kp],
            client: None,
        })
    }

    pub fn new(client_id: ClientId, kp: KeyPackage) -> Self {
        Self {
            id: client_id.clone().into(),
            client_ids: vec![client_id],
            keypackages: vec![kp],
            client: None,
        }
    }

    pub fn id(&self) -> &MemberId {
        &self.id
    }

    pub fn clients(&self) -> &[ClientId] {
        self.client_ids.as_slice()
    }

    /// This method consumes a KeyPackageBundle for the Member, hashes it and returns the hash,
    /// and if necessary regenerates a new keypackage for immediate use
    pub fn keypackage_hash(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<Vec<u8>> {
        let kp = self
            .keypackages
            .pop()
            .ok_or_else(|| CryptoError::OutOfKeyPackage(self.id.clone()))?;

        Ok(kp
            .hash_ref(backend.crypto())
            .map(|href| href.value().to_vec())
            .map_err(MlsError::from)?)
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
    pub fn random_generate(backend: &MlsCryptoProvider) -> CryptoResult<Self> {
        let uuid = uuid::Uuid::new_v4();
        let id: ClientId = format!("{}:{}@members.wire.com", uuid.hyphenated(), rand::random::<usize>()).parse()?;
        let mut client = Client::generate(id.clone(), backend)?;
        client.gen_keypackage(backend)?;

        let member = Self {
            id: id.clone().into(),
            client_ids: vec![id],
            keypackages: client.keypackages().into_iter().cloned().collect(),
            client: Some(client),
        };

        Ok(member)
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::INITIAL_KEYING_MATERIAL_COUNT;
    use mls_crypto_provider::MlsCryptoProvider;

    use super::ConversationMember;

    #[test]
    fn can_generate_member() {
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        assert!(ConversationMember::random_generate(&backend).is_ok());
    }

    #[test]
    #[should_panic]
    fn member_can_run_out_of_keypackage_hashes() {
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        let mut member = ConversationMember::random_generate(&backend).unwrap();
        for _ in 0..INITIAL_KEYING_MATERIAL_COUNT * 2 {
            assert!(member.keypackage_hash(&backend).is_ok())
        }
    }
}
