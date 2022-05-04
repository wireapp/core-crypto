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

use std::collections::HashMap;

use crate::{
    client::{Client, ClientId},
    CryptoResult, MlsError,
};
use openmls::prelude::KeyPackage;
use tls_codec::Deserialize;

pub type MemberId = Vec<u8>;

#[derive(Debug, Clone)]
pub struct ConversationMember {
    id: MemberId,
    clients: HashMap<ClientId, Vec<KeyPackage>>,
    #[allow(dead_code)]
    local_client: Option<Client>,
}

impl ConversationMember {
    pub fn new_raw(client_id: ClientId, kp_ser: Vec<u8>) -> CryptoResult<Self> {
        use openmls::prelude::TlsDeserializeTrait as _;
        let kp = KeyPackage::tls_deserialize(&mut &kp_ser[..]).map_err(MlsError::from)?;

        Ok(Self {
            id: client_id.to_vec(),
            clients: HashMap::from([(client_id, vec![kp])]),
            local_client: None,
        })
    }

    pub fn new(client_id: ClientId, kp: KeyPackage) -> Self {
        Self {
            id: client_id.to_vec(),
            clients: HashMap::from([(client_id, vec![kp])]),
            local_client: None,
        }
    }

    pub fn id(&self) -> &MemberId {
        &self.id
    }

    pub fn clients(&self) -> impl Iterator<Item=&ClientId> {
        self.clients.keys()
    }

    pub fn keypackages_for_all_clients(&mut self) -> HashMap<&ClientId, Option<KeyPackage>> {
        self.clients
            .iter_mut()
            .map(|(client, client_kps)| (client, client_kps.pop()))
            .collect()
    }

    pub fn add_keypackage(&mut self, kp: Vec<u8>) -> CryptoResult<()> {
        let kp = KeyPackage::tls_deserialize(&mut &kp[..]).map_err(MlsError::from)?;
        let cid = ClientId::from(kp.credential().identity());
        self.clients.entry(cid).or_insert_with(|| vec![]).push(kp);
        Ok(())
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
    pub fn random_generate(backend: &mls_crypto_provider::MlsCryptoProvider) -> CryptoResult<Self> {
        let uuid = uuid::Uuid::new_v4();
        let id = format!("{}@members.wire.com", uuid.as_hyphenated()).as_bytes().to_vec();
        let client_id: ClientId = format!("{}:{:x}@members.wire.com", uuid.hyphenated(), rand::random::<usize>())
            .as_bytes()
            .into();
        let mut client = Client::generate(client_id.clone(), backend)?;
        client.gen_keypackage(backend)?;

        let member = Self {
            id,
            clients: HashMap::from([(client_id, client.keypackages(backend)?)]),
            local_client: Some(client),
        };

        Ok(member)
    }
}

#[cfg(test)]
mod tests {
    use openmls::prelude::*;
    use crate::{prelude::INITIAL_KEYING_MATERIAL_COUNT, ClientId};
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
        let client_id = member.local_client.as_ref().map(|c| c.id().clone()).unwrap();
        for _ in 0..INITIAL_KEYING_MATERIAL_COUNT * 2 {
            let ckp = member.keypackages_for_all_clients();
            assert!(ckp[&client_id].is_some())
        }
    }

    mod add_keypackage {
        use super::*;

        #[test]
        fn add_valid_keypackage_should_add_it_to_client() {
            let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
            let mut member = ConversationMember::random_generate(&backend).unwrap();
            let cid = ClientId::from(member.id.as_slice());
            let kp = new_keypackage(&cid);
            let mut kp_raw = vec![];
            use tls_codec::Serialize as _;
            kp.tls_serialize(&mut kp_raw).unwrap();
            assert!(member.clients.get(&cid).is_none());
            assert!(member.add_keypackage(kp_raw).is_ok());
            assert!(member.clients.get(&cid).is_some());
        }

        #[test]
        fn add_invalid_keypackage_should_fail() {
            let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
            let mut member = ConversationMember::random_generate(&backend).unwrap();
            let previous_clients = member.clients.clone();
            assert!(member.add_keypackage(b"invalid-keypackage".to_vec()).is_err());
            // ensure clients are not altered in the process
            assert_eq!(member.clients, previous_clients);
        }

        fn new_keypackage(identity: &[u8]) -> KeyPackage {
            let ciphersuite = crate::MlsCiphersuite::default().0;
            let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
            let credential = CredentialBundle::new(
                identity.to_vec(),
                CredentialType::Basic,
                ciphersuite.into(),
                &backend,
            ).unwrap();
            let (kp, _) = KeyPackageBundle::new(&[ciphersuite], &credential, &backend, vec![])
                .unwrap().into_parts();
            kp
        }
    }
}
