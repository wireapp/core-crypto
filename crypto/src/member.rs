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

/// Type definition for the Client/Member id. It is an array of bytes
pub type MemberId = Vec<u8>;

/// Represents a member withing a group
#[derive(Debug, Clone)]
pub struct ConversationMember {
    id: MemberId,
    clients: HashMap<ClientId, Vec<KeyPackage>>,
    #[allow(dead_code)]
    local_client: Option<Client>,
}

impl ConversationMember {
    /// Creates a new member from a TLS-serialized keypackage
    ///
    /// # Errors
    /// Deserialization errors
    pub fn new_raw(client_id: ClientId, kp_ser: Vec<u8>) -> CryptoResult<Self> {
        use openmls::prelude::TlsDeserializeTrait as _;
        let kp = KeyPackage::tls_deserialize(&mut &kp_ser[..]).map_err(MlsError::from)?;

        Ok(Self {
            id: client_id.to_vec(),
            clients: HashMap::from([(client_id, vec![kp])]),
            local_client: None,
        })
    }

    /// Creates a new member from a keypackage and client id
    pub fn new(client_id: ClientId, kp: KeyPackage) -> Self {
        Self {
            id: client_id.to_vec(),
            clients: HashMap::from([(client_id, vec![kp])]),
            local_client: None,
        }
    }

    /// Returns a reference to the Client/Member id
    pub fn id(&self) -> &MemberId {
        &self.id
    }

    /// Returns an `Iterator` from the clients ids
    pub fn clients(&self) -> impl Iterator<Item = &ClientId> {
        self.clients.keys()
    }

    /// Returns the KeyPackages from all clients, poping the last added KeyPackage from each client
    /// from the local state as a result
    pub fn keypackages_for_all_clients(&mut self) -> HashMap<&ClientId, Option<KeyPackage>> {
        self.clients
            .iter_mut()
            .map(|(client, client_kps)| (client, client_kps.pop()))
            .collect()
    }

    /// Adds a new `KeyPackage` to the internal state.
    ///
    /// # Arguments
    /// * `kp` - `KeyPackage` to be added. It expects a TLS serialized byte array
    ///
    /// # Errors
    /// Deserialization errors
    pub fn add_keypackage(&mut self, kp: Vec<u8>) -> CryptoResult<()> {
        let kp = KeyPackage::tls_deserialize(&mut &kp[..]).map_err(MlsError::from)?;
        let cid = ClientId::from(kp.credential().identity());
        self.clients.entry(cid).or_insert_with(Vec::new).push(kp);
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
    /// Generates a random new Member
    pub async fn random_generate(
        backend: &mls_crypto_provider::MlsCryptoProvider,
        credential: crate::credential::CredentialSupplier,
    ) -> CryptoResult<Self> {
        let client = Client::random_generate(backend, false, credential()).await?;
        let id = client.id();
        client.gen_keypackage(backend).await?;

        let member = Self {
            id: id.to_vec(),
            clients: HashMap::from([(id.clone(), client.keypackages(backend).await?)]),
            local_client: Some(client),
        };

        Ok(member)
    }

    /// Generates a random new Member
    pub fn random_generate_clientless() -> CryptoResult<Self> {
        let user_uuid = uuid::Uuid::new_v4();
        let client_id = rand::random::<usize>();
        let client_id = format!("{}:{client_id:x}@members.wire.com", user_uuid.hyphenated());
        Ok(Self {
            id: client_id.as_bytes().into(),
            clients: HashMap::new(),
            local_client: None,
        })
    }

    /// Returns a reference for the internal local client
    pub fn local_client(&self) -> &Client {
        self.local_client.as_ref().unwrap()
    }

    /// Returns a mutable reference for the internal local client
    pub fn local_client_mut(&mut self) -> &mut Client {
        self.local_client.as_mut().unwrap()
    }
}

#[cfg(test)]
pub mod tests {
    use super::ConversationMember;
    use crate::{
        credential::{CertificateBundle, CredentialSupplier},
        prelude::INITIAL_KEYING_MATERIAL_COUNT,
        test_fixture_utils::*,
        ClientId,
    };
    use mls_crypto_provider::MlsCryptoProvider;
    use openmls::prelude::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn can_generate_member(credential: CredentialSupplier) {
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        assert!(ConversationMember::random_generate(&backend, credential).await.is_ok());
    }

    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn member_can_run_out_of_keypackage_hashes(credential: CredentialSupplier) {
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        let mut member = ConversationMember::random_generate(&backend, credential).await.unwrap();
        let client_id = member.local_client.as_ref().map(|c| c.id().clone()).unwrap();
        let ret = (0..INITIAL_KEYING_MATERIAL_COUNT * 2).all(|_| {
            let ckp = member.keypackages_for_all_clients();
            ckp[&client_id].is_some()
        });

        assert!(!ret);
    }

    pub mod add_keypackage {
        use super::*;
        use crate::Client;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn add_valid_keypackage_should_add_it_to_client(credential: CredentialSupplier) {
            let mut member = ConversationMember::random_generate_clientless().unwrap();
            let cid = ClientId::from(member.id.as_slice());
            let kp = new_keypackage(&cid, credential()).await;
            let mut kp_raw = vec![];
            use tls_codec::Serialize as _;
            kp.tls_serialize(&mut kp_raw).unwrap();
            assert!(member.clients.get(&cid).is_none());
            assert!(member.add_keypackage(kp_raw).is_ok());
            assert!(member.clients.get(&cid).is_some());
        }

        #[test]
        #[wasm_bindgen_test]
        pub fn add_invalid_keypackage_should_fail() {
            let mut member = ConversationMember::random_generate_clientless().unwrap();
            let previous_clients = member.clients.clone();
            assert!(member.add_keypackage(b"invalid-keypackage".to_vec()).is_err());
            // ensure clients are not altered in the process
            assert_eq!(member.clients, previous_clients);
        }

        async fn new_keypackage(identity: &[u8], credential: Option<CertificateBundle>) -> KeyPackage {
            let ciphersuite = crate::MlsCiphersuite::default().0;
            let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
            let credential = if let Some(cert) = credential {
                Client::generate_x509_credential_bundle(&identity.into(), cert.certificate_chain, cert.private_key)
            } else {
                Client::generate_basic_credential_bundle(&identity.into(), &backend)
            }
            .unwrap();
            let (kp, _) = KeyPackageBundle::new(&[ciphersuite], &credential, &backend, vec![])
                .unwrap()
                .into_parts();
            kp
        }
    }
}
