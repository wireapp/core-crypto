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

use openmls::prelude::KeyPackage;
use tls_codec::Deserialize;

use crate::{
    mls::client::{Client, ClientId},
    CryptoResult, MlsError,
};

/// Type definition for the identifier of a client in a conversation (aka Member)
pub type MemberId = Vec<u8>;

/// Represents a client withing a group
#[derive(Debug, Clone)]
pub struct ConversationMember {
    pub(crate) id: MemberId,
    pub(crate) clients: HashMap<ClientId, Vec<KeyPackage>>,
    #[allow(dead_code)]
    pub(crate) local_client: Option<Client>,
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
        case: &crate::test_utils::TestCase,
        backend: &mls_crypto_provider::MlsCryptoProvider,
    ) -> CryptoResult<(Self, openmls::prelude::KeyPackageBundle)> {
        let client = Client::random_generate(case, backend, false).await?;
        let id = client.id();
        let key_package = client.gen_keypackage(backend).await?;

        let member = Self {
            id: id.to_vec(),
            clients: HashMap::from([(id.clone(), client.keypackages(backend).await?)]),
            local_client: Some(client),
        };

        Ok((member, key_package))
    }

    /// Generates a random new Member
    pub fn random_generate_clientless(
        case: &crate::test_utils::TestCase,
        backend: &mls_crypto_provider::MlsCryptoProvider,
    ) -> CryptoResult<(Self, openmls::prelude::CredentialBundle)> {
        let (credential, client_id) = match case.credential_type {
            openmls::prelude::CredentialType::Basic => {
                let user_uuid = uuid::Uuid::new_v4();
                let client_id = rand::random::<usize>();
                let client_id = format!("{}:{client_id:x}@members.wire.com", user_uuid.hyphenated());
                let client_id = client_id.as_bytes().into();
                let credential =
                    Client::generate_basic_credential_bundle(&client_id, case.ciphersuite(), backend).unwrap();
                (credential, client_id)
            }
            openmls::prelude::CredentialType::X509 => {
                let cert = crate::prelude::CertificateBundle::rand(case.ciphersuite(), "alice".into());
                let client_id = cert.get_client_id().unwrap();
                (Client::generate_x509_credential_bundle(cert).unwrap(), client_id)
            }
        };

        let member = Self {
            id: client_id.into(),
            clients: HashMap::new(),
            local_client: None,
        };
        Ok((member, credential))
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
    use openmls::prelude::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    use mls_crypto_provider::MlsCryptoProvider;

    use crate::{mls::ClientId, prelude::INITIAL_KEYING_MATERIAL_COUNT, test_utils::*};

    use super::ConversationMember;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn can_generate_member(case: TestCase) {
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        assert!(ConversationMember::random_generate(&case, &backend).await.is_ok());
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn member_can_run_out_of_keypackage_hashes(case: TestCase) {
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        let (mut member, _) = ConversationMember::random_generate(&case, &backend).await.unwrap();
        let client_id = member.local_client.as_ref().map(|c| c.id().clone()).unwrap();
        let ret = (0..INITIAL_KEYING_MATERIAL_COUNT * 2).all(|_| {
            let ckp = member.keypackages_for_all_clients();
            ckp[&client_id].is_some()
        });

        assert!(!ret);
    }

    pub mod add_keypackage {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn add_valid_keypackage_should_add_it_to_client(case: TestCase) {
            let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
            let (mut member, credential) = ConversationMember::random_generate_clientless(&case, &backend).unwrap();
            let cid = ClientId::from(member.id.as_slice());

            let (kp, _) = KeyPackageBundle::new(&[case.ciphersuite().0], &credential, &backend, vec![])
                .unwrap()
                .into_parts();

            let mut kp_raw = vec![];
            use tls_codec::Serialize as _;
            kp.tls_serialize(&mut kp_raw).unwrap();
            assert!(member.clients.get(&cid).is_none());
            assert!(member.add_keypackage(kp_raw).is_ok());
            assert!(member.clients.get(&cid).is_some());
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn add_invalid_keypackage_should_fail(case: TestCase) {
            let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
            let (mut member, _) = ConversationMember::random_generate_clientless(&case, &backend).unwrap();
            let previous_clients = member.clients.clone();
            assert!(member.add_keypackage(b"invalid-keypackage".to_vec()).is_err());
            // ensure clients are not altered in the process
            assert_eq!(member.clients, previous_clients);
        }
    }
}
