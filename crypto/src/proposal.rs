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

use crate::{ClientId, ConversationId, CryptoError, CryptoResult, MlsCentral, MlsError};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::{KeyPackage, MlsGroup, MlsMessageOut};
use openmls_traits::OpenMlsCryptoProvider;

/// Internal representation of proposal to ease further additions
pub enum MlsProposal {
    /// Requests that a client with a specified KeyPackage be added to the group
    Add(KeyPackage),
    /// Similar mechanism to Add with the distinction that it replaces
    /// the sender's LeafNode in the tree instead of adding a new leaf to the tree
    Update,
    /// Requests that the member with LeafNodeRef removed be removed from the group
    Remove(ClientId),
}

impl MlsProposal {
    fn create(self, backend: &MlsCryptoProvider, group: &mut MlsGroup) -> CryptoResult<MlsMessageOut> {
        match self {
            MlsProposal::Add(key_package) => group
                .propose_add_member(backend, &key_package)
                .map_err(MlsError::from)
                .map_err(CryptoError::from),
            MlsProposal::Update => group
                .propose_self_update(backend, None)
                .map_err(MlsError::from)
                .map_err(CryptoError::from),
            MlsProposal::Remove(client_id) => group
                .members()
                .into_iter()
                .find(|kp| kp.credential().identity() == client_id.as_slice())
                .ok_or(CryptoError::ClientNotFound(client_id))
                .and_then(|kp| {
                    kp.hash_ref(backend.crypto())
                        .map_err(MlsError::from)
                        .map_err(CryptoError::from)
                })
                .and_then(|kpr| {
                    group
                        .propose_remove_member(backend, &kpr)
                        .map_err(MlsError::from)
                        .map_err(CryptoError::from)
                }),
        }
    }
}

impl MlsCentral {
    /// Generic proposal factory
    pub fn new_proposal(&mut self, conversation: ConversationId, proposal: MlsProposal) -> CryptoResult<MlsMessageOut> {
        let conversation = self
            .mls_groups
            .get_mut(&conversation)
            .ok_or(CryptoError::ConversationNotFound(conversation))?;
        let group = &mut conversation.group;

        proposal.create(&self.mls_backend, group)
    }
}

#[cfg(test)]
pub mod proposal_tests {
    use super::*;
    use crate::{
        credential::{CertificateBundle, CredentialSupplier},
        test_fixture_utils::*,
        test_utils::run_test_with_central,
        CryptoError, *,
    };
    use openmls::prelude::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    pub mod add {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub fn should_succeed(credential: CredentialSupplier) {
            run_test_with_central(credential, |mut central| {
                let conversation_id = b"conversation".to_vec();
                central
                    .new_conversation(conversation_id.clone(), MlsConversationConfiguration::default())
                    .unwrap();
                let kp = key_package(&central, credential);
                let proposal = MlsProposal::Add(kp.key_package().to_owned());
                let add_proposal = central.new_proposal(conversation_id, proposal);
                let _ = add_proposal.unwrap();
            })
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub fn should_fail_when_unknown_conversation(credential: CredentialSupplier) {
            run_test_with_central(credential, |mut central| {
                central.mls_groups.clear();
                let kp = key_package(&central, credential);
                let conversation_id = b"unknown".to_vec();
                let proposal = MlsProposal::Add(kp.key_package().to_owned());
                let add_proposal = central.new_proposal(conversation_id.clone(), proposal);
                match add_proposal {
                    Err(CryptoError::ConversationNotFound(conv_id)) => assert_eq!(conv_id, conversation_id),
                    _ => panic!(""),
                }
            })
        }
    }

    pub mod update {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub fn should_succeed(credential: CredentialSupplier) {
            run_test_with_central(credential, |mut central| {
                let conversation_id = b"conversation".to_vec();
                central
                    .new_conversation(conversation_id.clone(), MlsConversationConfiguration::default())
                    .unwrap();
                let update_proposal = central.new_proposal(conversation_id, MlsProposal::Update);
                let _ = update_proposal.unwrap();
            })
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub fn should_fail_when_unknown_conversation(credential: CredentialSupplier) {
            run_test_with_central(credential, |mut central| {
                central.mls_groups.clear();
                let conversation_id = b"conversation".to_vec();
                let update_proposal = central.new_proposal(conversation_id.clone(), MlsProposal::Update);
                match update_proposal {
                    Err(CryptoError::ConversationNotFound(conv_id)) => assert_eq!(conv_id, conversation_id),
                    _ => panic!(""),
                }
            })
        }
    }

    pub mod remove {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub fn should_succeed(credential: CredentialSupplier) {
            run_test_with_central(credential, |mut central| {
                let conversation_id = b"conversation".to_vec();
                central
                    .new_conversation(conversation_id.clone(), MlsConversationConfiguration::default())
                    .unwrap();
                let conversation = central.mls_groups.get(&conversation_id[..]).unwrap();
                let client_id = ClientId::from(conversation.group.members().get(0).unwrap().credential().identity());
                let remove_proposal = central.new_proposal(conversation_id, MlsProposal::Remove(client_id));
                let _ = remove_proposal.unwrap();
            })
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub fn should_fail_when_unknown_client(credential: CredentialSupplier) {
            run_test_with_central(credential, |mut central| {
                let conversation_id = b"conversation".to_vec();
                central
                    .new_conversation(conversation_id.clone(), MlsConversationConfiguration::default())
                    .unwrap();
                let client_id = ClientId::from(vec![]);
                let remove_proposal = central.new_proposal(conversation_id, MlsProposal::Remove(client_id.clone()));
                match remove_proposal {
                    Err(CryptoError::ClientNotFound(cli_id)) => assert_eq!(cli_id, client_id),
                    _ => panic!(""),
                }
            })
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub fn should_fail_when_unknown_conversation(credential: CredentialSupplier) {
            run_test_with_central(credential, |mut central| {
                central.mls_groups.clear();
                let conversation_id = b"conversation".to_vec();
                let client_id = ClientId::from(vec![]);
                let remove_proposal = central.new_proposal(conversation_id.clone(), MlsProposal::Remove(client_id));
                match remove_proposal {
                    Err(CryptoError::ConversationNotFound(conv_id)) => assert_eq!(conv_id, conversation_id),
                    _ => panic!(""),
                }
            })
        }
    }

    fn key_package(central: &MlsCentral, credential: CredentialSupplier) -> KeyPackageBundle {
        let id = b"test";
        let credential = if let Some(cert) = credential() {
            Client::generate_x509_credential_bundle(&id.to_vec().into(), cert.certificate_chain, cert.private_key)
        } else {
            Client::generate_basic_credential_bundle(&id.to_vec().into(), &central.mls_backend)
        }
        .unwrap();
        KeyPackageBundle::new(
            &[MlsCiphersuite::default().0],
            &credential,
            &central.mls_backend,
            vec![],
        )
        .unwrap()
    }
}
