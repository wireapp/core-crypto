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

    /// Creates and commits an update key package
    pub fn propose_self_update(&mut self, conversation: ConversationId) -> CryptoResult<MlsMessageOut> {
        let conversation = self
            .mls_groups
            .get_mut(&conversation)
            .ok_or(CryptoError::ConversationNotFound(conversation))?;
        conversation
            .group
            .propose_self_update(&self.mls_backend, None)
            .map_err(MlsError::from)
            .map_err(CryptoError::from)
    }
}

#[cfg(test)]
pub mod proposal_tests {
    use super::*;
    use crate::test_utils::run_test_with_central;
    use crate::CryptoError;
    use crate::*;
    use openmls::prelude::*;
    use wasm_bindgen_test::wasm_bindgen_test;
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    pub mod add {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        pub fn should_succeed() {
            run_test_with_central(|mut central| {
                let conversation_id = b"conversation".to_vec();
                central
                    .new_conversation(conversation_id.clone(), MlsConversationConfiguration::default())
                    .unwrap();
                let kp = key_package(&central, MlsCiphersuite::default().0);
                let proposal = MlsProposal::Add(kp.key_package().to_owned());
                let add_proposal = central.new_proposal(conversation_id, proposal);
                let _ = add_proposal.unwrap();
            })
        }

        #[test]
        #[wasm_bindgen_test]
        pub fn should_fail_when_unknown_conversation() {
            run_test_with_central(|mut central| {
                central.mls_groups.clear();
                let kp = key_package(&central, MlsCiphersuite::default().0);
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

        #[test]
        #[wasm_bindgen_test]
        pub fn should_succeed() {
            run_test_with_central(|mut central| {
                let conversation_id = b"conversation".to_vec();
                central
                    .new_conversation(conversation_id.clone(), MlsConversationConfiguration::default())
                    .unwrap();
                let update_proposal = central.new_proposal(conversation_id, MlsProposal::Update);
                let _ = update_proposal.unwrap();
            })
        }

        #[test]
        #[wasm_bindgen_test]
        pub fn should_fail_when_unknown_conversation() {
            run_test_with_central(|mut central| {
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

        #[test]
        #[wasm_bindgen_test]
        pub fn should_succeed() {
            run_test_with_central(|mut central| {
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

        #[test]
        #[wasm_bindgen_test]
        pub fn should_fail_when_unknown_client() {
            run_test_with_central(|mut central| {
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

        #[test]
        #[wasm_bindgen_test]
        pub fn should_fail_when_unknown_conversation() {
            run_test_with_central(|mut central| {
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

    mod propose_self_update {
        use mls_crypto_provider::MlsCryptoProvider;
        use openmls::prelude::KeyPackage;
        use wasm_bindgen_test::wasm_bindgen_test;

        use crate::{
            member::ConversationMember,
            prelude::{MlsConversation, MlsConversationConfiguration, MlsConversationCreationMessage},
            test_utils::run_test_with_central,
        };

        // if theres a pending proposal to be commited (Charles) the welcome message should
        // contain the welcome message from Charles
        // create charles group and should be able to decrypt the welcome message and send messages
        // to the group

        // create a group with alice and bob
        // when perform update on alice, bob has to be updated, so check key package from bob
        #[test]
        #[wasm_bindgen_test]
        pub fn should_propose_self_update_conversation_group() {
            run_test_with_central(|mut alice| {
                // create bob
                alice.mls_groups.clear();
                let conversation_id = b"conversation".to_vec();
                let (bob_backend, bob) = person("bob");
                let bob_key = bob.local_client().keypackages(&bob_backend).unwrap()[0].clone();

                let conversation_config = MlsConversationConfiguration::default();

                // create new group and add bob
                alice
                    .new_conversation(conversation_id.clone(), conversation_config)
                    .unwrap();

                let add_message = alice
                    .add_members_to_conversation(&conversation_id, &mut [bob])
                    .unwrap()
                    .unwrap();

                assert_eq!(alice.mls_groups[&conversation_id].members().unwrap().len(), 2);

                let MlsConversationCreationMessage { welcome, .. } = add_message;

                let conversation_config = MlsConversationConfiguration::default();

                // creating group on bob's side
                let mut bob_group =
                    MlsConversation::from_welcome_message(welcome, conversation_config, &bob_backend).unwrap();

                assert_eq!(bob_group.id(), alice.mls_groups[&conversation_id].id());

                // ensuring both sides can encrypt messages
                let msg = b"Hello";
                let alice_can_send_message = alice.encrypt_message(conversation_id.clone(), msg);
                assert!(alice_can_send_message.is_ok());
                let bob_can_send_message = bob_group.encrypt_message(msg, &bob_backend);
                assert!(bob_can_send_message.is_ok());

                let bob_keys = bob_group
                    .group
                    .members()
                    .into_iter()
                    .cloned()
                    .collect::<Vec<KeyPackage>>();

                let alice_keys = alice
                    .mls_groups
                    .get(&conversation_id)
                    .unwrap()
                    .group
                    .members()
                    .into_iter()
                    .cloned()
                    .collect::<Vec<KeyPackage>>();

                assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

                let alice_key = alice_keys.into_iter().find(|k| *k != bob_key).unwrap();

                // proposing the key update for alice
                let msg_out = alice.propose_self_update(conversation_id.clone()).unwrap();

                // receiving the proposal on bob's side
                assert!(bob_group
                    .decrypt_message(&msg_out.to_bytes().unwrap(), &bob_backend)
                    .unwrap()
                    .is_none());

                // commiting the proposal and merging the commit
                let (msg_out, _) = alice
                    .mls_groups
                    .get_mut(&conversation_id)
                    .unwrap()
                    .group
                    .commit_to_pending_proposals(&alice.mls_backend)
                    .unwrap();

                alice
                    .mls_groups
                    .get_mut(&conversation_id)
                    .unwrap()
                    .group
                    .merge_pending_commit()
                    .unwrap();

                let alice_new_keys = alice
                    .mls_groups
                    .get(&conversation_id)
                    .unwrap()
                    .group
                    .members()
                    .into_iter()
                    .cloned()
                    .collect::<Vec<KeyPackage>>();

                assert!(!alice_new_keys.contains(&alice_key));

                // receiving the commit on bob's side (updating key from alice)
                assert!(bob_group
                    .decrypt_message(&msg_out.to_bytes().unwrap(), &bob_backend)
                    .unwrap()
                    .is_none());

                let bob_new_keys = bob_group
                    .group
                    .members()
                    .into_iter()
                    .cloned()
                    .collect::<Vec<KeyPackage>>();

                assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

                // ensuring both can encrypt messages
                let bob_can_send_message = bob_group.encrypt_message(msg, &bob_backend);
                assert!(bob_can_send_message.is_ok());

                let alice_can_send_message = alice.encrypt_message(conversation_id.clone(), msg);
                assert!(alice_can_send_message.is_ok());
            })
        }

        fn person(name: &str) -> (MlsCryptoProvider, ConversationMember) {
            let backend = MlsCryptoProvider::try_new_in_memory(name).unwrap();
            let member = ConversationMember::random_generate(&backend).unwrap();
            (backend, member)
        }
    }

    fn credential_bundle(central: &MlsCentral, ciphersuite: Ciphersuite) -> CredentialBundle {
        CredentialBundle::new(
            b"test".to_vec(),
            CredentialType::Basic,
            SignatureScheme::from(ciphersuite),
            &central.mls_backend,
        )
        .unwrap()
    }

    fn key_package(central: &MlsCentral, ciphersuite: Ciphersuite) -> KeyPackageBundle {
        KeyPackageBundle::new(
            &[ciphersuite],
            &credential_bundle(central, ciphersuite),
            &central.mls_backend,
            vec![],
        )
        .unwrap()
    }
}
