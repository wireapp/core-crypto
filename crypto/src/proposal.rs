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
    pub fn new_proposal(&self, conversation: ConversationId, proposal: MlsProposal) -> CryptoResult<MlsMessageOut> {
        let groups = self.mls_groups.read();
        let conversation = groups
            .get(&conversation)
            .ok_or(CryptoError::ConversationNotFound(conversation))?;
        let mut group = conversation.group.write();
        let proposal = proposal.create(&self.mls_backend, &mut group);
        proposal
    }
}

#[cfg(test)]
mod proposal_tests {
    use super::*;
    use crate::CryptoError;
    use crate::*;
    use openmls::prelude::*;

    mod add {
        use super::*;

        #[test]
        fn should_succeed() {
            let tmp_dir = tempfile::tempdir().unwrap();
            let central = MlsCentral::try_new(central_configuration(&tmp_dir)).unwrap();
            let conversation_id = b"conversation".to_vec();
            central
                .new_conversation(conversation_id.clone(), MlsConversationConfiguration::default())
                .unwrap();
            let kp = key_package(&central, MlsCiphersuite::default().0);
            let proposal = MlsProposal::Add(kp.key_package().to_owned());
            let add_proposal = central.new_proposal(conversation_id, proposal);
            assert!(add_proposal.is_ok());
        }

        #[test]
        fn should_fail_when_unknown_conversation() {
            let tmp_dir = tempfile::tempdir().unwrap();
            let central = MlsCentral::try_new(central_configuration(&tmp_dir)).unwrap();
            central.mls_groups.write().clear();
            let kp = key_package(&central, MlsCiphersuite::default().0);
            let conversation_id = b"unknown".to_vec();
            let proposal = MlsProposal::Add(kp.key_package().to_owned());
            let add_proposal = central.new_proposal(conversation_id.clone(), proposal);
            match add_proposal {
                Err(CryptoError::ConversationNotFound(conv_id)) => assert_eq!(conv_id, conversation_id),
                _ => panic!(""),
            }
        }
    }

    mod update {
        use super::*;

        #[test]
        fn should_succeed() {
            let tmp_dir = tempfile::tempdir().unwrap();
            let central = MlsCentral::try_new(central_configuration(&tmp_dir)).unwrap();
            let conversation_id = b"conversation".to_vec();
            central
                .new_conversation(conversation_id.clone(), MlsConversationConfiguration::default())
                .unwrap();
            let update_proposal = central.new_proposal(conversation_id, MlsProposal::Update);
            assert!(update_proposal.is_ok());
        }

        #[test]
        fn should_fail_when_unknown_conversation() {
            let tmp_dir = tempfile::tempdir().unwrap();
            let central = MlsCentral::try_new(central_configuration(&tmp_dir)).unwrap();
            central.mls_groups.write().clear();
            let conversation_id = b"conversation".to_vec();
            let update_proposal = central.new_proposal(conversation_id.clone(), MlsProposal::Update);
            match update_proposal {
                Err(CryptoError::ConversationNotFound(conv_id)) => assert_eq!(conv_id, conversation_id),
                _ => panic!(""),
            }
        }
    }

    mod remove {
        use super::*;

        #[test]
        fn should_succeed() {
            let tmp_dir = tempfile::tempdir().unwrap();
            let central = MlsCentral::try_new(central_configuration(&tmp_dir)).unwrap();
            let conversation_id = b"conversation".to_vec();
            central
                .new_conversation(conversation_id.clone(), MlsConversationConfiguration::default())
                .unwrap();
            let groups = central.mls_groups.read();
            let conversation = groups.get(&conversation_id[..]).unwrap();
            let group = conversation.group.read();
            let client_id = ClientId::from(group.members().get(0).unwrap().credential().identity());
            // release the lock for conversation group to be mutated in code being tested
            drop(group);
            let remove_proposal = central.new_proposal(conversation_id, MlsProposal::Remove(client_id));
            assert!(remove_proposal.is_ok());
        }

        #[test]
        fn should_fail_when_unknown_client() {
            let tmp_dir = tempfile::tempdir().unwrap();
            let central = MlsCentral::try_new(central_configuration(&tmp_dir)).unwrap();
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
        }

        #[test]
        fn should_fail_when_unknown_conversation() {
            let tmp_dir = tempfile::tempdir().unwrap();
            let central = MlsCentral::try_new(central_configuration(&tmp_dir)).unwrap();
            central.mls_groups.write().clear();
            let conversation_id = b"conversation".to_vec();
            let client_id = ClientId::from(vec![]);
            let remove_proposal = central.new_proposal(conversation_id.clone(), MlsProposal::Remove(client_id));
            match remove_proposal {
                Err(CryptoError::ConversationNotFound(conv_id)) => assert_eq!(conv_id, conversation_id),
                _ => panic!(""),
            }
        }
    }

    fn central_configuration(tmp_dir: &tempfile::TempDir) -> MlsCentralConfiguration {
        MlsCentralConfiguration::try_new(
            MlsCentralConfiguration::tmp_store_path(tmp_dir),
            "test".to_string(),
            "alice".to_string(),
        )
        .unwrap()
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
            &credential_bundle(&central, ciphersuite),
            &central.mls_backend,
            vec![],
        )
        .unwrap()
    }
}
