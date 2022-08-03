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

use openmls::prelude::{KeyPackage, MlsMessageOut};
use openmls_traits::OpenMlsCryptoProvider;

use mls_crypto_provider::MlsCryptoProvider;

use crate::{ClientId, ConversationId, CryptoError, CryptoResult, MlsCentral, MlsConversation, MlsError};

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
    /// Creates a new proposal within the specified `MlsGroup`
    async fn create(
        self,
        backend: &MlsCryptoProvider,
        conversation: &mut MlsConversation,
    ) -> CryptoResult<MlsMessageOut> {
        match self {
            MlsProposal::Add(key_package) => conversation.propose_add_member(backend, &key_package).await,
            MlsProposal::Update => conversation.propose_self_update(backend).await,
            MlsProposal::Remove(client_id) => {
                let href = conversation
                    .group
                    .members()
                    .into_iter()
                    .find(|kp| kp.credential().identity() == client_id.as_slice())
                    .ok_or(CryptoError::ClientNotFound(client_id))
                    .and_then(|kp| Ok(kp.hash_ref(backend.crypto()).map_err(MlsError::from)?))?;
                conversation.propose_remove_member(backend, &href).await
            }
        }
    }
}

impl MlsCentral {
    /// Creates a new proposal within a group
    ///
    /// # Arguments
    /// * `conversation` - the group/conversation id
    /// * `proposal` - the proposal do be added in the group
    ///
    /// # Return type
    /// A message will be returned with the proposal that was created
    ///
    /// # Errors
    /// If the conversation is not found, an error will be returned. Errors from OpenMls can be
    /// returned as well, when for example there's a commit pending to be merged
    pub async fn new_proposal(
        &mut self,
        conversation: &ConversationId,
        proposal: MlsProposal,
    ) -> CryptoResult<MlsMessageOut> {
        let conversation = Self::get_conversation_mut(&mut self.mls_groups, conversation)?;
        proposal.create(&self.mls_backend, conversation).await
    }
}

#[cfg(test)]
pub mod proposal_tests {
    use wasm_bindgen_test::*;

    use crate::{credential::CredentialSupplier, prelude::handshake::MlsCommitBundle, test_utils::*, *};

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod add {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_add_member(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        let bob_kp = bob_central.get_one_key_package().await;
                        alice_central.new_proposal(&id, MlsProposal::Add(bob_kp)).await.unwrap();
                        let MlsCommitBundle { welcome, .. } =
                            alice_central.commit_pending_proposals(&id).await.unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(alice_central[&id].members().len(), 2);
                        let new_id = bob_central
                            .process_welcome_message(welcome.unwrap(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        assert_eq!(id, new_id);
                        assert!(bob_central.talk_to(&id, &mut alice_central).await.is_ok());
                    })
                },
            )
            .await
        }
    }

    pub mod update {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_update_key_package(credential: CredentialSupplier) {
            run_test_with_central(credential, |[mut central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    let before = &(*central[&id].group.members().first().unwrap()).clone();
                    central.new_proposal(&id, MlsProposal::Update).await.unwrap();
                    central.commit_pending_proposals(&id).await.unwrap();
                    central.commit_accepted(&id).await.unwrap();
                    let after = &(*central[&id].group.members().first().unwrap()).clone();
                    assert_ne!(before, after)
                })
            })
            .await
        }
    }

    pub mod remove {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_remove_member(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice", "bob"], |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    alice_central.invite(&id, &mut bob_central).await.unwrap();
                    assert_eq!(alice_central[&id].members().len(), 2);
                    assert_eq!(bob_central[&id].members().len(), 2);

                    let remove_proposal = alice_central
                        .new_proposal(&id, MlsProposal::Remove(b"bob"[..].into()))
                        .await
                        .unwrap();
                    bob_central
                        .decrypt_message(&id, remove_proposal.to_bytes().unwrap())
                        .await
                        .unwrap();
                    let MlsCommitBundle { commit, .. } = alice_central.commit_pending_proposals(&id).await.unwrap();
                    alice_central.commit_accepted(&id).await.unwrap();
                    assert_eq!(alice_central[&id].members().len(), 1);

                    bob_central
                        .decrypt_message(&id, commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    assert!(matches!(
                        bob_central.get_conversation(&id).unwrap_err(),
                        CryptoError::ConversationNotFound(conv_id) if conv_id == id
                    ));
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_unknown_client(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice"], |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();

                    let remove_proposal = alice_central
                        .new_proposal(&id, MlsProposal::Remove(b"unknown"[..].into()))
                        .await;
                    assert!(matches!(
                        remove_proposal.unwrap_err(),
                        CryptoError::ClientNotFound(client_id) if client_id == b"unknown"[..].into()
                    ));
                })
            })
            .await
        }
    }

    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn should_fail_when_unknown_conversation(credential: CredentialSupplier) {
        run_test_with_client_ids(credential, ["alice", "bob"], move |[mut alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                let bob_kp = bob_central.get_one_key_package().await;
                let add_proposal = alice_central.new_proposal(&id, MlsProposal::Add(bob_kp)).await;
                assert!(matches!(
                    add_proposal.unwrap_err(),
                    CryptoError::ConversationNotFound(conv_id) if conv_id == id
                ));
                let update_proposal = alice_central.new_proposal(&id, MlsProposal::Update).await;
                assert!(matches!(
                    update_proposal.unwrap_err(),
                    CryptoError::ConversationNotFound(conv_id) if conv_id == id
                ));
                let remove_proposal = alice_central
                    .new_proposal(&id, MlsProposal::Remove(b"any"[..].into()))
                    .await;
                assert!(matches!(
                    remove_proposal.unwrap_err(),
                    CryptoError::ConversationNotFound(conv_id) if conv_id == id
                ));
            })
        })
        .await
    }
}
