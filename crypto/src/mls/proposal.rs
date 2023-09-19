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

use openmls::prelude::{hash_ref::ProposalRef, KeyPackage};

use mls_crypto_provider::MlsCryptoProvider;

use crate::{
    mls::{ClientId, ConversationId, MlsCentral, MlsConversation},
    prelude::{handshake::MlsProposalBundle, Client, CryptoError, CryptoResult},
};

/// Abstraction over a [openmls::prelude::hash_ref::ProposalRef] to deal with conversions
#[derive(Debug, Clone, Eq, PartialEq, derive_more::From, derive_more::Deref, derive_more::Display)]
pub struct MlsProposalRef(ProposalRef);

impl From<Vec<u8>> for MlsProposalRef {
    fn from(value: Vec<u8>) -> Self {
        Self(ProposalRef::from_slice(value.as_slice()))
    }
}

impl MlsProposalRef {
    /// Duh
    pub fn into_inner(self) -> ProposalRef {
        self.0
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.0.as_slice().to_vec()
    }
}

#[cfg(test)]
impl From<MlsProposalRef> for Vec<u8> {
    fn from(prop_ref: MlsProposalRef) -> Self {
        prop_ref.0.as_slice().to_vec()
    }
}

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
        client: &Client,
        backend: &MlsCryptoProvider,
        mut conversation: impl std::ops::DerefMut<Target = MlsConversation>,
    ) -> CryptoResult<MlsProposalBundle> {
        let proposal = match self {
            MlsProposal::Add(key_package) => (*conversation).propose_add_member(client, backend, key_package).await,
            MlsProposal::Update => (*conversation).propose_self_update(client, backend).await,
            MlsProposal::Remove(client_id) => {
                let index = conversation
                    .group
                    .members()
                    .find(|kp| kp.credential.identity() == client_id.as_slice())
                    .ok_or(CryptoError::ClientNotFound(client_id))
                    .map(|kp| kp.index)?;
                (*conversation).propose_remove_member(client, backend, index).await
            }
        }?;
        Ok(proposal)
    }
}

impl MlsCentral {
    /// Creates a new Add proposal
    #[cfg_attr(test, crate::idempotent)]
    pub async fn new_add_proposal(
        &mut self,
        id: &ConversationId,
        key_package: KeyPackage,
    ) -> CryptoResult<MlsProposalBundle> {
        self.new_proposal(id, MlsProposal::Add(key_package)).await
    }

    /// Creates a new Add proposal
    #[cfg_attr(test, crate::idempotent)]
    pub async fn new_remove_proposal(
        &mut self,
        id: &ConversationId,
        client_id: ClientId,
    ) -> CryptoResult<MlsProposalBundle> {
        self.new_proposal(id, MlsProposal::Remove(client_id)).await
    }

    /// Creates a new Add proposal
    #[cfg_attr(test, crate::dispotent)]
    pub async fn new_update_proposal(&mut self, id: &ConversationId) -> CryptoResult<MlsProposalBundle> {
        self.new_proposal(id, MlsProposal::Update).await
    }

    /// Creates a new proposal within a group
    ///
    /// # Arguments
    /// * `conversation` - the group/conversation id
    /// * `proposal` - the proposal do be added in the group
    ///
    /// # Return type
    /// A [MlsProposalBundle] with the proposal in a Mls message and a reference to that proposal in order to rollback it if required
    ///
    /// # Errors
    /// If the conversation is not found, an error will be returned. Errors from OpenMls can be
    /// returned as well, when for example there's a commit pending to be merged
    async fn new_proposal(&mut self, id: &ConversationId, proposal: MlsProposal) -> CryptoResult<MlsProposalBundle> {
        let conversation = self.get_conversation(id).await?;
        let client = self.mls_client()?;
        proposal
            .create(client, &self.mls_backend, conversation.write().await)
            .await
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{prelude::handshake::MlsCommitBundle, prelude::*, test_utils::*};

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod add {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_add_member(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        let bob_kp = bob_central.get_one_key_package(&case).await;
                        alice_central.new_add_proposal(&id, bob_kp).await.unwrap();
                        let MlsCommitBundle { welcome, .. } =
                            alice_central.commit_pending_proposals(&id).await.unwrap().unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);
                        let new_id = bob_central
                            .process_welcome_message(welcome.unwrap().into(), case.custom_cfg())
                            .await
                            .unwrap();
                        assert_eq!(id, new_id);
                        assert!(bob_central.try_talk_to(&id, &mut alice_central).await.is_ok());
                    })
                },
            )
            .await
        }
    }

    pub mod update {
        use super::*;
        use itertools::Itertools;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_update_hpke_key(case: TestCase) {
            run_test_with_central(case.clone(), move |[mut central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    let before = central
                        .get_conversation_unchecked(&id)
                        .await
                        .encryption_keys()
                        .find_or_first(|_| true)
                        .unwrap();
                    central.new_update_proposal(&id).await.unwrap();
                    central.commit_pending_proposals(&id).await.unwrap();
                    central.commit_accepted(&id).await.unwrap();
                    let after = central
                        .get_conversation_unchecked(&id)
                        .await
                        .encryption_keys()
                        .find_or_first(|_| true)
                        .unwrap();
                    assert_ne!(before, after)
                })
            })
            .await
        }
    }

    pub mod remove {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_remove_member(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);
                    assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 2);

                    let remove_proposal = alice_central
                        .new_remove_proposal(&id, bob_central.get_client_id())
                        .await
                        .unwrap();
                    bob_central
                        .decrypt_message(&id, remove_proposal.proposal.to_bytes().unwrap())
                        .await
                        .unwrap();
                    let MlsCommitBundle { commit, .. } =
                        alice_central.commit_pending_proposals(&id).await.unwrap().unwrap();
                    alice_central.commit_accepted(&id).await.unwrap();
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);

                    bob_central
                        .decrypt_message(&id, commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    assert!(matches!(
                        bob_central.get_conversation(&id).await.unwrap_err(),
                        CryptoError::ConversationNotFound(conv_id) if conv_id == id
                    ));
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_unknown_client(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let remove_proposal = alice_central.new_remove_proposal(&id, b"unknown"[..].into()).await;
                    assert!(matches!(
                        remove_proposal.unwrap_err(),
                        CryptoError::ClientNotFound(client_id) if client_id == b"unknown"[..].into()
                    ));
                })
            })
            .await
        }
    }
}
