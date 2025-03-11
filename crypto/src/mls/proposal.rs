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

use openmls::prelude::{KeyPackage, hash_ref::ProposalRef};

use mls_crypto_provider::MlsCryptoProvider;

use super::{Error, Result};
use crate::{
    RecursiveError,
    mls::{ClientId, ConversationId, MlsConversation},
    prelude::{Client, MlsProposalBundle},
};

use crate::context::CentralContext;

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
// To solve the clippy issue we'd need to box the `KeyPackage`, but we can't because we need an
// owned value of it. We can have it when Box::into_inner is stablized.
// https://github.com/rust-lang/rust/issues/80437
#[allow(clippy::large_enum_variant)]
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
    ) -> Result<MlsProposalBundle> {
        let proposal = match self {
            MlsProposal::Add(key_package) => (*conversation)
                .propose_add_member(client, backend, key_package.into())
                .await
                .map_err(RecursiveError::mls_conversation("proposing to add member"))?,
            MlsProposal::Update => (*conversation)
                .propose_self_update(client, backend)
                .await
                .map_err(RecursiveError::mls_conversation("proposing self update"))?,
            MlsProposal::Remove(client_id) => {
                let index = conversation
                    .group
                    .members()
                    .find(|kp| kp.credential.identity() == client_id.as_slice())
                    .ok_or(Error::ClientNotFound(client_id))
                    .map(|kp| kp.index)?;
                (*conversation)
                    .propose_remove_member(client, backend, index)
                    .await
                    .map_err(RecursiveError::mls_conversation("proposing to remove member"))?
            }
        };
        Ok(proposal)
    }
}

impl CentralContext {
    /// Creates a new Add proposal
    #[cfg_attr(test, crate::idempotent)]
    pub async fn new_add_proposal(&self, id: &ConversationId, key_package: KeyPackage) -> Result<MlsProposalBundle> {
        self.new_proposal(id, MlsProposal::Add(key_package)).await
    }

    /// Creates a new Add proposal
    #[cfg_attr(test, crate::idempotent)]
    pub async fn new_remove_proposal(&self, id: &ConversationId, client_id: ClientId) -> Result<MlsProposalBundle> {
        self.new_proposal(id, MlsProposal::Remove(client_id)).await
    }

    /// Creates a new Add proposal
    #[cfg_attr(test, crate::dispotent)]
    pub async fn new_update_proposal(&self, id: &ConversationId) -> Result<MlsProposalBundle> {
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
    async fn new_proposal(&self, id: &ConversationId, proposal: MlsProposal) -> Result<MlsProposalBundle> {
        let mut conversation = self
            .conversation_guard(id)
            .await
            .map_err(RecursiveError::mls_conversation("getting conversation by id"))?;
        let client = &self
            .mls_client()
            .await
            .map_err(RecursiveError::root("getting mls client"))?;
        proposal
            .create(
                client,
                &self
                    .mls_provider()
                    .await
                    .map_err(RecursiveError::root("getting mls provider"))?,
                conversation.conversation_mut().await,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use crate::{prelude::*, test_utils::*};

    wasm_bindgen_test_configure!(run_in_browser);

    mod add {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_add_member(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    let bob_kp = bob_central.get_one_key_package(&case).await;
                    alice_central.context.new_add_proposal(&id, bob_kp).await.unwrap();
                    alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .commit_pending_proposals()
                        .await
                        .unwrap();
                    let welcome = alice_central.mls_transport.latest_welcome_message().await;
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);
                    let new_id = bob_central
                        .context
                        .process_welcome_message(welcome.into(), case.custom_cfg())
                        .await
                        .unwrap()
                        .id;
                    assert_eq!(id, new_id);
                    assert!(bob_central.try_talk_to(&id, &alice_central).await.is_ok());
                })
            })
            .await
        }
    }

    mod update {
        use super::*;
        use itertools::Itertools;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_update_hpke_key(case: TestCase) {
            run_test_with_central(case.clone(), move |[central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    let before = central
                        .get_conversation_unchecked(&id)
                        .await
                        .encryption_keys()
                        .find_or_first(|_| true)
                        .unwrap();
                    central.context.new_update_proposal(&id).await.unwrap();
                    central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .commit_pending_proposals()
                        .await
                        .unwrap();
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

    mod remove {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_remove_member(case: TestCase) {
            use crate::mls;

            run_test_with_client_ids(case.clone(), ["alice", "bob"], |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);
                    assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 2);

                    let remove_proposal = alice_central
                        .context
                        .new_remove_proposal(&id, bob_central.get_client_id().await)
                        .await
                        .unwrap();
                    bob_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .decrypt_message(remove_proposal.proposal.to_bytes().unwrap())
                        .await
                        .unwrap();
                    alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .commit_pending_proposals()
                        .await
                        .unwrap();
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);

                    let commit = alice_central.mls_transport.latest_commit().await;
                    bob_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .decrypt_message(commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    assert!(matches!(
                        bob_central.context.conversation_guard(&id).await.unwrap_err(),
                        mls::conversation::Error::Leaf(LeafError::ConversationNotFound(conv_id)) if conv_id == id
                    ));
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_unknown_client(case: TestCase) {
            use crate::mls;

            run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let remove_proposal = alice_central
                        .context
                        .new_remove_proposal(&id, b"unknown"[..].into())
                        .await;
                    assert!(matches!(
                        remove_proposal.unwrap_err(),
                        mls::Error::ClientNotFound(client_id) if client_id == b"unknown"[..].into()
                    ));
                })
            })
            .await
        }
    }
}
