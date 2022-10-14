//! Handshake refers here to either a commit or proposal message. Overall, it covers all the
//! operation modifying the group state
//!
//! This table summarizes when a MLS group can create a commit or proposal:
//!
//! | can create handshake ? | 0 pend. Commit | 1 pend. Commit |
//! |------------------------|----------------|----------------|
//! | 0 pend. Proposal       | ✅              | ❌              |
//! | 1+ pend. Proposal      | ✅              | ❌              |

use std::io::Write;

use openmls::prelude::{KeyPackage, KeyPackageRef, MlsMessageOut, Welcome};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::Error;

use mls_crypto_provider::MlsCryptoProvider;

use crate::mls::conversation::public_group_state::PublicGroupStateBundle;
use crate::prelude::MlsProposalRef;
use crate::{
    mls::member::ConversationMember, mls::ClientId, mls::ConversationId, mls::MlsCentral, CryptoError, CryptoResult,
    MlsError,
};

use super::MlsConversation;

/// Returned when a commit is created
#[derive(Debug)]
pub struct MlsProposalBundle {
    /// The proposal message
    pub proposal: MlsMessageOut,
    /// An identifier of the proposal to rollback it later if required
    pub proposal_ref: MlsProposalRef,
}

impl From<(MlsMessageOut, openmls::prelude::hash_ref::ProposalRef)> for MlsProposalBundle {
    fn from((proposal, proposal_ref): (MlsMessageOut, openmls::prelude::hash_ref::ProposalRef)) -> Self {
        Self {
            proposal,
            proposal_ref: proposal_ref.into(),
        }
    }
}

impl MlsProposalBundle {
    /// Serializes both wrapped objects into TLS and return them as a tuple of byte arrays.
    /// 0 -> proposal
    /// 1 -> proposal reference
    pub fn to_bytes_pair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        use openmls::prelude::TlsSerializeTrait as _;
        let proposal = self.proposal.to_bytes().map_err(MlsError::from)?;
        let proposal_ref = self.proposal_ref.tls_serialize_detached().map_err(MlsError::from)?;

        Ok((proposal, proposal_ref))
    }
}

/// Creating proposals
impl MlsConversation {
    /// see [openmls::group::MlsGroup::propose_add_member]
    #[cfg_attr(test, crate::durable)]
    pub async fn propose_add_member(
        &mut self,
        backend: &MlsCryptoProvider,
        key_package: &KeyPackage,
    ) -> CryptoResult<MlsProposalBundle> {
        let proposal = self
            .group
            .propose_add_member(backend, key_package)
            .await
            .map_err(MlsError::from)
            .map(MlsProposalBundle::from)?;
        self.persist_group_when_changed(backend, false).await?;
        Ok(proposal)
    }

    /// see [openmls::group::MlsGroup::propose_self_update]
    #[cfg_attr(test, crate::durable)]
    pub async fn propose_self_update(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<MlsProposalBundle> {
        let proposal = self
            .group
            .propose_self_update(backend, None)
            .await
            .map_err(MlsError::from)
            .map(MlsProposalBundle::from)?;
        self.persist_group_when_changed(backend, false).await?;
        Ok(proposal)
    }

    /// see [openmls::group::MlsGroup::propose_remove_member]
    #[cfg_attr(test, crate::durable)]
    pub async fn propose_remove_member(
        &mut self,
        backend: &MlsCryptoProvider,
        member: &KeyPackageRef,
    ) -> CryptoResult<MlsProposalBundle> {
        let proposal = self
            .group
            .propose_remove_member(backend, member)
            .await
            .map_err(MlsError::from)
            .map_err(CryptoError::from)
            .map(MlsProposalBundle::from)?;
        self.persist_group_when_changed(backend, false).await?;
        Ok(proposal)
    }
}

/// Returned when initializing a conversation through a commit.
/// Different from conversation created from a [`Welcome`] message or an external commit.
#[derive(Debug, tls_codec::TlsSize)]
pub struct MlsConversationCreationMessage {
    /// A welcome message for new members to join the group
    pub welcome: Welcome,
    /// Commit message adding members to the group
    pub commit: MlsMessageOut,
    /// [`PublicGroupState`] (aka GroupInfo) if the commit is merged
    pub public_group_state: PublicGroupStateBundle,
}

impl tls_codec::Serialize for MlsConversationCreationMessage {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.welcome
            .tls_serialize(writer)
            .and_then(|w| self.commit.tls_serialize(writer).map(|l| l + w))
            .and_then(|w| self.public_group_state.tls_serialize(writer).map(|l| l + w))
    }
}

impl MlsConversationCreationMessage {
    /// Serializes both wrapped objects into TLS and return them as a tuple of byte arrays.
    /// 0 -> welcome
    /// 1 -> commit
    /// 2 -> public_group_state
    pub fn to_bytes_triple(&self) -> CryptoResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        use openmls::prelude::TlsSerializeTrait as _;
        let welcome = self.welcome.tls_serialize_detached().map_err(MlsError::from)?;
        let msg = self.commit.to_bytes().map_err(MlsError::from)?;
        let public_group_state = self
            .public_group_state
            .tls_serialize_detached()
            .map_err(MlsError::from)?;

        Ok((welcome, msg, public_group_state))
    }
}

/// Returned when a commit is created
#[derive(Debug, tls_codec::TlsSize)]
pub struct MlsCommitBundle {
    /// A welcome message if there are pending Add proposals
    pub welcome: Option<Welcome>,
    /// The commit message
    pub commit: MlsMessageOut,
    /// [`PublicGroupState`] (aka GroupInfo) if the commit is merged
    pub public_group_state: PublicGroupStateBundle,
}

impl tls_codec::Serialize for MlsCommitBundle {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.welcome
            .tls_serialize(writer)
            .and_then(|w| self.commit.tls_serialize(writer).map(|l| l + w))
            .and_then(|w| self.public_group_state.tls_serialize(writer).map(|l| l + w))
    }
}

impl MlsCommitBundle {
    /// Serializes both wrapped objects into TLS and return them as a tuple of byte arrays.
    /// 0 -> welcome
    /// 1 -> message
    /// 2 -> public group state
    #[allow(clippy::type_complexity)]
    pub fn to_bytes_triple(&self) -> CryptoResult<(Option<Vec<u8>>, Vec<u8>, Vec<u8>)> {
        use openmls::prelude::TlsSerializeTrait as _;
        let welcome = self
            .welcome
            .as_ref()
            .map(|w| w.tls_serialize_detached().map_err(MlsError::from))
            .transpose()?;
        let commit = self.commit.to_bytes().map_err(MlsError::from)?;
        let public_group_state = self
            .public_group_state
            .tls_serialize_detached()
            .map_err(MlsError::from)?;

        Ok((welcome, commit, public_group_state))
    }
}

/// Creating commit
impl MlsConversation {
    /// see [MlsCentral::add_members_to_conversation]
    /// Note: this is not exposed publicly because authorization isn't handled at this level
    #[cfg_attr(test, crate::durable)]
    pub(crate) async fn add_members(
        &mut self,
        members: &mut [ConversationMember],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsConversationCreationMessage> {
        let keypackages = members
            .iter_mut()
            .flat_map(|member| member.keypackages_for_all_clients())
            .filter_map(|(_, kps)| kps)
            .collect::<Vec<KeyPackage>>();

        let (commit, welcome, pgs) = self
            .group
            .add_members(backend, &keypackages)
            .await
            .map_err(MlsError::from)?;

        self.persist_group_when_changed(backend, false).await?;

        Ok(MlsConversationCreationMessage {
            welcome,
            commit,
            public_group_state: PublicGroupStateBundle::try_new_full_unencrypted(pgs)?,
        })
    }

    /// see [MlsCentral::remove_members_from_conversation]
    /// Note: this is not exposed publicly because authorization isn't handled at this level
    #[cfg_attr(test, crate::durable)]
    pub(crate) async fn remove_members(
        &mut self,
        clients: &[ClientId],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsCommitBundle> {
        let crypto = backend.crypto();

        let member_kps = self
            .group
            .members()
            .into_iter()
            .filter(|kp| {
                clients
                    .iter()
                    .any(move |client_id| client_id.as_slice() == kp.credential().identity())
            })
            .try_fold(Vec::new(), |mut acc, kp| -> CryptoResult<Vec<KeyPackageRef>> {
                acc.push(kp.hash_ref(crypto).map_err(MlsError::from)?);
                Ok(acc)
            })?;

        let (commit, welcome, pgs) = self
            .group
            .remove_members(backend, &member_kps)
            .await
            .map_err(MlsError::from)?;

        self.persist_group_when_changed(backend, false).await?;

        Ok(MlsCommitBundle {
            commit,
            welcome,
            public_group_state: PublicGroupStateBundle::try_new_full_unencrypted(pgs)?,
        })
    }

    /// see [MlsCentral::update_keying_material]
    #[cfg_attr(test, crate::durable)]
    pub(crate) async fn update_keying_material(
        &mut self,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsCommitBundle> {
        let (commit, welcome, pgs) = self.group.self_update(backend, None).await.map_err(MlsError::from)?;

        self.persist_group_when_changed(backend, false).await?;

        Ok(MlsCommitBundle {
            welcome,
            commit,
            public_group_state: PublicGroupStateBundle::try_new_full_unencrypted(pgs)?,
        })
    }

    /// see [MlsCentral::commit_pending_proposals]
    #[cfg_attr(test, crate::durable)]
    pub(crate) async fn commit_pending_proposals(
        &mut self,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Option<MlsCommitBundle>> {
        if self.group.pending_proposals().count() > 0 {
            let (commit, welcome, pgs) = self
                .group
                .commit_to_pending_proposals(backend)
                .await
                .map_err(MlsError::from)?;

            self.persist_group_when_changed(backend, false).await?;

            Ok(Some(MlsCommitBundle {
                welcome,
                commit,
                public_group_state: PublicGroupStateBundle::try_new_full_unencrypted(pgs)?,
            }))
        } else {
            Ok(None)
        }
    }
}

impl MlsCentral {
    /// Adds new members to the group/conversation
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    /// * `members` - members to be added to the group
    ///
    /// # Return type
    /// An optional struct containing a welcome and a message will be returned on successful call.
    /// The value will be `None` only if the group can't be found locally (no error will be returned
    /// in this case).
    ///
    /// # Errors
    /// If the authorisation callback is set, an error can be caused when the authorization fails.
    /// Other errors are KeyStore and OpenMls errors:
    pub async fn add_members_to_conversation(
        &mut self,
        id: &ConversationId,
        members: &mut [ConversationMember],
    ) -> CryptoResult<MlsConversationCreationMessage> {
        if let Some(callbacks) = self.callbacks.as_ref() {
            if !callbacks.authorize(id.clone(), self.mls_client.id().clone()) {
                return Err(CryptoError::Unauthorized);
            }
        }
        Self::get_conversation_mut(&mut self.mls_groups, id)?
            .add_members(members, &self.mls_backend)
            .await
    }

    /// Removes clients from the group/conversation.
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    /// * `clients` - list of client ids to be removed from the group
    ///
    /// # Return type
    /// An optional message will be returned on successful call.
    /// The value will be `None` only if the group can't be found locally (no error will be returned
    /// in this case).
    ///
    /// # Errors
    /// If the authorisation callback is set, an error can be caused when the authorization fails. Other errors are KeyStore and OpenMls errors.
    pub async fn remove_members_from_conversation(
        &mut self,
        id: &ConversationId,
        clients: &[ClientId],
    ) -> CryptoResult<MlsCommitBundle> {
        if let Some(callbacks) = self.callbacks.as_ref() {
            if !callbacks.authorize(id.clone(), self.mls_client.id().clone()) {
                return Err(CryptoError::Unauthorized);
            }
        }
        Self::get_conversation_mut(&mut self.mls_groups, id)?
            .remove_members(clients, &self.mls_backend)
            .await
    }

    /// Self updates the KeyPackage and automatically commits. Pending proposals will be commited
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    ///
    /// # Return type
    /// A tuple containing the message with the commit this call generated and an optional welcome
    /// message that will be present if there were pending add proposals to be commited
    ///
    /// # Errors
    /// If the conversation can't be found, an error will be returned. Other errors are originating
    /// from OpenMls and the KeyStore
    pub async fn update_keying_material(&mut self, id: &ConversationId) -> CryptoResult<MlsCommitBundle> {
        Self::get_conversation_mut(&mut self.mls_groups, id)?
            .update_keying_material(&self.mls_backend)
            .await
    }

    /// Commits all pending proposals of the group
    ///
    /// # Arguments
    /// * `backend` - the KeyStore to persist group changes
    ///
    /// # Return type
    /// A tuple containing the commit message and a possible welcome (in the case `Add` proposals were pending within the internal MLS Group)
    ///
    /// # Errors
    /// Errors can be originating from the KeyStore and OpenMls
    pub async fn commit_pending_proposals(&mut self, id: &ConversationId) -> CryptoResult<Option<MlsCommitBundle>> {
        Self::get_conversation_mut(&mut self.mls_groups, id)?
            .commit_pending_proposals(&self.mls_backend)
            .await
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{mls::proposal::MlsProposal, test_utils::*};

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod add_members {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_add_members_to_conversation(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();

                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        let MlsConversationCreationMessage { welcome, .. } = alice_central
                            .add_members_to_conversation(&id, &mut [bob_central.rnd_member().await])
                            .await
                            .unwrap();

                        // before merging, commit is not applied
                        assert_eq!(alice_central[&id].members().len(), 1);
                        alice_central.commit_accepted(&id).await.unwrap();

                        assert_eq!(alice_central[&id].id, id);
                        assert_eq!(alice_central[&id].group.group_id().as_slice(), id);
                        assert_eq!(alice_central[&id].members().len(), 2);

                        bob_central
                            .process_welcome_message(welcome, case.cfg.clone())
                            .await
                            .unwrap();
                        assert_eq!(alice_central[&id].id(), bob_central[&id].id());
                        assert_eq!(bob_central[&id].members().len(), 2);
                        assert!(alice_central.talk_to(&id, &mut bob_central).await.is_ok());
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_return_valid_welcome(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();

                        let welcome = alice_central
                            .add_members_to_conversation(&id, &mut [bob_central.rnd_member().await])
                            .await
                            .unwrap()
                            .welcome;
                        alice_central.commit_accepted(&id).await.unwrap();

                        bob_central
                            .process_welcome_message(welcome, case.cfg.clone())
                            .await
                            .unwrap();
                        assert!(alice_central.talk_to(&id, &mut bob_central).await.is_ok());
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_return_valid_public_group_state(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "guest"],
                move |[mut alice_central, bob_central, mut guest_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();

                        let public_group_state = alice_central
                            .add_members_to_conversation(&id, &mut [bob_central.rnd_member().await])
                            .await
                            .unwrap()
                            .public_group_state;
                        alice_central.commit_accepted(&id).await.unwrap();

                        assert!(guest_central
                            .try_join_from_public_group_state(
                                &id,
                                public_group_state.get_pgs(),
                                case.cfg.clone(),
                                vec![&mut alice_central]
                            )
                            .await
                            .is_ok());
                    })
                },
            )
            .await
        }
    }

    pub mod propose_add_members {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_propose_adding_members_to_conversation(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();
                        let charlie_kp = charlie_central.get_one_key_package().await;

                        assert!(alice_central.pending_proposals(&id).is_empty());
                        let proposal = alice_central
                            .new_proposal(&id, MlsProposal::Add(charlie_kp))
                            .await
                            .unwrap()
                            .proposal;
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        bob_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        let MlsCommitBundle { commit, welcome, .. } =
                            bob_central.commit_pending_proposals(&id).await.unwrap().unwrap();
                        bob_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(bob_central[&id].members().len(), 3);

                        // if 'new_proposal' wasn't durable this would fail because proposal would
                        // not be referenced in commit
                        alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central[&id].members().len(), 3);

                        charlie_central
                            .try_join_from_welcome(
                                &id,
                                case.cfg.clone(),
                                welcome.unwrap(),
                                vec![&mut alice_central, &mut bob_central],
                            )
                            .await
                            .unwrap();
                        assert_eq!(charlie_central[&id].members().len(), 3);
                    })
                },
            )
            .await
        }
    }

    pub mod remove_members {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn alice_can_remove_bob_from_conversation(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();

                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        let MlsCommitBundle { commit, welcome, .. } = alice_central
                            .remove_members_from_conversation(&id, &["bob".into()])
                            .await
                            .unwrap();
                        assert!(welcome.is_none());

                        // before merging, commit is not applied
                        assert_eq!(alice_central[&id].members().len(), 2);
                        alice_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(alice_central[&id].members().len(), 1);

                        bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // But has been removed from the conversation
                        assert!(matches!(
                           bob_central.get_conversation(&id).unwrap_err(),
                            CryptoError::ConversationNotFound(conv_id) if conv_id == id
                        ));
                        assert!(alice_central.talk_to(&id, &mut bob_central).await.is_err());
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_return_valid_welcome(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "guest"],
                move |[mut alice_central, mut bob_central, mut guest_central]| {
                    Box::pin(async move {
                        let id = conversation_id();

                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        let proposal = alice_central
                            .new_proposal(&id, MlsProposal::Add(guest_central.get_one_key_package().await))
                            .await
                            .unwrap();
                        bob_central
                            .decrypt_message(&id, proposal.proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let welcome = alice_central
                            .remove_members_from_conversation(&id, &["bob".into()])
                            .await
                            .unwrap()
                            .welcome;
                        alice_central.commit_accepted(&id).await.unwrap();

                        assert!(guest_central
                            .try_join_from_welcome(&id, case.cfg.clone(), welcome.unwrap(), vec![&mut alice_central])
                            .await
                            .is_ok());
                        // because Bob has been removed from the group
                        assert!(guest_central.talk_to(&id, &mut bob_central).await.is_err());
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_return_valid_public_group_state(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "guest"],
                move |[mut alice_central, mut bob_central, mut guest_central]| {
                    Box::pin(async move {
                        let id = conversation_id();

                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        let public_group_state = alice_central
                            .remove_members_from_conversation(&id, &["bob".into()])
                            .await
                            .unwrap()
                            .public_group_state;
                        alice_central.commit_accepted(&id).await.unwrap();

                        assert!(guest_central
                            .try_join_from_public_group_state(
                                &id,
                                public_group_state.get_pgs(),
                                case.cfg.clone(),
                                vec![&mut alice_central]
                            )
                            .await
                            .is_ok());
                        // because Bob has been removed from the group
                        assert!(guest_central.talk_to(&id, &mut bob_central).await.is_err());
                    })
                },
            )
            .await;
        }
    }

    pub mod propose_remove_members {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_propose_removing_members_from_conversation(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();
                        let pgs = alice_central.verifiable_public_group_state(&id).await;
                        charlie_central
                            .try_join_from_public_group_state(
                                &id,
                                pgs,
                                case.cfg.clone(),
                                vec![&mut alice_central, &mut bob_central],
                            )
                            .await
                            .unwrap();

                        assert!(alice_central.pending_proposals(&id).is_empty());
                        let proposal = alice_central
                            .new_proposal(&id, MlsProposal::Remove(b"charlie"[..].into()))
                            .await
                            .unwrap()
                            .proposal;
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        bob_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        let commit = bob_central.commit_pending_proposals(&id).await.unwrap().unwrap().commit;
                        bob_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(bob_central[&id].members().len(), 2);

                        // if 'new_proposal' wasn't durable this would fail because proposal would
                        // not be referenced in commit
                        alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central[&id].members().len(), 2);
                    })
                },
            )
            .await
        }
    }

    pub mod update_keying_material {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_update_keying_material_conversation_group(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        let bob_keys = bob_central[&id].group.members();
                        let alice_keys = alice_central[&id].group.members();
                        assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

                        let alice_key = alice_central.key_package_of(&id, "alice");

                        // proposing the key update for alice
                        let MlsCommitBundle { commit, welcome, .. } =
                            alice_central.update_keying_material(&id).await.unwrap();
                        assert!(welcome.is_none());

                        // before merging, commit is not applied
                        assert!(alice_central[&id].group.members().contains(&&alice_key));
                        alice_central.commit_accepted(&id).await.unwrap();
                        let alice_new_keys = alice_central[&id].group.members();
                        assert!(!alice_new_keys.contains(&&alice_key));

                        // receiving the commit on bob's side (updating key from alice)
                        bob_central
                            .decrypt_message(&id, &commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let bob_new_keys = bob_central[&id].group.members();
                        assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

                        // ensuring both can encrypt messages
                        assert!(alice_central.talk_to(&id, &mut bob_central).await.is_ok());
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_update_keying_material_group_pending_commit(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        let bob_keys = bob_central[&id].group.members();
                        let alice_keys = alice_central[&id].group.members();

                        // checking that the members on both sides are the same
                        assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

                        let alice_key = alice_central.key_package_of(&id, "alice");

                        // proposing adding charlie
                        let charlie_kp = charlie_central.get_one_key_package().await;
                        let add_charlie_proposal = alice_central
                            .new_proposal(&id, MlsProposal::Add(charlie_kp))
                            .await
                            .unwrap();

                        // receiving the proposal on Bob's side
                        bob_central
                            .decrypt_message(&id, add_charlie_proposal.proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // performing an update on Alice's key. this should generate a welcome for Charlie
                        let MlsCommitBundle { commit, welcome, .. } =
                            alice_central.update_keying_material(&id).await.unwrap();
                        assert!(welcome.is_some());
                        assert!(alice_central[&id].group.members().contains(&&alice_key));
                        alice_central.commit_accepted(&id).await.unwrap();
                        assert!(!alice_central[&id].group.members().contains(&&alice_key));

                        // create the group on charlie's side
                        charlie_central
                            .process_welcome_message(welcome.unwrap(), case.cfg.clone())
                            .await
                            .unwrap();

                        assert_eq!(alice_central[&id].members().len(), 3);
                        assert_eq!(charlie_central[&id].members().len(), 3);
                        // bob still didn't receive the message with the updated key and charlie's addition
                        assert_eq!(bob_central[&id].members().len(), 2);

                        let alice_new_keys = alice_central[&id].group.members();
                        assert!(!alice_new_keys.contains(&&alice_key));

                        // receiving the key update and the charlie's addition to the group
                        bob_central
                            .decrypt_message(&id, &commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(bob_central[&id].members().len(), 3);

                        let bob_new_keys = bob_central[&id].group.members();
                        assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

                        // ensure all parties can encrypt messages
                        assert!(alice_central.talk_to(&id, &mut bob_central).await.is_ok());
                        assert!(bob_central.talk_to(&id, &mut charlie_central).await.is_ok());
                        assert!(charlie_central.talk_to(&id, &mut alice_central).await.is_ok());
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_return_valid_welcome(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "guest"],
                move |[mut alice_central, mut bob_central, mut guest_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        let proposal = alice_central
                            .new_proposal(&id, MlsProposal::Add(guest_central.get_one_key_package().await))
                            .await
                            .unwrap()
                            .proposal;
                        bob_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let MlsCommitBundle { commit, welcome, .. } =
                            alice_central.update_keying_material(&id).await.unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();

                        bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        assert!(guest_central
                            .try_join_from_welcome(
                                &id,
                                case.cfg.clone(),
                                welcome.unwrap(),
                                vec![&mut alice_central, &mut bob_central]
                            )
                            .await
                            .is_ok());
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_return_valid_public_group_state(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "guest"],
                move |[mut alice_central, mut bob_central, mut guest_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        let public_group_state = alice_central
                            .update_keying_material(&id)
                            .await
                            .unwrap()
                            .public_group_state;
                        alice_central.commit_accepted(&id).await.unwrap();

                        assert!(guest_central
                            .try_join_from_public_group_state(
                                &id,
                                public_group_state.get_pgs(),
                                case.cfg.clone(),
                                vec![&mut alice_central]
                            )
                            .await
                            .is_ok());
                    })
                },
            )
            .await;
        }
    }

    pub mod propose_self_update {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_propose_updating(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        let bob_keys = bob_central[&id].group.members();
                        let alice_keys = alice_central[&id].group.members();
                        assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));
                        let alice_key = alice_central.key_package_of(&id, "alice");

                        let proposal = alice_central
                            .new_proposal(&id, MlsProposal::Update)
                            .await
                            .unwrap()
                            .proposal;
                        bob_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        let commit = bob_central.commit_pending_proposals(&id).await.unwrap().unwrap().commit;

                        // before merging, commit is not applied
                        assert!(bob_central[&id].group.members().contains(&&alice_key));
                        bob_central.commit_accepted(&id).await.unwrap();
                        assert!(!bob_central[&id].group.members().contains(&&alice_key));

                        assert!(alice_central[&id].group.members().contains(&&alice_key));
                        // if 'new_proposal' wasn't durable this would fail because proposal would
                        // not be referenced in commit
                        alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert!(!alice_central[&id].group.members().contains(&&alice_key));

                        // ensuring both can encrypt messages
                        assert!(alice_central.talk_to(&id, &mut bob_central).await.is_ok());
                    })
                },
            )
            .await;
        }
    }

    pub mod commit_pending_proposals {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_create_a_commit_out_of_self_pending_proposals(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .new_proposal(&id, MlsProposal::Add(bob_central.get_one_key_package().await))
                            .await
                            .unwrap();
                        assert!(!alice_central.pending_proposals(&id).is_empty());
                        assert_eq!(alice_central[&id].members().len(), 1);
                        let MlsCommitBundle { welcome, .. } =
                            alice_central.commit_pending_proposals(&id).await.unwrap().unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(alice_central[&id].members().len(), 2);

                        bob_central
                            .process_welcome_message(welcome.unwrap(), case.cfg.clone())
                            .await
                            .unwrap();
                        assert!(alice_central.talk_to(&id, &mut bob_central).await.is_ok());
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_return_none_when_there_are_no_pending_proposals(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), case.cfg.clone())
                        .await
                        .unwrap();
                    assert!(alice_central.pending_proposals(&id).is_empty());
                    assert!(alice_central.commit_pending_proposals(&id).await.unwrap().is_none());
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_create_a_commit_out_of_pending_proposals_by_ref(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();
                        let proposal = bob_central
                            .new_proposal(&id, MlsProposal::Add(charlie_central.get_one_key_package().await))
                            .await
                            .unwrap();
                        assert!(!bob_central.pending_proposals(&id).is_empty());
                        assert_eq!(bob_central[&id].members().len(), 2);
                        alice_central
                            .decrypt_message(&id, proposal.proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let MlsCommitBundle { commit, .. } =
                            alice_central.commit_pending_proposals(&id).await.unwrap().unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(alice_central[&id].members().len(), 3);

                        bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(bob_central[&id].members().len(), 3);
                        assert!(alice_central.talk_to(&id, &mut bob_central).await.is_ok());
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_return_valid_welcome(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .new_proposal(&id, MlsProposal::Add(bob_central.get_one_key_package().await))
                            .await
                            .unwrap();
                        let MlsCommitBundle { welcome, .. } =
                            alice_central.commit_pending_proposals(&id).await.unwrap().unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();

                        bob_central
                            .process_welcome_message(welcome.unwrap(), case.cfg.clone())
                            .await
                            .unwrap();
                        assert!(alice_central.talk_to(&id, &mut bob_central).await.is_ok());
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_return_valid_public_group_state(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "guest"],
                move |[mut alice_central, bob_central, mut guest_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .new_proposal(&id, MlsProposal::Add(bob_central.get_one_key_package().await))
                            .await
                            .unwrap();
                        let MlsCommitBundle { public_group_state, .. } =
                            alice_central.commit_pending_proposals(&id).await.unwrap().unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();

                        assert!(guest_central
                            .try_join_from_public_group_state(
                                &id,
                                public_group_state.get_pgs(),
                                case.cfg.clone(),
                                vec![&mut alice_central]
                            )
                            .await
                            .is_ok());
                    })
                },
            )
            .await;
        }
    }
}
