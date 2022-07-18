//! A MLS group can be merged (aka committed) when it has a pending commit. The latter is a commit
//! we created which is still waiting to be "committed". By doing so, we will apply all the
//! modifications present in the commit to the ratchet tree and also persist the new group in the
//! keystore. Like this, even if the application crashes we will be able to restore.
//!
//! This table summarizes when a MLS group can be merged:
//!
//! | can be merged ?   | 0 pend. Commit | 1 pend. Commit |
//! |-------------------|----------------|----------------|
//! | 0 pend. Proposal  | ❌              | ✅              |
//! | 1+ pend. Proposal | ❌              | ✅              |
//!

use openmls::prelude::{QueuedProposal, Sender};

use mls_crypto_provider::MlsCryptoProvider;

use crate::{ConversationId, CryptoError, CryptoResult, MlsCentral, MlsConversation, MlsError};

/// Abstraction over a MLS group capable of merging a commit
#[derive(Debug, derive_more::Deref, derive_more::DerefMut)]
pub struct MlsConversationCanMerge<'a>(&'a mut MlsConversation);

impl MlsConversationCanMerge<'_> {
    const REASON: &'static str = "No pending commit to merge";

    /// see [MlsCentral::commit_accepted]
    pub async fn commit_accepted(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<()> {
        // preserve proposal store before 'merge_pending_commit' erases it
        let previous_pending_proposals = self.group.pending_proposals().cloned().collect::<Vec<_>>();

        self.group.merge_pending_commit().map_err(MlsError::from)?;

        // Now restore our own proposals we created for our future self e.g. when leaving a group.
        // This is safe because core-crypto prevents us from creating proposals when there is a pending commit.
        // TODO: What to do with received proposals while we have a pending commit ?
        self.restore_proposals(previous_pending_proposals);

        self.persist_group_when_changed(backend, false).await
    }

    /// see [MlsCentral::commit_conflict]
    async fn commit_conflict(&mut self, _backend: &MlsCryptoProvider) -> CryptoResult<()> {
        unimplemented!()
    }

    /// Merging a commit erases all pending proposals. But we might need to restore them if:
    /// - We just "leave" the group. We still have a Remove Proposal for ourselves that we have
    /// to keep in order to accept the final commit with this proposal which will definitely
    /// kick us out of this group
    /// - TODO: After creating the commit and before merging it, we have received proposals, we should
    /// restore them because it might be unordered proposals for the next epoch sent by the DS
    fn restore_proposals(&mut self, proposals: Vec<QueuedProposal>) {
        let previous_own_kpr = self.0.group.key_package_ref().cloned();
        let is_sent_by_self =
            |p: &QueuedProposal| matches!(p.sender(), Sender::Member(kpr) if Some(kpr) == previous_own_kpr.as_ref());
        proposals
            .into_iter()
            .filter(is_sent_by_self)
            .for_each(|p| self.group.store_pending_proposal(p));
    }
}

impl<'a> TryFrom<&'a mut MlsConversation> for MlsConversationCanMerge<'a> {
    type Error = CryptoError;

    fn try_from(conv: &'a mut MlsConversation) -> CryptoResult<Self> {
        if conv.group.pending_commit().is_some() {
            Ok(Self(conv))
        } else {
            Err(CryptoError::GroupStateError(Self::REASON))
        }
    }
}

/// A MLS group is a distributed object scattered across many parties. We use a Delivery Service
/// to orchestrate those parties. So when we create a commit, a mutable operation, it has to be
/// validated by the Delivery Service. But it might occur that another group member did the
/// exact same thing at the same time. So if we arrive second in this race, we must "rollback" the commit
/// we created and accept ("merge") the other one.
/// A client would
/// * Create a commit
/// * Send the commit to the Delivery Service
/// * When Delivery Service responds
///     * 200 OK --> use [MlsCentral::commit_accepted] to merge the commit
///     * 409 CONFLICT --> use [MlsCentral::commit_conflict] to rollback the commit
///     * 5xx --> retry
impl MlsCentral {
    /// The commit we created has been accepted by the Delivery Service. Hence it is guaranteed
    /// to be used for the new epoch.
    /// We can now safely "merge" it (effectively apply the commit to the group) and update it
    /// in the keystore. The previous can be discarded to respect Forward Secrecy.
    pub async fn commit_accepted(&mut self, conversation_id: &ConversationId) -> CryptoResult<()> {
        Self::get_conversation_mut::<MlsConversationCanMerge>(&mut self.mls_groups, conversation_id)?
            .commit_accepted(&self.mls_backend)
            .await
    }

    /// Rollbacks an unmerged commit. Use it when you created a commit, sent it to the Delivery Service
    /// but the latter rejects it (e.g. by responding 409 CONFLICT if it's a http server).
    /// We now have to locally rollback everything (pending commit and proposals) and return to the
    /// consumer all the proposals which were in the pending commit in order to include them in the next
    /// valid epoch
    pub async fn commit_conflict(&mut self, conversation_id: &ConversationId) -> CryptoResult<()> {
        Self::get_conversation_mut::<MlsConversationCanMerge>(&mut self.mls_groups, conversation_id)?
            .commit_conflict(&self.mls_backend)
            .await
    }
}

#[cfg(test)]
impl MlsConversation {
    pub fn as_can_merge(&mut self) -> MlsConversationCanMerge {
        MlsConversationCanMerge::try_from(self).unwrap()
    }
}

#[cfg(test)]
pub mod tests {
    use openmls::prelude::{MlsGroup, MlsGroupConfig, Proposal};
    use wasm_bindgen_test::*;

    use crate::{
        conversation::decrypt::MlsConversationCanDecrypt, credential::CredentialSupplier, test_fixture_utils::*,
        test_utils::*, MlsCentral, MlsConversationConfiguration,
    };

    use super::super::state_tests_utils::*;
    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod state {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn cannot_merge_when_no_pending(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    conv_no_pending(&mut central, &id).await;
                    let can_merge =
                        MlsCentral::get_conversation_mut::<MlsConversationCanMerge>(&mut central.mls_groups, &id);
                    assert!(matches!(
                        can_merge.unwrap_err(),
                        CryptoError::GroupStateError(MlsConversationCanMerge::REASON)
                    ));
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn cannot_merge_when_pending_proposals_and_no_pending_commit(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    conv_pending_proposal_and_no_pending_commit(&mut central, &id).await;
                    let can_merge =
                        MlsCentral::get_conversation_mut::<MlsConversationCanMerge>(&mut central.mls_groups, &id);
                    assert!(matches!(
                        can_merge.unwrap_err(),
                        CryptoError::GroupStateError(MlsConversationCanMerge::REASON)
                    ));
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn can_merge_when_no_pending_proposals_and_pending_commit(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    conv_no_pending_proposal_and_pending_commit(&mut central, &id).await;
                    let can_merge =
                        MlsCentral::get_conversation_mut::<MlsConversationCanMerge>(&mut central.mls_groups, &id);
                    assert!(can_merge.is_ok());
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn can_merge_when_pending_proposals_and_pending_commit(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice", "bob"], move |[mut alice_central, bob_central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    conv_pending_proposal_and_pending_commit(&mut alice_central, bob_central, &id).await;
                    let can_merge =
                        MlsCentral::get_conversation_mut::<MlsConversationCanMerge>(&mut alice_central.mls_groups, &id);
                    assert!(can_merge.is_ok());
                })
            })
            .await
        }
    }

    pub mod restore_proposals {
        use crate::prelude::MlsConversationCanHandshake;

        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_be_unchanged_when_empty(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    let _ = central.update_keying_material(&id).await.unwrap();
                    let mut conv =
                        MlsCentral::get_conversation_mut::<MlsConversationCanMerge>(&mut central.mls_groups, &id)
                            .unwrap();
                    let before = conv.group.pending_proposals().cloned().collect::<Vec<_>>();
                    conv.restore_proposals(vec![]);
                    let after = conv.group.pending_proposals().cloned().collect::<Vec<_>>();
                    assert_eq!(before, after);
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_not_restore_proposals_of_others(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut alice_central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    let (bob_backend, bob) = bob(credential).await.unwrap();
                    let (charlie_backend, charlie) = charlie(credential).await.unwrap();

                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    let add_bob = alice_central
                        .add_members_to_conversation(&id, &mut [bob])
                        .await
                        .unwrap()
                        .unwrap();
                    alice_central.commit_accepted(&id).await.unwrap();
                    let mut bob_group =
                        MlsGroup::new_from_welcome(&bob_backend, &MlsGroupConfig::default(), add_bob.welcome, None)
                            .await
                            .unwrap();

                    // Alice creates a pending commit...
                    let charlie_kp = charlie
                        .local_client()
                        .gen_keypackage(&charlie_backend)
                        .await
                        .unwrap()
                        .key_package()
                        .clone();
                    alice_central
                        .add_members_to_conversation(&id, &mut [charlie])
                        .await
                        .unwrap();

                    // ...meanwhile Bob creates a proposal and will fan it out to Alice
                    let proposal = bob_group.propose_add_member(&bob_backend, &charlie_kp).await.unwrap();

                    let mut alice_group = MlsCentral::get_conversation_mut::<MlsConversationCanDecrypt>(
                        &mut alice_central.mls_groups,
                        &id,
                    )
                    .unwrap();

                    alice_group
                        .decrypt_message(proposal.to_bytes().unwrap(), &alice_central.mls_backend)
                        .await
                        .unwrap();
                    let before = alice_group.group.pending_proposals();
                    assert_eq!(before.count(), 1);

                    alice_group
                        .as_can_merge()
                        .commit_accepted(&alice_central.mls_backend)
                        .await
                        .unwrap();

                    let after = alice_group.group.pending_proposals();
                    // Proposal is not preserved since Bob sent it
                    assert_eq!(after.count(), 0);
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_restore_self_proposals_when_no_update_path(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut alice_central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    let (_, bob) = bob(credential).await.unwrap();
                    let (_, charlie) = charlie(credential).await.unwrap();

                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    let _ = alice_central
                        .add_members_to_conversation(&id, &mut [bob.clone(), charlie])
                        .await
                        .unwrap()
                        .unwrap();
                    alice_central.commit_accepted(&id).await.unwrap();

                    let mut alice_group = MlsCentral::get_conversation_mut::<MlsConversationCanHandshake>(
                        &mut alice_central.mls_groups,
                        &id,
                    )
                    .unwrap();

                    // Alice removes herself and Bob
                    let _ = alice_group
                        .leave(&[bob.local_client().id().clone()], &alice_central.mls_backend)
                        .await
                        .unwrap();
                    assert!(alice_group.group.pending_commit().is_some());

                    let before = alice_group.group.pending_proposals().cloned().collect::<Vec<_>>();
                    assert_eq!(before.len(), 1);

                    alice_group
                        .as_can_merge()
                        .commit_accepted(&alice_central.mls_backend)
                        .await
                        .unwrap();

                    let after = alice_group.group.pending_proposals().cloned().collect::<Vec<_>>();
                    // Proposal is preserved since created by Alice
                    assert_eq!(before, after);
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_restore_self_proposals_with_update_path(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut alice_central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    let (_, bob) = bob(credential).await.unwrap();
                    let (_, charlie) = charlie(credential).await.unwrap();

                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    let _ = alice_central
                        .add_members_to_conversation(&id, &mut [bob.clone(), charlie])
                        .await
                        .unwrap()
                        .unwrap();
                    alice_central.commit_accepted(&id).await.unwrap();

                    let mut alice_group = MlsCentral::get_conversation_mut::<MlsConversationCanHandshake>(
                        &mut alice_central.mls_groups,
                        &id,
                    )
                    .unwrap();

                    // First Alice updates her KeyPackage
                    let _ = alice_group
                        .group
                        .propose_self_update(&alice_central.mls_backend, None)
                        .await
                        .unwrap();
                    // Alice removes herself and Bob
                    let _ = alice_group
                        .leave(&[bob.local_client().id().clone()], &alice_central.mls_backend)
                        .await
                        .unwrap();
                    assert!(alice_group.group.pending_commit().is_some());

                    let before = alice_group.group.pending_proposals().cloned().collect::<Vec<_>>();
                    assert_eq!(before.len(), 2);
                    let self_remove_proposal = before
                        .iter()
                        .find(|p| matches!(p.proposal(), Proposal::Remove(_)))
                        .unwrap();

                    alice_group
                        .as_can_merge()
                        .commit_accepted(&alice_central.mls_backend)
                        .await
                        .unwrap();

                    // Proposal is preserved since created by Alice
                    let mut after = alice_group.group.pending_proposals();
                    assert!(after.any(|x| x == self_remove_proposal));
                })
            })
            .await
        }
    }
}
