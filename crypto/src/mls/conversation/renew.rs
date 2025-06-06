use core_crypto_keystore::entities::MlsEncryptionKeyPair;
use openmls::prelude::{LeafNode, LeafNodeIndex, Proposal, QueuedProposal, Sender, StagedCommit};
use openmls_traits::OpenMlsCryptoProvider;

use mls_crypto_provider::MlsCryptoProvider;

use super::{Error, Result};
use crate::{
    KeystoreError, RecursiveError,
    prelude::{MlsConversation, MlsProposalBundle, Session},
};

/// Marker struct holding methods responsible for restoring (renewing) proposals (or pending commit)
/// in case another commit has been accepted by the backend instead of ours
pub(crate) struct Renew;

impl Renew {
    /// Renews proposals:
    /// * in pending_proposals but not in valid commit
    /// * in pending_commit but not in valid commit
    ///
    /// NB: we do not deal with partial commit (commit which do not contain all pending proposals)
    /// because they cannot be created at the moment by core-crypto
    ///
    /// * `self_index` - own client [KeyPackageRef] in current MLS group
    /// * `pending_proposals` - local pending proposals in group's proposal store
    /// * `pending_commit` - local pending commit which is now invalid
    /// * `valid_commit` - commit accepted by the backend which will now supersede our local pending commit
    pub(crate) fn renew<'a>(
        self_index: &LeafNodeIndex,
        pending_proposals: impl Iterator<Item = QueuedProposal> + 'a,
        pending_commit: Option<&'a StagedCommit>,
        valid_commit: &'a StagedCommit,
    ) -> (Vec<QueuedProposal>, bool) {
        // indicates if we need to renew an update proposal.
        // true only if we have an empty pending commit or the valid commit does not contain one of our update proposal
        // otherwise, local orphan update proposal will be renewed regularly, without this flag
        let mut needs_update = false;

        let renewed_pending_proposals = if let Some(pending_commit) = pending_commit {
            // present in pending commit but not in valid commit
            let commit_proposals = pending_commit.queued_proposals().cloned().collect::<Vec<_>>();

            // if our own pending commit is empty it means we were attempting to update
            let empty_commit = commit_proposals.is_empty();

            // does the valid commit contains one of our update proposal ?
            let valid_commit_has_own_update_proposal = valid_commit.update_proposals().any(|p| match p.sender() {
                Sender::Member(sender_index) => self_index == sender_index,
                _ => false,
            });

            // do we need to renew the update or has it already been committed
            needs_update = !valid_commit_has_own_update_proposal && empty_commit;

            // local proposals present in local pending commit but not in valid commit
            commit_proposals
                .into_iter()
                .filter_map(|p| Self::is_proposal_renewable(p, Some(valid_commit)))
                .collect::<Vec<_>>()
        } else {
            // local pending proposals present locally but not in valid commit
            pending_proposals
                .filter_map(|p| Self::is_proposal_renewable(p, Some(valid_commit)))
                .collect::<Vec<_>>()
        };
        (renewed_pending_proposals, needs_update)
    }

    /// A proposal has to be renewed if it is absent from supplied commit
    fn is_proposal_renewable(proposal: QueuedProposal, commit: Option<&StagedCommit>) -> Option<QueuedProposal> {
        if let Some(commit) = commit {
            let in_commit = match proposal.proposal() {
                Proposal::Add(add) => commit.add_proposals().any(|p| {
                    let commits_identity = p.add_proposal().key_package().leaf_node().credential().identity();
                    let proposal_identity = add.key_package().leaf_node().credential().identity();
                    commits_identity == proposal_identity
                }),
                Proposal::Remove(remove) => commit
                    .remove_proposals()
                    .any(|p| p.remove_proposal().removed() == remove.removed()),
                Proposal::Update(update) => commit
                    .update_proposals()
                    .any(|p| p.update_proposal().leaf_node() == update.leaf_node()),
                _ => true,
            };
            if in_commit { None } else { Some(proposal) }
        } else {
            // if proposal is orphan (not present in commit)
            Some(proposal)
        }
    }
}

impl MlsConversation {
    /// Given the proposals to renew, actually restore them by using associated methods in [MlsGroup].
    /// This will also add them to the local proposal store
    pub(crate) async fn renew_proposals_for_current_epoch(
        &mut self,
        client: &Session,
        backend: &MlsCryptoProvider,
        proposals: impl Iterator<Item = QueuedProposal>,
        needs_update: bool,
    ) -> Result<Vec<MlsProposalBundle>> {
        let mut bundle = vec![];
        let is_external = |p: &QueuedProposal| matches!(p.sender(), Sender::External(_) | Sender::NewMemberProposal);
        let proposals = proposals.filter(|p| !is_external(p));
        for proposal in proposals {
            let msg = match proposal.proposal {
                Proposal::Add(add) => self.propose_add_member(client, backend, add.key_package.into()).await?,
                Proposal::Remove(remove) => self.propose_remove_member(client, backend, remove.removed()).await?,
                Proposal::Update(update) => self.renew_update(client, backend, Some(update.leaf_node())).await?,
                _ => return Err(Error::ProposalVariantCannotBeRenewed),
            };
            bundle.push(msg);
        }
        if needs_update {
            let proposal = self.renew_update(client, backend, None).await?;
            bundle.push(proposal);
        }
        Ok(bundle)
    }

    /// Renews an update proposal by considering the explicit LeafNode supplied in the proposal
    /// by applying it to the current own LeafNode.
    /// At this point, we have already verified we are only operating on proposals created by self.
    async fn renew_update(
        &mut self,
        client: &Session,
        backend: &MlsCryptoProvider,
        leaf_node: Option<&LeafNode>,
    ) -> Result<MlsProposalBundle> {
        if let Some(leaf_node) = leaf_node {
            // Creating an update rekeys the LeafNode everytime. Hence we need to clear the previous
            // encryption key from the keystore otherwise we would have a leak
            backend
                .key_store()
                .remove::<MlsEncryptionKeyPair, _>(leaf_node.encryption_key().as_slice())
                .await
                .map_err(KeystoreError::wrap("removing mls encryption keypair"))?;
        }

        let mut leaf_node = leaf_node
            .or_else(|| self.group.own_leaf())
            .cloned()
            .ok_or(Error::MlsGroupInvalidState("own_leaf is None"))?;

        let sc = self.signature_scheme();
        let ct = self.own_credential_type()?;
        let cb = client
            .find_most_recent_credential_bundle(sc, ct)
            .await
            .map_err(RecursiveError::mls_client("finding most recent credential bundle"))?;

        leaf_node.set_credential_with_key(cb.to_mls_credential_with_key());

        self.propose_explicit_self_update(client, backend, Some(leaf_node))
            .await
    }

    pub(crate) fn self_pending_proposals(&self) -> impl Iterator<Item = &QueuedProposal> {
        self.group
            .pending_proposals()
            .filter(|&p| matches!(p.sender(), Sender::Member(i) if i == &self.group.own_leaf_index()))
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;

    mod update {
        use super::*;

        #[apply(all_cred_cipher)]
        pub async fn renewable_when_created_by_self(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;
                let id = conversation.id().clone();

                assert!(alice.pending_proposals(&id).await.is_empty());
                let propposal_guard = conversation.update_proposal().await;
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);

                // Bob hasn't Alice's proposal but creates a commit
                let (commit_guard, result) = propposal_guard
                    .finish()
                    .acting_as(&bob)
                    .await
                    .update()
                    .await
                    .notify_member_fallible(&alice)
                    .await;

                let proposals = result.unwrap().proposals;
                // Alice should renew the proposal because its hers
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);
                assert_eq!(proposals.len(), alice.pending_proposals(&id).await.len());

                // It should also renew the proposal when in pending_commit
                let (_, result) = commit_guard
                    .finish()
                    .acting_as(&bob)
                    .await
                    .update()
                    .await
                    .notify_member_fallible(&alice)
                    .await;
                let proposals = result.unwrap().proposals;
                // Alice should renew the proposal because its hers
                // It should also replace existing one
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);
                assert_eq!(proposals.len(), alice.pending_proposals(&id).await.len());
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn not_renewable_when_in_valid_commit(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;
                let id = conversation.id().clone();

                assert!(alice.pending_proposals(&id).await.is_empty());
                // Bob has Alice's update proposal
                let conversation = conversation.update_proposal_notify().await;
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);

                // Bob's commit has Alice's proposal
                let (commit_guard, result) = conversation
                    .acting_as(&bob)
                    .await
                    .update()
                    .await
                    .notify_member_fallible(&alice)
                    .await;

                let proposals = result.unwrap().proposals;
                // Alice proposal should not be renew as it was in valid commit
                assert!(alice.pending_proposals(&id).await.is_empty());
                assert_eq!(proposals.len(), alice.pending_proposals(&id).await.len());

                let (_, result) = commit_guard
                    .finish()
                    .update_proposal_notify()
                    .await
                    .acting_as(&bob)
                    .await
                    .update()
                    .await
                    .notify_member_fallible(&alice)
                    .await;
                let proposals = result.unwrap().proposals;
                // Alice should not be renew as it was in valid commit
                assert!(alice.pending_proposals(&id).await.is_empty());
                assert_eq!(proposals.len(), alice.pending_proposals(&id).await.len());
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn not_renewable_by_ref(case: TestContext) {
            let [alice, bob, charlie] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob, &charlie]).await;
                let id = conversation.id().clone();

                let propposal_guard = conversation.acting_as(&bob).await.update_proposal().await;
                assert!(alice.pending_proposals(&id).await.is_empty());
                let propposal_guard = propposal_guard.notify_member(&alice).await;
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);

                // Charlie hasn't been notified about Bob's proposal but creates a commit
                let (_, result) = propposal_guard
                    .finish()
                    .acting_as(&charlie)
                    .await
                    .update()
                    .await
                    .notify_member_fallible(&alice)
                    .await;
                let proposals = result.unwrap().proposals;
                // Alice should not renew Bob's update proposal
                assert!(alice.pending_proposals(&id).await.is_empty());
                assert_eq!(proposals.len(), alice.pending_proposals(&id).await.len());
            })
            .await
        }
    }

    mod add {
        use super::*;

        #[apply(all_cred_cipher)]
        pub async fn not_renewable_when_valid_commit_adds_same(case: TestContext) {
            let [alice, bob, charlie] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;
                let id = conversation.id().clone();

                // Alice creates a proposal locally that nobody will be notified about
                assert!(alice.pending_proposals(&id).await.is_empty());
                let proposal_guard = conversation.invite_proposal(&charlie).await;
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);

                // Bob commits the same invite that alice proposed
                let (commit_guard, result) = proposal_guard
                    .finish()
                    .acting_as(&bob)
                    .await
                    .invite([&charlie])
                    .await
                    .notify_member_fallible(&alice)
                    .await;

                let proposals = result.unwrap().proposals;
                // Alice proposal is not renewed since she also wanted to add Charlie
                assert!(alice.pending_proposals(&id).await.is_empty());
                assert_eq!(proposals.len(), alice.pending_proposals(&id).await.len());

                let conversation = commit_guard.notify_members().await;
                assert!(conversation.is_functional_and_contains([&alice, &bob, &charlie]).await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn not_renewable_in_pending_commit_when_valid_commit_adds_same(case: TestContext) {
            let [alice, bob, charlie] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;
                let id = conversation.id().clone();

                // Alice creates a proposal locally that nobody will be notified about
                assert!(alice.pending_proposals(&id).await.is_empty());
                let proposal_guard = conversation.invite_proposal(&charlie).await;
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);

                // Here Alice also creates a commit
                alice.commit_pending_proposals_unmerged(&id).await;
                assert!(alice.pending_commit(&id).await.is_some());

                // Bob commits the same invite that alice proposed
                let (commit_guard, result) = proposal_guard
                    .finish()
                    .acting_as(&bob)
                    .await
                    .invite([&charlie])
                    .await
                    .notify_member_fallible(&alice)
                    .await;

                let proposals = result.unwrap().proposals;
                // Alice proposal is not renewed since she also wanted to add Charlie
                assert!(alice.pending_proposals(&id).await.is_empty());
                assert_eq!(proposals.len(), alice.pending_proposals(&id).await.len());

                let conversation = commit_guard.notify_members().await;
                assert!(conversation.is_functional_and_contains([&alice, &bob, &charlie]).await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn not_renewable_by_ref(case: TestContext) {
            let [alice, bob, charlie, debbie] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob, &charlie]).await;
                let id = conversation.id().clone();

                // Bob will propose adding Debbie
                let proposal_guard = conversation
                    .acting_as(&bob)
                    .await
                    .invite_proposal(&debbie)
                    .await
                    .notify_member(&alice)
                    .await;
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);

                // But Charlie will commit meanwhile
                let (_, result) = proposal_guard
                    .finish()
                    .acting_as(&charlie)
                    .await
                    .update()
                    .await
                    .notify_member_fallible(&alice)
                    .await;

                let proposals = result.unwrap().proposals;
                // which Alice should not renew since it's not hers
                assert!(alice.pending_proposals(&id).await.is_empty());
                assert_eq!(proposals.len(), alice.pending_proposals(&id).await.len());
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn renewable_when_valid_commit_doesnt_adds_same(case: TestContext) {
            let [alice, bob, charlie] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;
                let id = conversation.id().clone();

                // Alice proposes adding Charlie
                assert!(alice.pending_proposals(&id).await.is_empty());
                let propposal_guard = conversation.invite_proposal(&charlie).await;
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);

                // But meanwhile Bob will create a commit without Alice's proposal
                let (commit_guard, result) = propposal_guard
                    .finish()
                    .acting_as(&bob)
                    .await
                    .update()
                    .await
                    .notify_member_fallible(&alice)
                    .await;

                let proposals = result.unwrap().proposals;
                // So Alice proposal should be renewed
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);
                assert_eq!(proposals.len(), alice.pending_proposals(&id).await.len());

                // And same should happen when proposal is in pending commit
                alice.commit_pending_proposals_unmerged(&id).await;
                assert!(alice.pending_commit(&id).await.is_some());
                let (_, result) = commit_guard
                    .finish()
                    .acting_as(&bob)
                    .await
                    .update()
                    .await
                    .notify_member_fallible(&alice)
                    .await;

                let proposals = result.unwrap().proposals;
                // So Alice proposal should also be renewed
                // It should also replace existing one
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);
                assert_eq!(proposals.len(), alice.pending_proposals(&id).await.len());
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn renews_pending_commit_when_valid_commit_doesnt_add_same(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;
                let id = conversation.id().clone();

                // Alice has a pending commit
                alice.create_unmerged_commit(&id).await;
                assert!(alice.pending_commit(&id).await.is_some());

                // But meanwhile Bob will create a commit
                let (_, result) = conversation
                    .acting_as(&bob)
                    .await
                    .update()
                    .await
                    .notify_member_fallible(&alice)
                    .await;

                let proposals = result.unwrap().proposals;
                // So Alice proposal should be renewed
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);
                assert_eq!(proposals.len(), alice.pending_proposals(&id).await.len());
            })
            .await
        }
    }

    mod remove {
        use super::*;

        #[apply(all_cred_cipher)]
        pub async fn not_renewable_when_valid_commit_removes_same(case: TestContext) {
            let [alice, bob, charlie] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob, &charlie]).await;
                let id = conversation.id().clone();

                assert!(alice.pending_proposals(&id).await.is_empty());
                let proposal_guard = conversation.remove_proposal(&charlie).await;
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);

                let (commit_guard, result) = proposal_guard
                    .finish()
                    .acting_as(&bob)
                    .await
                    .remove(&charlie)
                    .await
                    .notify_member_fallible(&alice)
                    .await;

                let proposals = result.unwrap().proposals;
                // Remove proposal is not renewed since commit does same
                assert!(alice.pending_proposals(&id).await.is_empty());
                assert_eq!(proposals.len(), alice.pending_proposals(&id).await.len());

                let conversation = commit_guard.notify_members().await;
                assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn not_renewable_by_ref(case: TestContext) {
            let [alice, bob, charlie] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob, &charlie]).await;
                let id = conversation.id().clone();

                assert!(alice.pending_proposals(&id).await.is_empty());
                let proposal_guard = conversation
                    .acting_as(&bob)
                    .await
                    .remove_proposal(&charlie)
                    .await
                    .notify_member(&alice)
                    .await;
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);

                let (_, result) = proposal_guard
                    .finish()
                    .acting_as(&charlie)
                    .await
                    .update()
                    .await
                    .notify_member_fallible(&alice)
                    .await;

                let proposals = result.unwrap().proposals;
                // Remove proposal is not renewed since by ref
                assert!(alice.pending_proposals(&id).await.is_empty());
                assert_eq!(proposals.len(), alice.pending_proposals(&id).await.len());
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn renewable_when_valid_commit_doesnt_remove_same(case: TestContext) {
            let [alice, bob, charlie, debbie] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob, &charlie, &debbie]).await;
                let id = conversation.id().clone();

                // Alice wants to remove Charlie
                assert!(alice.pending_proposals(&id).await.is_empty());
                let propposal_guard = conversation.remove_proposal(&charlie).await;
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);

                // Whereas Bob wants to remove Debbie
                let (_, result) = propposal_guard
                    .finish()
                    .acting_as(&bob)
                    .await
                    .remove(&debbie)
                    .await
                    .notify_member_fallible(&alice)
                    .await;

                let proposals = result.unwrap().proposals;
                // Remove is renewed since valid commit removes another
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);
                assert_eq!(proposals.len(), alice.pending_proposals(&id).await.len());
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn renews_pending_commit_when_commit_doesnt_remove_same(case: TestContext) {
            let [alice, bob, charlie, debbie] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob, &charlie, &debbie]).await;
                let id = conversation.id().clone();

                // Alice wants to remove Charlie
                assert!(alice.pending_proposals(&id).await.is_empty());
                let propposal_guard = conversation.remove_proposal(&charlie).await;
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);
                alice.commit_pending_proposals_unmerged(&id).await;
                assert!(alice.pending_commit(&id).await.is_some());

                // Whereas Bob wants to remove Debbie
                let (_, result) = propposal_guard
                    .finish()
                    .acting_as(&bob)
                    .await
                    .remove(&debbie)
                    .await
                    .notify_member_fallible(&alice)
                    .await;
                let proposals = result.unwrap().proposals;
                // Remove is renewed since valid commit removes another
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);
                assert_eq!(proposals.len(), alice.pending_proposals(&id).await.len());
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn renews_pending_commit_from_proposal_when_commit_doesnt_remove_same(case: TestContext) {
            let [alice, bob, charlie, debbie] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob, &charlie, &debbie]).await;
                let id = conversation.id().clone();

                // Alice wants to remove Charlie
                let propposal_guard = conversation.remove_proposal(&charlie).await;
                alice.commit_pending_proposals_unmerged(&id).await;

                // Whereas Bob wants to remove Debbie
                let (_, result) = propposal_guard
                    .finish()
                    .acting_as(&bob)
                    .await
                    .remove(&debbie)
                    .await
                    .notify_member_fallible(&alice)
                    .await;
                let proposals = result.unwrap().proposals;
                // Remove is renewed since valid commit removes another
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);
                assert_eq!(proposals.len(), alice.pending_proposals(&id).await.len());
            })
            .await
        }
    }
}
