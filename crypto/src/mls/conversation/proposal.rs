//! This table summarizes when a MLS group can create a commit or proposal:
//!
//! | can create handshake ? | 0 pend. Commit | 1 pend. Commit |
//! |------------------------|----------------|----------------|
//! | 0 pend. Proposal       | ✅              | ❌              |
//! | 1+ pend. Proposal      | ✅              | ❌              |

use openmls::{binary_tree::LeafNodeIndex, framing::MlsMessageOut, key_packages::KeyPackageIn, prelude::LeafNode};

use mls_crypto_provider::MlsCryptoProvider;

use super::{Error, Result};
use crate::{
    MlsError, RecursiveError,
    e2e_identity::NewCrlDistributionPoints,
    mls::credential::crl::{extract_crl_uris_from_credentials, get_new_crl_distribution_points},
    prelude::{MlsConversation, MlsProposalRef, Session},
};

/// Creating proposals
impl MlsConversation {
    /// see [openmls::group::MlsGroup::propose_add_member]
    #[cfg_attr(test, crate::durable)]
    pub async fn propose_add_member(
        &mut self,
        client: &Session,
        backend: &MlsCryptoProvider,
        key_package: KeyPackageIn,
    ) -> Result<MlsProposalBundle> {
        let signer = &self
            .find_current_credential_bundle(client)
            .await
            .map_err(|_| Error::IdentityInitializationError)?
            .signature_key;

        let crl_new_distribution_points = get_new_crl_distribution_points(
            backend,
            extract_crl_uris_from_credentials(std::iter::once(key_package.credential().mls_credential()))
                .map_err(RecursiveError::mls_credential("extracting crl uris from credentials"))?,
        )
        .await
        .map_err(RecursiveError::mls_credential("getting new crl distribution points"))?;

        let (proposal, proposal_ref) = self
            .group
            .propose_add_member(backend, signer, key_package)
            .await
            .map_err(MlsError::wrap("propose add member"))?;
        let proposal = MlsProposalBundle {
            proposal,
            proposal_ref: proposal_ref.into(),
            crl_new_distribution_points,
        };
        self.persist_group_when_changed(&backend.keystore(), false).await?;
        Ok(proposal)
    }

    /// see [openmls::group::MlsGroup::propose_remove_member]
    #[cfg_attr(test, crate::durable)]
    pub async fn propose_remove_member(
        &mut self,
        client: &Session,
        backend: &MlsCryptoProvider,
        member: LeafNodeIndex,
    ) -> Result<MlsProposalBundle> {
        let signer = &self
            .find_current_credential_bundle(client)
            .await
            .map_err(|_| Error::IdentityInitializationError)?
            .signature_key;
        let proposal = self
            .group
            .propose_remove_member(backend, signer, member)
            .map_err(MlsError::wrap("propose remove member"))
            .map(MlsProposalBundle::from)?;
        self.persist_group_when_changed(&backend.keystore(), false).await?;
        Ok(proposal)
    }

    /// see [openmls::group::MlsGroup::propose_self_update]
    #[cfg_attr(test, crate::durable)]
    pub async fn propose_self_update(
        &mut self,
        client: &Session,
        backend: &MlsCryptoProvider,
    ) -> Result<MlsProposalBundle> {
        self.propose_explicit_self_update(client, backend, None).await
    }

    /// see [openmls::group::MlsGroup::propose_self_update]
    #[cfg_attr(test, crate::durable)]
    pub async fn propose_explicit_self_update(
        &mut self,
        client: &Session,
        backend: &MlsCryptoProvider,
        leaf_node: Option<LeafNode>,
    ) -> Result<MlsProposalBundle> {
        let msg_signer = &self
            .find_current_credential_bundle(client)
            .await
            .map_err(|_| Error::IdentityInitializationError)?
            .signature_key;

        let proposal = if let Some(leaf_node) = leaf_node {
            let leaf_node_signer = &self.find_most_recent_credential_bundle(client).await?.signature_key;

            self.group
                .propose_explicit_self_update(backend, msg_signer, leaf_node, leaf_node_signer)
                .await
        } else {
            self.group.propose_self_update(backend, msg_signer).await
        }
        .map(MlsProposalBundle::from)
        .map_err(MlsError::wrap("proposing self update"))?;

        self.persist_group_when_changed(&backend.keystore(), false).await?;
        Ok(proposal)
    }
}

/// Returned when a Proposal is created. Helps roll backing a local proposal
#[derive(Debug)]
pub struct MlsProposalBundle {
    /// The proposal message
    pub proposal: MlsMessageOut,
    /// A unique identifier of the proposal to rollback it later if required
    pub proposal_ref: MlsProposalRef,
    /// New CRL distribution points that appeared by the introduction of a new credential
    pub crl_new_distribution_points: NewCrlDistributionPoints,
}

impl From<(MlsMessageOut, openmls::prelude::hash_ref::ProposalRef)> for MlsProposalBundle {
    fn from((proposal, proposal_ref): (MlsMessageOut, openmls::prelude::hash_ref::ProposalRef)) -> Self {
        Self {
            proposal,
            proposal_ref: proposal_ref.into(),
            crl_new_distribution_points: None.into(),
        }
    }
}

impl MlsProposalBundle {
    /// Serializes both wrapped objects into TLS and return them as a tuple of byte arrays.
    /// 0 -> proposal
    /// 1 -> proposal reference
    #[allow(clippy::type_complexity)]
    pub fn to_bytes(self) -> Result<(Vec<u8>, Vec<u8>, NewCrlDistributionPoints)> {
        use openmls::prelude::TlsSerializeTrait as _;
        let proposal = self
            .proposal
            .tls_serialize_detached()
            .map_err(Error::tls_serialize("proposal"))?;
        let proposal_ref = self.proposal_ref.to_bytes();

        Ok((proposal, proposal_ref, self.crl_new_distribution_points))
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use crate::mls::conversation::ConversationWithMls as _;
    use crate::test_utils::*;

    use super::*;

    mod propose_add_members {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn can_propose_adding_members_to_conversation(case: TestContext) {
            let [alice, bob, charlie] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;
                assert!(!conversation.has_pending_proposals().await);

                let proposal_guard = conversation.invite_proposal(&charlie).await;
                assert_eq!(proposal_guard.conversation().pending_proposal_count().await, 1);
                let commit_guard = proposal_guard
                    .notify_members()
                    .await
                    .acting_as(&bob)
                    .await
                    .commit_pending_proposals()
                    .await;
                assert_eq!(commit_guard.conversation().members_counted_by(&bob).await, 3);
                assert_eq!(commit_guard.conversation().members_counted_by(&alice).await, 2);

                // if 'new_proposal' wasn't durable this would fail because proposal would
                // not be referenced in commit
                let conversation = commit_guard.notify_members().await;
                assert_eq!(conversation.member_count().await, 3);
                assert!(conversation.is_functional_and_contains([&alice, &bob, &charlie]).await)
            })
            .await
        }
    }

    mod propose_remove_members {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn can_propose_removing_members_from_conversation(case: TestContext) {
            let [alice, bob, charlie] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob, &charlie]).await;

                assert!(!conversation.has_pending_proposals().await);
                let proposal_guard = conversation.remove_proposal(&charlie).await;
                assert_eq!(proposal_guard.conversation().pending_proposal_count().await, 1);
                let conversation = proposal_guard
                    .notify_members()
                    .await
                    .acting_as(&bob)
                    .await
                    .commit_pending_proposals_notify()
                    .await;
                assert_eq!(conversation.member_count().await, 2);
                assert!(conversation.is_functional_and_contains([&alice, &bob]).await)
            })
            .await
        }
    }

    mod propose_self_update {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn can_propose_updating(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;

                let bob_keys = conversation
                    .guard_of(&bob)
                    .await
                    .conversation()
                    .await
                    .signature_keys()
                    .collect::<Vec<_>>();
                let alice_keys = conversation
                    .guard()
                    .await
                    .conversation()
                    .await
                    .signature_keys()
                    .collect::<Vec<_>>();
                assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));
                let alice_key = conversation.encryption_public_key().await;

                let commit_guard = conversation
                    .update_proposal_notify()
                    .await
                    .acting_as(&bob)
                    .await
                    .commit_pending_proposals()
                    .await;

                let conversation = commit_guard.conversation();

                assert!(
                    !conversation
                        .guard_of(&bob)
                        .await
                        .conversation()
                        .await
                        .encryption_keys()
                        .contains(&alice_key)
                );

                assert!(
                    conversation
                        .guard_of(&alice)
                        .await
                        .conversation()
                        .await
                        .encryption_keys()
                        .contains(&alice_key)
                );
                // if 'new_proposal' wasn't durable this would fail because proposal would
                // not be referenced in commit
                let conversation = commit_guard.notify_members().await;
                assert!(
                    !conversation
                        .guard_of(&alice)
                        .await
                        .conversation()
                        .await
                        .encryption_keys()
                        .contains(&alice_key)
                );

                // ensuring both can encrypt messages
                assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
            })
            .await;
        }
    }

    mod delivery_semantics {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn should_prevent_out_of_order_proposals(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;
                let id = conversation.id().clone();

                let proposal_guard = conversation.update_proposal().await;
                let proposal = proposal_guard.message();
                proposal_guard
                    .notify_members()
                    .await
                    .acting_as(&bob)
                    .await
                    .commit_pending_proposals_notify()
                    .await;
                // epoch++

                // fails when we try to decrypt a proposal for past epoch
                let past_proposal = bob
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(&proposal.to_bytes().unwrap())
                    .await;
                assert!(matches!(past_proposal.unwrap_err(), Error::StaleProposal));
            })
            .await;
        }
    }
}
