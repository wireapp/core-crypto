//! This table summarizes when a MLS group can create a commit or proposal:
//!
//! | can create handshake ? | 0 pend. Commit | 1 pend. Commit |
//! |------------------------|----------------|----------------|
//! | 0 pend. Proposal       | ✅              | ❌              |
//! | 1+ pend. Proposal      | ✅              | ❌              |

use core_crypto_keystore::Database;
use openmls::{binary_tree::LeafNodeIndex, framing::MlsMessageOut, key_packages::KeyPackageIn};

use super::{Error, Result};
use crate::{MlsConversation, MlsError, MlsProposalRef, Session, mls_provider::MlsCryptoProvider};

/// Creating proposals
impl MlsConversation {
    /// Used when adding or updating the history client.
    pub(crate) async fn propose_add_member(
        &mut self,
        session: &Session<Database>,
        key_package: KeyPackageIn,
    ) -> Result<MlsProposalBundle> {
        let signer = &self
            .find_current_credential(session)
            .await
            .map_err(|_| Error::IdentityInitializationError)?
            .signature_key_pair;

        let (proposal, proposal_ref) = self
            .group
            .propose_add_member(&session.crypto_provider, signer, key_package)
            .await
            .map_err(MlsError::wrap("propose add member"))?;
        let proposal = MlsProposalBundle {
            proposal,
            proposal_ref: proposal_ref.into(),
        };
        Ok(proposal)
    }

    /// see [openmls::group::MlsGroup::propose_remove_member]
    pub async fn propose_remove_member(
        &mut self,
        client: &Session<Database>,
        provider: &MlsCryptoProvider,
        member: LeafNodeIndex,
    ) -> Result<MlsProposalBundle> {
        let signer = &self
            .find_current_credential(client)
            .await
            .map_err(|_| Error::IdentityInitializationError)?
            .signature_key_pair;
        let proposal = self
            .group
            .propose_remove_member(provider, signer, member)
            .map_err(MlsError::wrap("propose remove member"))
            .map(MlsProposalBundle::from)?;
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
    #[allow(clippy::type_complexity)]
    pub fn to_bytes(self) -> Result<(Vec<u8>, Vec<u8>)> {
        use openmls::prelude::TlsSerializeTrait as _;
        let proposal = self
            .proposal
            .tls_serialize_detached()
            .map_err(Error::tls_serialize("proposal"))?;
        let proposal_ref = self.proposal_ref.to_bytes();

        Ok((proposal, proposal_ref))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

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

    mod delivery_semantics {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn should_prevent_out_of_order_proposals(case: TestContext) {
            let [alice, bob, charlie] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob, &charlie]).await;
                let id = conversation.id().clone();

                let proposal_guard = conversation.remove_proposal(&charlie).await;
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
