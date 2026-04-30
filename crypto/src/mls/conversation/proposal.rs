//! This table summarizes when a MLS group can create a commit or proposal:
//!
//! | can create handshake ? | 0 pend. Commit | 1 pend. Commit |
//! |------------------------|----------------|----------------|
//! | 0 pend. Proposal       | ✅              | ❌              |
//! | 1+ pend. Proposal      | ✅              | ❌              |

use core_crypto_keystore::Database;
use openmls::{binary_tree::LeafNodeIndex, framing::MlsMessageOut, key_packages::KeyPackageIn};

use super::{Error, Result};
use crate::{MlsConversation, MlsError, MlsProposalRef, Session};

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

    /// Used when updating the history client.
    pub(crate) async fn propose_remove_member(
        &mut self,
        session: &Session<Database>,
        member: LeafNodeIndex,
    ) -> Result<MlsProposalBundle> {
        let signer = &self
            .find_current_credential(session)
            .await
            .map_err(|_| Error::IdentityInitializationError)?
            .signature_key_pair;
        let proposal = self
            .group
            .propose_remove_member(&session.crypto_provider, signer, member)
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

    mod external_propose_remove {
        use openmls::prelude::{ProcessMessageError, ValidationError};

        use super::*;
        use crate::{MlsError, MlsErrorKind};

        #[apply(all_cred_cipher)]
        async fn ds_should_remove_guest_from_conversation(mut case: TestContext) {
            let [owner, guest, ds] = case.sessions().await;
            Box::pin(async move {
                let conversation = case
                    .create_conversation_with_external_sender(&ds, [&owner, &guest])
                    .await;
                assert_eq!(conversation.member_count().await, 2);

                // now, as e.g. a Delivery Service, let's create an external remove proposal
                // and kick guest out of the conversation

                let conversation = conversation.external_remove_proposal_notify(&ds, &guest).await;
                let conversation = conversation.commit_pending_proposals_notify().await;
                assert_eq!(conversation.member_count().await, 1);

                // guest can no longer participate
                assert!(guest.transaction.conversation(conversation.id()).await.is_err());
                assert!(!conversation.can_talk(&owner, &guest).await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn should_fail_when_invalid_external_sender(mut case: TestContext) {
            use crate::mls;

            let [owner, guest, ds, attacker] = case.sessions().await;
            Box::pin(async move {
                // Delivery service key is used in the group..
                let conversation = case
                    .create_conversation_with_external_sender(&ds, [&owner, &guest])
                    .await;
                assert_eq!(conversation.member_count().await, 2);

                // now, attacker will try to remove guest from the group, and should fail
                let proposal_guard = conversation
                    .external_remove_proposal_with_sender_index(&attacker, 1, &guest)
                    .await;

                let (proposal_guard, owner_decrypt) = proposal_guard.notify_member_fallible(&owner).await;

                assert!(matches!(
                    owner_decrypt.unwrap_err(),
                    mls::conversation::Error::Mls(MlsError {
                        source: MlsErrorKind::MlsMessageError(ProcessMessageError::ValidationError(
                            ValidationError::UnauthorizedExternalSender
                        )),
                        ..
                    })
                ));

                let (_, guest_decrypt) = proposal_guard.notify_member_fallible(&guest).await;
                assert!(matches!(
                    guest_decrypt.unwrap_err(),
                    mls::conversation::Error::Mls(MlsError {
                        source: MlsErrorKind::MlsMessageError(ProcessMessageError::ValidationError(
                            ValidationError::UnauthorizedExternalSender
                        )),
                        ..
                    })
                ));
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn should_fail_when_wrong_signature_key(mut case: TestContext) {
            use crate::mls;

            let [owner, guest, ds] = case.sessions().await;
            Box::pin(async move {
                // Here we're going to add the Delivery Service's (DS) signature key to the
                // external senders list. However, for the purpose of this test, we will
                // intentionally _not_ use that key when generating the remove proposal below.
                let conversation = case
                    .create_conversation_with_external_sender(&ds, [&owner, &guest])
                    .await;
                assert_eq!(conversation.member_count().await, 2);

                // Intentionally use the guest's credential, and therefore the guest's signature
                // key when generating the proposal so that the signature verification fails.
                let proposal_guard = conversation.external_remove_proposal(&guest, &guest).await;

                let (proposal_guard, owner_decrypt) = proposal_guard.notify_member_fallible(&owner).await;
                assert!(matches!(
                    owner_decrypt.unwrap_err(),
                    mls::conversation::Error::Mls(MlsError {
                        source: MlsErrorKind::MlsMessageError(ProcessMessageError::InvalidSignature),
                        ..
                    })
                ));

                let (_, guest_decrypt) = proposal_guard.notify_member_fallible(&guest).await;
                assert!(matches!(
                    guest_decrypt.unwrap_err(),
                    mls::conversation::Error::Mls(MlsError {
                        source: MlsErrorKind::MlsMessageError(ProcessMessageError::InvalidSignature),
                        ..
                    })
                ));
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn joiners_from_welcome_can_accept_external_remove_proposals(mut case: TestContext) {
            let [alice, bob, charlie, ds] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation_with_external_sender(&ds, [&alice, &bob]).await;
                assert_eq!(conversation.member_count().await, 2);

                // Charlie joins through a Welcome and should get external_senders from Welcome
                // message and not from configuration
                // charlie can only get it from there, because the `MlsCustomgConfiguration` that they receive when
                // processing the welcome, doesn't contain any info about an external sender.
                let conversation = conversation.invite_notify([&charlie]).await;
                assert_eq!(conversation.member_count().await, 3);
                assert!(conversation.is_functional_and_contains([&alice, &bob, &charlie]).await);

                // now, as e.g. a Delivery Service, let's create an external remove proposal
                // and kick Bob out of the conversation

                // joiner from Welcome should be able to verify the external remove proposal since
                // it has fetched back the external_sender from Welcome
                let conversation = conversation.external_remove_proposal_notify(&ds, &bob).await;
                let conversation = conversation
                    .acting_as(&charlie)
                    .await
                    .commit_pending_proposals_notify()
                    .await;

                assert_eq!(conversation.member_count().await, 2);

                assert!(conversation.is_functional_and_contains([&alice, &charlie]).await);
                assert!(!conversation.can_talk(&alice, &bob).await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn joiners_from_external_commit_can_accept_external_remove_proposals(mut case: TestContext) {
            let [alice, bob, charlie, ds] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation_with_external_sender(&ds, [&alice, &bob]).await;
                assert_eq!(conversation.member_count().await, 2);

                // Charlie joins through an external commit and should get external_senders
                // from the public group state and not from configuration
                let conversation = conversation.external_join_notify(&charlie).await;
                assert_eq!(conversation.member_count().await, 3);
                assert!(conversation.is_functional_and_contains([&alice, &bob, &charlie]).await);

                // now, as e.g. a Delivery Service, let's create an external remove proposal
                // and kick Bob out of the conversation

                // joiner from external commit should be able to verify the external remove proposal
                // since it has fetched back the external_sender from external commit
                let conversation = conversation.external_remove_proposal_notify(&ds, &bob).await;
                let conversation = conversation
                    .acting_as(&charlie)
                    .await
                    .commit_pending_proposals_notify()
                    .await;

                assert_eq!(conversation.member_count().await, 2);

                assert!(conversation.is_functional_and_contains([&alice, &charlie]).await);
                assert!(!conversation.can_talk(&alice, &bob).await);
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
