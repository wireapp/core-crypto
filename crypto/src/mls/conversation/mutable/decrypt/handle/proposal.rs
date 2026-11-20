use log::info;
use obfuscate::Obfuscated;
use openmls::group::QueuedProposal;
use openmls_traits::OpenMlsProvider as _;

use crate::{
    DecryptedMessage, KeystoreError, Proposal, RecursiveError, WireIdentity,
    mls::{
        conversation::{ConversationMut, Error, Result},
        credential::validation::validate_credentials,
    },
};

/// Handle decryption of a proposal message.
pub(in crate::mls::conversation::mutable::decrypt) async fn handle(
    conversation: &mut ConversationMut,
    proposal: QueuedProposal,
    identity: WireIdentity,
) -> Result<DecryptedMessage> {
    // A proposal reference is a hash of the proposal, so a proposal already pending under this one is the same
    // proposal, received again.
    if conversation
        .group()
        .await
        .mls_group()
        .pending_proposals()
        .any(|pending| pending.proposal_reference_ref() == proposal.proposal_reference_ref())
    {
        return Err(Error::DuplicateMessage);
    }

    let provider = conversation.crypto_provider().await?;
    let credentials = proposal.proposal().credentials_to_verify().collect::<Vec<_>>();
    validate_credentials(provider.authentication_service(), &credentials)
        .await
        .map_err(RecursiveError::mls_credential(
            "checking the credentials a proposal brings in",
        ))?;

    conversation
        .mutate_group(async |provider, group, id| {
            info!(
                group_id = id.to_owned(),
                sender = Obfuscated::from(proposal.sender()),
                proposals = Obfuscated::from(proposal.proposal());
                "Received proposal"
            );
            group
                .store_pending_proposal(provider.storage(), proposal)
                .map_err(KeystoreError::wrap("storing pending proposal"))?;
            Ok(())
        })
        .await?;

    let delay = conversation.compute_next_commit_delay().await;

    Ok(DecryptedMessage::Proposal(Proposal { delay, identity }))
}
