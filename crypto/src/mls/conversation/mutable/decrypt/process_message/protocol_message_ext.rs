use openmls::prelude::{
    ConfirmationTag, ContentType, FramedContentBodyIn, LeafNodeIndex, Proposal, ProtocolMessage, Sender,
};

use crate::{
    OpenMlsError,
    mls::conversation::{ConversationMut, Error, Result},
};

/// Some helper methods on `ProtocolMessage`
pub(super) trait ProtocolMessageExt {
    /// Extracts the confirmation tag from this message if it is a commit we created.
    ///
    /// If this is not a public message, or if the content type is not a commit, or if we were not the sender,
    /// or the body data is not a commit, or the auth data somehow is missing the content tag, returns
    /// `MlsMessageInvalidState`.
    fn own_commit_confirmation_tag(&self, own_leaf_index: LeafNodeIndex) -> Result<&ConfirmationTag>;

    /// A non-exhaustive early duplicate detection mechanism.
    ///
    /// In certain scenarios, we can determine whether a message is a duplicate before processing it.
    /// This may return spurious `false`, but all `true` results are true duplicates.
    async fn is_duplicate(&self, conversation: &ConversationMut) -> Result<bool>;
}

impl ProtocolMessageExt for ProtocolMessage {
    fn own_commit_confirmation_tag(&self, own_leaf_index: LeafNodeIndex) -> Result<&ConfirmationTag> {
        let ProtocolMessage::PublicMessage(message) = self else {
            return Err(Error::MlsMessageInvalidState(
                "only public protocol messages have a confirmation tag",
            ));
        };
        if !matches!(message.content_type(), ContentType::Commit)
            || !matches!(message.body(), FramedContentBodyIn::Commit(_))
            || !matches!(message.sender(), Sender::Member(idx) if idx == &own_leaf_index)
        {
            return Err(Error::MlsMessageInvalidState("this was not a commit we created"));
        }

        message
            .auth
            .confirmation_tag
            .as_ref()
            .ok_or(Error::MlsMessageInvalidState(
                "confirmation tag missing from message auth",
            ))
    }

    async fn is_duplicate(&self, conversation: &ConversationMut) -> Result<bool> {
        match self {
            ProtocolMessage::PrivateMessage(_) => Ok(false),
            ProtocolMessage::PublicMessage(message) => {
                match (message.content_type(), message.sender()) {
                    (ContentType::Commit, Sender::Member(_) | Sender::NewMemberCommit) => {
                        // we use the confirmation tag to detect duplicate since it is issued from the GroupContext
                        // which is supposed to be unique per epoch
                        let Some(msg_ct) = message.confirmation_tag() else {
                            // a commit MUST have a ConfirmationTag
                            return Err(Error::MlsGroupInvalidState("a commit must have a ConfirmationTag"));
                        };

                        let crypto_provider = conversation.crypto_provider().await?;

                        let group_ct = conversation
                            .group()
                            .await
                            .compute_confirmation_tag(&crypto_provider)
                            .map_err(OpenMlsError::wrap("computing confirmation tag"))?;

                        Ok(msg_ct == &group_ct)
                    }

                    (ContentType::Proposal, Sender::Member(_) | Sender::NewMemberProposal) => {
                        let FramedContentBodyIn::Proposal(proposal) = message.body() else {
                            return Err(Error::MlsGroupInvalidState(
                                "message body was not a proposal despite ContentType::Proposal",
                            ));
                        };

                        let proposal = Proposal::from(proposal.clone()); // TODO: eventually remove this clone 😮‍💨. Tracking issue: WPB-9622
                        let already_exists = conversation
                            .group()
                            .await
                            .pending_proposals()
                            .any(|pp| pp.proposal() == &proposal);
                        Ok(already_exists)
                    }

                    _ => Ok(false),
                }
            }
        }
    }
}
