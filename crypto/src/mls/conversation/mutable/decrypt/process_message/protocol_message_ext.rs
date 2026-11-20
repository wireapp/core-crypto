use openmls::prelude::{ContentType, ProtocolMessage, Sender};

use crate::mls::conversation::{ConversationMut, Error, Result};

/// Some helper methods on `ProtocolMessage`
pub(super) trait ProtocolMessageExt {
    /// A non-exhaustive early duplicate detection mechanism.
    ///
    /// In certain scenarios, we can determine whether a message is a duplicate before processing it.
    /// This may return spurious `false`, but all `true` results are true duplicates.
    async fn is_duplicate(&self, conversation: &ConversationMut) -> Result<bool>;
}

impl ProtocolMessageExt for ProtocolMessage {
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

                        // The group keeps the confirmation tag of the commit which created its current epoch.
                        Ok(msg_ct == conversation.group().await.confirmation_tag())
                    }

                    // openmls doesn't expose the proposal of an incoming message before processing it, so a duplicate
                    // proposal can only be recognized afterwards, by its reference.
                    _ => Ok(false),
                }
            }
        }
    }
}
