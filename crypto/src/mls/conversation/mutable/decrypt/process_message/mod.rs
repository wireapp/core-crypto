mod protocol_message_ext;

use openmls::{
    framing::errors::{MessageDecryptionError, SecretTreeError},
    prelude::{
        ContentType, MlsMessageBodyIn, ProcessMessageError, ProcessedMessage as MlsProcessedMessage,
        ProcessedMessageContent, ProtocolMessage, Sender, StageCommitError, ValidationError,
    },
};

use self::protocol_message_ext::ProtocolMessageExt as _;
use super::DeferralReason;
use crate::{
    OpenMlsError,
    mls::conversation::{ConversationMut, Error, Result, config::MAX_FUTURE_EPOCHS},
};

/// Outcome of processing a message
#[derive(derive_more::From)]
pub(super) enum ProcessedMessage {
    Content(MlsProcessedMessage),
    /// A commit we sent ourselves, which the delivery service fanned back out to us.
    #[from(skip)]
    OwnCommit {
        /// Whether it is the commit we have pending.
        matches_pending_commit: bool,
    },
    Deferred(DeferralReason),
}

/// Parse and process a message. This is the step which actually performs decryption.
pub(super) async fn process_message(
    conversation: &mut ConversationMut,
    message: MlsMessageBodyIn,
) -> Result<ProcessedMessage> {
    // Parse the incoming message
    let protocol_message: ProtocolMessage = match message {
        MlsMessageBodyIn::PublicMessage(public_message_in) => public_message_in.into(),
        MlsMessageBodyIn::PrivateMessage(private_message_in) => private_message_in.into(),
        _ => {
            return Err(
                OpenMlsError::wrap("parsing inbound message")(ProcessMessageError::IncompatibleWireFormat).into(),
            );
        }
    };

    let is_duplicate = protocol_message.is_duplicate(conversation).await?;
    let msg_epoch = protocol_message.epoch().as_u64();
    let content_type = protocol_message.content_type();
    conversation
        .mutate_group_with_operation_check(
            async move |provider, group, _| {
                let group_epoch = group.epoch().as_u64();
                let own_leaf_index = group.own_leaf_index();
                let has_pending_commit = group.pending_commit().is_some();

                // Here, we inspect the results OpenMLS retured to us and map those to our own, hopefully-more-helpful
                // response types.
                match group.process_message(provider, protocol_message) {
                    // now that openmls has handled the message, we can return the duplicate message error
                    Ok(_) if is_duplicate => Err(Error::DuplicateMessage),
                    // a private message of ours, which we can't decrypt: we have it already
                    Ok(processed) if matches!(processed.content(), ProcessedMessageContent::OwnPrivateMessage) => {
                        Err(Error::DuplicateMessage)
                    }
                    // openmls recognized our own pending commit
                    Ok(processed) if matches!(processed.content(), ProcessedMessageContent::OwnPendingCommit) => {
                        Ok(ProcessedMessage::OwnCommit {
                            matches_pending_commit: true,
                        })
                    }
                    // A commit of ours, while we have a different one pending. openmls only refuses such a commit
                    // when it has an update path, which it can't decrypt. Without one, it stages the commit as if
                    // another member had sent it, and merging it would silently discard the pending commit. With
                    // nothing pending, merging it is what we want: the delivery service accepted a commit we lost.
                    Ok(processed)
                        if has_pending_commit
                            && matches!(processed.content(), ProcessedMessageContent::StagedCommitMessage(_))
                            && matches!(processed.sender(), Sender::Member(sender) if *sender == own_leaf_index) =>
                    {
                        Ok(ProcessedMessage::OwnCommit {
                            matches_pending_commit: false,
                        })
                    }
                    // processing message went well
                    Ok(processed) => Ok(processed.into()),

                    // Attempt to unpack whether a message was too old, too new, or duplicate.
                    // OpenMLS makes this surprisingly challenging!
                    Err(ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                        MessageDecryptionError::GenerationOutOfBound,
                    ))) => {
                        // This is an annoyance, but not wrong: OpenMLS knows whether the message was too old, too new,
                        // or an actual duplicate. It emits a log line and flattens all three variants into this single
                        // `GenerationOutOfBound` variant, so we can't tell what situation we're in at this level.
                        // `DuplicateMessage` is more likely than the other two, so that's what we unpack here.
                        Err(Error::DuplicateMessage)
                    }
                    // openmls deletes a message's secret once it has decrypted the message, so a secret it can't find
                    // again means we have decrypted this message before.
                    Err(ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                        MessageDecryptionError::SecretTreeError(SecretTreeError::SecretReuseError),
                    ))) => Err(Error::DuplicateMessage),
                    Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch)) if is_duplicate => {
                        Err(Error::DuplicateMessage)
                    }
                    Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch))
                        if msg_epoch > group_epoch && msg_epoch <= group_epoch.saturating_add(MAX_FUTURE_EPOCHS) =>
                    {
                        // limit to next epoch otherwise if we were buffering a commit for epoch + 2
                        // we would fail when trying to decrypt it in mls.

                        // We need to buffer the message until the group has advanced to the right
                        // epoch. We can't do that here--we don't have the appropriate data in scope
                        // --but we can at least produce the proper result and return that, so our
                        // caller can handle it. Our caller needs to know about the epoch number, so
                        // we pass it back inside the deferral.
                        Ok(ProcessedMessage::Deferred(DeferralReason::FutureEpoch {
                            epoch: msg_epoch,
                        }))
                    }
                    Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch))
                        if msg_epoch < group_epoch =>
                    {
                        match content_type {
                            ContentType::Application => Err(Error::MessageEpochTooOld),
                            ContentType::Commit => Err(Error::StaleCommit),
                            ContentType::Proposal => Err(Error::StaleProposal),
                        }
                    }
                    Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch)) => {
                        Err(Error::UnbufferedFarFutureMessage)
                    }
                    // openmls says this both when it no longer has the secrets of the message's epoch, and when the
                    // message is from the current epoch but too far behind the others from its sender. In the latter
                    // case openmls no longer knows whether it decrypted the message, so we can't call it a duplicate:
                    // that would hide a message which was lost.
                    Err(ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                        MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast),
                    ))) => Err(Error::MessageEpochTooOld),

                    // other errors we care to unpack
                    Err(ProcessMessageError::InvalidCommit(StageCommitError::MissingProposal)) => {
                        Ok(ProcessedMessage::Deferred(DeferralReason::MissingProposal))
                    }
                    // a commit of ours that isn't the one we have pending
                    Err(ProcessMessageError::InvalidCommit(StageCommitError::OwnCommitMismatch)) => {
                        Ok(ProcessedMessage::OwnCommit {
                            matches_pending_commit: false,
                        })
                    }
                    Err(ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                        MessageDecryptionError::AeadError,
                    ))) => Err(Error::DecryptionError),

                    // everything else gets a generic wrapping
                    Err(err) => Err(OpenMlsError::wrap("processing message")(err).into()),
                }
            },
            // only outcomes producing a message with content actually mutate the group
            |outcome| !matches!(outcome, ProcessedMessage::Content(_)),
        )
        .await
}
