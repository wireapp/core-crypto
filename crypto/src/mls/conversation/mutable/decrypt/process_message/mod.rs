mod protocol_message_ext;

use openmls::{
    framing::errors::{MessageDecryptionError, SecretTreeError},
    prelude::{
        ConfirmationTag, ContentType, ProcessMessageError, ProcessedMessage as MlsProcessedMessage, ProtocolMessage,
        StageCommitError, ValidationError,
    },
};

use self::protocol_message_ext::ProtocolMessageExt as _;
use super::{DeferralReason, RejectionReason};
use crate::{
    OpenMlsError,
    mls::conversation::{ConversationMut, Result, config::MAX_FUTURE_EPOCHS},
};

/// Outcome of processing a message
#[derive(derive_more::From)]
pub(super) enum ProcessedMessage {
    Content(MlsProcessedMessage),
    OwnCommit(ConfirmationTag),
    Deferred(DeferralReason),
    Rejected(RejectionReason),
}

/// Parse and process a message. This is the step which actually performs decryption.
pub(super) async fn process_message(
    conversation: &mut ConversationMut,
    protocol_message: ProtocolMessage,
) -> Result<ProcessedMessage> {
    let is_duplicate = protocol_message.is_duplicate(conversation).await?;
    let message_epoch = protocol_message.epoch().as_u64();
    let content_type = protocol_message.content_type();
    // we need to compute the confirmation tag now, but it's only relevant in a particular case of processing the
    // message, so don't propagate the error yet.
    let confirmation_tag_result = protocol_message
        .own_commit_confirmation_tag(conversation.group().await.own_leaf_index())
        .map(ToOwned::to_owned);

    let backend = conversation.crypto_provider().await?;
    conversation
        .mutate_group_with_operation_check(
            async move |_, group, _| {
                let group_epoch = group.epoch().as_u64();

                // Here, we inspect the results OpenMLS retured to us and map those to our own, hopefully-more-helpful
                // response types.
                //
                // It's worth noting that `group.process_message` unconditionally sets the group's
                // `InnerState::Changed`, and `mutate_group` uses only two signals to determine
                match group.process_message(&backend, protocol_message).await {
                    // now that openmls has handled the message, we can return the duplicate message error
                    Ok(_) if is_duplicate => Ok(RejectionReason::DuplicateMessage.into()),
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
                        Ok(RejectionReason::DuplicateMessage.into())
                    }
                    Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch)) if is_duplicate => {
                        Ok(RejectionReason::DuplicateMessage.into())
                    }
                    Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch))
                        if message_epoch > group_epoch
                            && message_epoch <= group_epoch.saturating_add(MAX_FUTURE_EPOCHS) =>
                    {
                        // limit to next epoch otherwise if we were buffering a commit for epoch + 2
                        // we would fail when trying to decrypt it in mls.

                        // We need to buffer the message until the group has advanced to the right
                        // epoch. We can't do that here--we don't have the appropriate data in scope
                        // --but we can at least produce the proper result and return that, so our
                        // caller can handle it. Our caller needs to know about the epoch number, so
                        // we pass it back inside the deferral.
                        Ok(ProcessedMessage::Deferred(DeferralReason::FutureEpoch {
                            epoch: message_epoch,
                        }))
                    }
                    Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch))
                        if message_epoch < group_epoch =>
                    {
                        match content_type {
                            ContentType::Application => Ok(RejectionReason::MessageEpochTooOld {
                                message_epoch,
                                group_epoch,
                            }
                            .into()),
                            ContentType::Commit => Ok(RejectionReason::StaleCommit.into()),
                            ContentType::Proposal => Ok(RejectionReason::StaleProposal.into()),
                        }
                    }
                    Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch)) => {
                        Ok(RejectionReason::UnbufferedFarFutureMessage {
                            message_epoch,
                            group_epoch,
                        }
                        .into())
                    }
                    Err(ProcessMessageError::ValidationError(
                        ValidationError::UnableToDecrypt(MessageDecryptionError::SecretTreeError(
                            SecretTreeError::TooDistantInThePast,
                        ))
                        | ValidationError::NoPastEpochData,
                    )) => Ok(RejectionReason::MessageEpochTooOld {
                        message_epoch,
                        group_epoch,
                    }
                    .into()),

                    // other errors we care to unpack
                    Err(ProcessMessageError::InvalidCommit(StageCommitError::MissingProposal)) => {
                        Ok(ProcessedMessage::Deferred(DeferralReason::MissingProposal))
                    }
                    Err(ProcessMessageError::InvalidCommit(StageCommitError::OwnCommit)) => {
                        confirmation_tag_result.map(Into::into)
                    }
                    Err(ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                        MessageDecryptionError::AeadError,
                    ))) => Ok(RejectionReason::InvalidAuthentication.into()),
                    Err(ProcessMessageError::IncompatibleWireFormat) => {
                        Ok(RejectionReason::IncompatibleWireFormat.into())
                    }

                    // everything else gets a generic wrapping
                    Err(err) => Err(OpenMlsError::wrap("processing message")(err).into()),
                }
            },
            // only outcomes producing a message with content actually mutate the group
            |outcome| !matches!(outcome, ProcessedMessage::Content(_)),
        )
        .await
}
