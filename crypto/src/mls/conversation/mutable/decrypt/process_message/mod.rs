mod protocol_message_ext;

use openmls::{
    framing::errors::{MessageDecryptionError, SecretTreeError},
    prelude::{
        ConfirmationTag, ContentType, MlsMessageIn, MlsMessageInBody, ProcessMessageError,
        ProcessedMessage as MlsProcessedMessage, ProtocolMessage, StageCommitError, ValidationError,
    },
};

use self::protocol_message_ext::ProtocolMessageExt as _;
use crate::{
    OpenMlsError,
    mls::conversation::{ConversationMut, Error, Result, config::MAX_FUTURE_EPOCHS},
};

/// A reason why processing this message had to be deferred
pub(super) enum DeferralReason {
    /// Message comes from a future epoch and can be processed once we arrive in that epoch
    FutureEpoch { epoch: u64 },
    /// Message attempts to commit a proposal by reference, but we have not yet received the referenced proposal
    MissingProposal,
}

/// Outcome of processing a message
#[derive(derive_more::From)]
pub(super) enum ProcessedMessage {
    Content(MlsProcessedMessage),
    OwnCommit(ConfirmationTag),
    Deferred(DeferralReason),
}

/// Parse and process a message. This is the step which actually performs decryption.
pub(super) async fn process_message(
    conversation: &mut ConversationMut,
    message: MlsMessageIn,
) -> Result<ProcessedMessage> {
    // Parse the incoming message
    let protocol_message: ProtocolMessage = match message.extract() {
        MlsMessageInBody::PublicMessage(public_message_in) => public_message_in.into(),
        MlsMessageInBody::PrivateMessage(private_message_in) => private_message_in.into(),
        _ => {
            return Err(
                OpenMlsError::wrap("parsing inbound message")(ProcessMessageError::IncompatibleWireFormat).into(),
            );
        }
    };

    let is_duplicate = protocol_message.is_duplicate(conversation).await?;
    let msg_epoch = protocol_message.epoch().as_u64();
    let content_type = protocol_message.content_type();
    // we need to compute the confirmation tag now, but it's only relevant in a particular case of processing the
    // message, so don't propagate the error yet.
    let confirmation_tag_result = protocol_message
        .own_commit_confirmation_tag(conversation.group().await.own_leaf_index())
        .map(ToOwned::to_owned);

    let backend = conversation.crypto_provider().await?;
    conversation
        .mutate_group(async move |_, group, _| {
            let group_epoch = group.epoch().as_u64();

            match group.process_message(&backend, protocol_message).await {
                // now that openmls has handled the message, we can return the duplicate message error
                Ok(_) if is_duplicate => Err(Error::DuplicateMessage),
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
                Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch)) if is_duplicate => {
                    Err(Error::DuplicateMessage)
                }
                Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch))
                    if msg_epoch > group_epoch && msg_epoch <= group_epoch.saturating_add(MAX_FUTURE_EPOCHS) =>
                {
                    // limit to next epoch otherwise if we were buffering a commit for epoch + 2
                    // we would fail when trying to decrypt it in [MlsCentral::commit_accepted]

                    // We need to buffer the message until the group has advanced to the right
                    // epoch. We can't do that here--we don't have the appropriate data in scope
                    // --but we can at least produce the proper error and return that, so our
                    // caller can handle it. Our caller needs to know about the epoch number, so
                    // we pass it back inside the deferral.
                    Ok(ProcessedMessage::Deferred(DeferralReason::FutureEpoch {
                        epoch: msg_epoch,
                    }))
                }
                Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch)) if msg_epoch < group_epoch => {
                    match content_type {
                        ContentType::Application => Err(Error::MessageEpochTooOld),
                        ContentType::Commit => Err(Error::StaleCommit),
                        ContentType::Proposal => Err(Error::StaleProposal),
                    }
                }
                Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch)) => {
                    Err(Error::UnbufferedFarFutureMessage)
                }
                Err(ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast),
                ))) => Err(Error::MessageEpochTooOld),

                // other errors we care to unpack
                Err(ProcessMessageError::InvalidCommit(StageCommitError::MissingProposal)) => {
                    Ok(ProcessedMessage::Deferred(DeferralReason::MissingProposal))
                }
                Err(ProcessMessageError::InvalidCommit(StageCommitError::OwnCommit)) => {
                    confirmation_tag_result.map(Into::into)
                }
                Err(ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::AeadError,
                ))) => Err(Error::DecryptionError),

                // everything else gets a generic wrapping
                Err(err) => Err(OpenMlsError::wrap("processing message")(err).into()),
            }
        })
        .await
}
