use openmls::{
    framing::errors::{MessageDecryptionError, SecretTreeError},
    prelude::{ContentType, ProcessMessageError, ProcessedMessage, ValidationError},
};

use crate::{
    OpenMlsError,
    mls::conversation::{ConversationMut, Error, Result, config::MAX_FUTURE_EPOCHS, mutable::decrypt::ParsedMessage},
};

/// Process a parsed message. This is the step which actually performs decryption.
pub(super) async fn process_message(
    conversation: &mut ConversationMut,
    ParsedMessage {
        is_duplicate,
        protocol_message,
        content_type,
    }: ParsedMessage,
) -> Result<ProcessedMessage> {
    let msg_epoch = protocol_message.epoch().as_u64();
    let backend = conversation.crypto_provider().await?;
    conversation
        .mutate_group(async move |_, group, _| {
            let group_epoch = group.epoch().as_u64();
            let processed_msg = match group.process_message(&backend, protocol_message).await {
                // processing message went well
                Ok(processed) => Ok(processed),

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
                    // we pass it back inside the error.
                    Err(Error::BufferedFutureMessage {
                        message_epoch: msg_epoch,
                    })
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
                Err(ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::AeadError,
                ))) => Err(Error::DecryptionError),

                // everything else gets a generic wrapping
                Err(err) => Err(OpenMlsError::wrap("processing message")(err).into()),
            }?;
            if is_duplicate {
                return Err(Error::DuplicateMessage);
            }
            Ok(processed_msg)
        })
        .await
}
