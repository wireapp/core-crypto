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
            let processed_msg = group
                .process_message(&backend, protocol_message)
                .await
                .map_err(|e| match e {
                    ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                        MessageDecryptionError::GenerationOutOfBound,
                    )) => {
                        // This is an annoyance, but not wrong: OpenMLS knows whether the message was too old, too new,
                        // or an actual duplicate. It emits a log line and flattens all three variants into this single
                        // `GenerationOutOfBound` variant, so we can't tell what situation we're in at this level.
                        // `DuplicateMessage` is more likely than the other two, so that's what we unpack here.
                        Error::DuplicateMessage
                    }
                    ProcessMessageError::ValidationError(ValidationError::WrongEpoch) => {
                        if is_duplicate {
                            Error::DuplicateMessage
                        } else if msg_epoch > group_epoch && msg_epoch <= group_epoch.saturating_add(MAX_FUTURE_EPOCHS)
                        {
                            // limit to next epoch otherwise if we were buffering a commit for epoch + 2
                            // we would fail when trying to decrypt it in [MlsCentral::commit_accepted]

                            // We need to buffer the message until the group has advanced to the right
                            // epoch. We can't do that here--we don't have the appropriate data in scope
                            // --but we can at least produce the proper error and return that, so our
                            // caller can handle it. Our caller needs to know about the epoch number, so
                            // we pass it back inside the error.
                            Error::BufferedFutureMessage {
                                message_epoch: msg_epoch,
                            }
                        } else if msg_epoch < group_epoch {
                            match content_type {
                                ContentType::Application => Error::MessageEpochTooOld,
                                ContentType::Commit => Error::StaleCommit,
                                ContentType::Proposal => Error::StaleProposal,
                            }
                        } else {
                            Error::UnbufferedFarFutureMessage
                        }
                    }
                    ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                        MessageDecryptionError::AeadError,
                    )) => Error::DecryptionError,
                    ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                        MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast),
                    )) => Error::MessageEpochTooOld,
                    _ => OpenMlsError::wrap("processing message")(e).into(),
                })?;
            if is_duplicate {
                return Err(Error::DuplicateMessage);
            }
            Ok(processed_msg)
        })
        .await
}
