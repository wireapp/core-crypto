#[cfg(target_family = "wasm")]
use js_sys::Object;
#[cfg(target_family = "wasm")]
use wasm_bindgen::JsValue;

use core_crypto::InnermostErrorMessage as _;

#[cfg(target_family = "wasm")]
use super::wasm::{JsErrorContext, JsValueMutationExt as _};

/// MLS produces these kinds of error
#[derive(Debug, thiserror::Error)]
#[cfg_attr(target_family = "wasm", derive(strum::AsRefStr))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Error))]
#[allow(missing_docs)] // error variants are self-describing
pub enum MlsError {
    /// The byte vector included in this error variant is the raw conversation id.
    ///
    /// We cannot provide a proper `ConversationId` instance because of a uniffi bug:
    /// <https://github.com/mozilla/uniffi-rs/issues/2409>.
    #[error("Conversation already exists")]
    ConversationAlreadyExists {
        conversation_id: core_crypto::prelude::ConversationId,
    },
    #[error("We already decrypted this message once")]
    DuplicateMessage,
    #[error("Incoming message is for a future epoch. We will buffer it until the commit for that epoch arrives")]
    BufferedFutureMessage,
    #[error("Incoming message is from an epoch too far in the future to buffer.")]
    WrongEpoch,
    #[error(
        "Incoming message is a commit for which we have not yet received all the proposals. Buffering until all proposals have arrived."
    )]
    BufferedCommit,
    #[error("The epoch in which message was encrypted is older than allowed")]
    MessageEpochTooOld,
    #[error("Tried to decrypt a commit created by self which is likely to have been replayed by the DS")]
    SelfCommitIgnored,
    #[error(
        "You tried to join with an external commit but did not merge it yet. We will reapply this message for you when you merge your external commit"
    )]
    UnmergedPendingGroup,
    #[error("The received proposal is deemed stale and is from an older epoch.")]
    StaleProposal,
    #[error("The received commit is deemed stale and is from an older epoch.")]
    StaleCommit,
    /// This happens when the DS cannot flag KeyPackages as claimed or not. It this scenario, a client
    /// requests their old KeyPackages to be deleted but one has already been claimed by another client to create a Welcome.
    /// In that case the only solution is that the client receiving such a Welcome tries to join the group
    /// with an External Commit instead
    #[error(
        "Although this Welcome seems valid, the local KeyPackage it references has already been deleted locally. Join this group with an external commit"
    )]
    OrphanWelcome,
    #[error("Message rejected by the delivery service. Reason: {reason}")]
    MessageRejected { reason: String },
    #[error("{msg}")]
    Other { msg: String },
}

impl From<core_crypto::MlsError> for MlsError {
    #[inline]
    fn from(e: core_crypto::MlsError) -> Self {
        Self::Other {
            msg: e.innermost_error_message(),
        }
    }
}

#[cfg(target_family = "wasm")]
impl JsErrorContext for MlsError {
    fn get_context(&self) -> JsValue {
        let context = Object::new();
        let inner_context = Object::new();
        match &self {
            e @ MlsError::ConversationAlreadyExists { conversation_id } => {
                context.set_field("type", e.as_ref());
                inner_context.set_field(
                    "conversationId",
                    serde_wasm_bindgen::to_value(conversation_id).expect("constructing json array"),
                );
            }
            e @ (MlsError::DuplicateMessage
            | MlsError::BufferedFutureMessage
            | MlsError::WrongEpoch
            | MlsError::BufferedCommit
            | MlsError::MessageEpochTooOld
            | MlsError::SelfCommitIgnored
            | MlsError::UnmergedPendingGroup
            | MlsError::StaleProposal
            | MlsError::StaleCommit
            | MlsError::OrphanWelcome) => context.set_field("type", e.as_ref()),
            e @ MlsError::MessageRejected { reason } => {
                context.set_field("type", e.as_ref());
                inner_context.set_field("reason", reason);
            }
            e @ MlsError::Other { msg } => {
                context.set_field("type", e.as_ref());
                inner_context.set_field("msg", msg);
            }
        }
        context.set_field("context", inner_context);
        context.into()
    }
}
