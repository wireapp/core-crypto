use core_crypto::InnermostErrorMessage as _;

#[derive(Debug, thiserror::Error)]
#[cfg_attr(target_family = "wasm", derive(strum::AsRefStr))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Error))]
pub enum MlsError {
    #[error("Conversation already exists")]
    ConversationAlreadyExists(crate::ConversationIdMaybeArc),
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
    /// Message rejected by the delivery service
    #[error("Message rejected by the delivery service. Reason: {reason}")]
    MessageRejected {
        /// Why was the message rejected by the delivery service?
        reason: String,
    },
    #[error("{0}")]
    Other(String),
}

impl From<core_crypto::MlsError> for MlsError {
    #[inline]
    fn from(e: core_crypto::MlsError) -> Self {
        Self::Other(e.innermost_error_message())
    }
}
