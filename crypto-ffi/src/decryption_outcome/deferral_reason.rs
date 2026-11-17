use core_crypto::DeferralReason as CcDeferralReason;

/// A reason why processing this message had to be deferred.
#[derive(Debug, uniffi::Enum)]
pub enum DeferralReason {
    /// Message comes from a future epoch and can be processed once we arrive in that epoch
    FutureEpoch {
        /// The epoch at which this message should become decryptable.
        epoch: u64,
    },
    /// Message attempts to commit a proposal by reference, but we have not yet received the referenced proposal
    MissingProposal,
    /// Message was delivered for a pending group which we haven't fully joined yet.
    PendingJoin,
}

impl From<CcDeferralReason> for DeferralReason {
    fn from(value: CcDeferralReason) -> Self {
        match value {
            CcDeferralReason::FutureEpoch { epoch } => Self::FutureEpoch { epoch },
            CcDeferralReason::MissingProposal => Self::MissingProposal,
            CcDeferralReason::PendingJoin => Self::PendingJoin,
        }
    }
}
