mod decrypted_message;
mod deferral_reason;
mod rejection_reason;

use core_crypto::DecryptionOutcome as CcDecryptionOutcome;

pub use self::{
    decrypted_message::DecryptedMessage, deferral_reason::DeferralReason, rejection_reason::RejectionReason,
};

/// Outcome of attempting to decrypt a message.
#[derive(Debug, derive_more::From, uniffi::Enum)]
pub enum DecryptionOutcome {
    /// The message was successfully decrypted.
    Decrypted {
        /// The decrypted message.
        decrypted_message: DecryptedMessage,
    },
    /// The message could not be processed yet, but is expected to be processable in the future.
    Deferred {
        /// The reason the message needed to be deferred.
        deferral_reason: DeferralReason,
    },
    /// The message could not be processed.
    ///
    /// This is a stable condition; reattempts will produce the same rejection in the future.
    /// Even so, this message's rejection doesn't indicate a fundamental error and is no reason
    /// to abort the transaction.
    Rejected {
        /// The reason the message was rejected.
        rejection_reason: RejectionReason,
    },
}

impl From<CcDecryptionOutcome> for DecryptionOutcome {
    fn from(value: CcDecryptionOutcome) -> Self {
        match value {
            CcDecryptionOutcome::Decrypted(decrypted_message) => DecryptedMessage::from(decrypted_message).into(),
            CcDecryptionOutcome::Deferred(deferral_reason) => DeferralReason::from(deferral_reason).into(),
            CcDecryptionOutcome::Rejected(rejection_reason) => RejectionReason::from(rejection_reason).into(),
        }
    }
}
