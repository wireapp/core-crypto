use std::error::Error;

use core_crypto::RejectionReason as CcRejectionReason;

/// A reason why this message could not be decrypted.
#[derive(Debug, uniffi::Enum)]
pub enum RejectionReason {
    /// This message has already been processed, or replays a message which has.
    DuplicateMessage,
    /// This commit is for an epoch which this conversation has already moved past.
    StaleCommit,
    /// This proposal is for an epoch which this conversation has already moved past.
    StaleProposal,
    /// This message is from an epoch whose secrets are no longer available.
    ///
    /// This includes transient messages from any epoch older than the current one.
    MessageEpochTooOld {
        /// Epoch of the message
        message_epoch: u64,
        /// Epoch of the group
        group_epoch: u64,
    },
    /// This message is from an epoch too far in the future to buffer.
    UnbufferedFarFutureMessage {
        /// Epoch of the message
        message_epoch: u64,
        /// Epoch of the group
        group_epoch: u64,
    },
    /// This message's ciphertext failed authentication, so it could not be decrypted.
    ///
    /// The ciphertext may have been corrupted or tampered with, or encrypted with keys we don't have.
    /// Authenticated encryption deliberately doesn't distinguish between these.
    InvalidAuthentication,
    /// This message could not be deserialized.
    Unparseable {
        /// What specifically could not be parsed.
        reason: String,
    },
    /// This message is valid MLS, but not a public or private message, so it cannot be decrypted.
    ///
    /// For example, a welcome or a key package.
    InappropriateMessageBodyType,
    /// This message uses a protocol version we don't support.
    UnsupportedProtocolVersion,
    /// This message uses a wire format which the conversation's wire format policy doesn't allow.
    IncompatibleWireFormat,
    /// This message's signature doesn't match its sender's signature key.
    InvalidSignature,
    /// The sender's X509 certificate chain could not be parsed.
    MalformedCredential {
        /// What went wrong when attempting to parse the certificate chain.
        error: String,
    },
    /// The sender's X509 certificate chain is not correctly signed.
    UntrustedCredential {
        /// What went wrong when validating the signatures of the certificate chain.
        error: String,
    },
    /// This message belongs to a different conversation.
    WrongGroupId,
    /// This message's sender is not a member of the conversation in the message's epoch.
    UnknownMember,
    /// This targeted message is addressed to a different member of the conversation.
    WrongRecipient,
    /// This public message's membership tag is missing or invalid.
    InvalidMembershipTag,
    /// This message comes from an external sender not authorized in this conversation.
    UnauthorizedExternalSender,
    /// This external proposal is of a type which external senders may not send.
    UnsupportedProposalType,
    /// This commit's confirmation tag doesn't match the one we computed.
    ///
    /// Either the commit is invalid, or our view of the conversation has diverged from the sender's.
    ConfirmationTagMismatch,
}

impl From<CcRejectionReason> for RejectionReason {
    fn from(value: CcRejectionReason) -> Self {
        match value {
            CcRejectionReason::Unparseable(tls_codec_error) => {
                let reason = format!(
                    "{tls_codec_error}: {}",
                    tls_codec_error.source().expect("tls codec error always has a source")
                );
                Self::Unparseable { reason }
            }
            CcRejectionReason::MalformedCredential(credential_error) => Self::MalformedCredential {
                error: credential_error.to_string(),
            },
            CcRejectionReason::UntrustedCredential(crypto_error) => Self::UntrustedCredential {
                error: crypto_error.to_string(),
            },
            CcRejectionReason::DuplicateMessage => Self::DuplicateMessage,
            CcRejectionReason::StaleCommit => Self::StaleCommit,
            CcRejectionReason::StaleProposal => Self::StaleProposal,
            CcRejectionReason::MessageEpochTooOld {
                message_epoch,
                group_epoch,
            } => Self::MessageEpochTooOld {
                message_epoch,
                group_epoch,
            },
            CcRejectionReason::UnbufferedFarFutureMessage {
                message_epoch,
                group_epoch,
            } => Self::UnbufferedFarFutureMessage {
                message_epoch,
                group_epoch,
            },
            CcRejectionReason::InvalidAuthentication => Self::InvalidAuthentication,
            CcRejectionReason::InappropriateMessageBodyType => Self::InappropriateMessageBodyType,
            CcRejectionReason::UnsupportedProtocolVersion => Self::UnsupportedProtocolVersion,
            CcRejectionReason::IncompatibleWireFormat => Self::IncompatibleWireFormat,
            CcRejectionReason::InvalidSignature => Self::InvalidSignature,
            CcRejectionReason::WrongGroupId => Self::WrongGroupId,
            CcRejectionReason::UnknownMember => Self::UnknownMember,
            CcRejectionReason::WrongRecipient => Self::WrongRecipient,
            CcRejectionReason::InvalidMembershipTag => Self::InvalidMembershipTag,
            CcRejectionReason::UnauthorizedExternalSender => Self::UnauthorizedExternalSender,
            CcRejectionReason::UnsupportedProposalType => Self::UnsupportedProposalType,
            CcRejectionReason::ConfirmationTagMismatch => Self::ConfirmationTagMismatch,
        }
    }
}
