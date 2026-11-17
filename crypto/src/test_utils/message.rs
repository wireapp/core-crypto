use openmls::{
    framing::MlsMessageInBody,
    prelude::{GroupEpoch, MlsMessageIn, MlsMessageOut, group_info::VerifiableGroupInfo},
};

pub trait MessageExt {
    fn epoch(&self) -> Option<GroupEpoch>;
    fn group_info(&self) -> Option<VerifiableGroupInfo>;
}

impl MessageExt for MlsMessageOut {
    fn epoch(&self) -> Option<GroupEpoch> {
        let msg_in = MlsMessageIn::from(self.clone());
        match msg_in.extract() {
            MlsMessageInBody::PublicMessage(m) => Some(m.epoch()),
            MlsMessageInBody::PrivateMessage(m) => Some(m.epoch()),
            _ => None,
        }
    }

    fn group_info(&self) -> Option<VerifiableGroupInfo> {
        let msg_in = MlsMessageIn::from(self.clone());
        match msg_in.extract() {
            MlsMessageInBody::GroupInfo(vgi) => Some(vgi),
            _ => None,
        }
    }
}

/// Helpers for the list of messages returned by `ConversationMut::decrypt_message`.
pub trait DecryptedMessagesExt {
    /// Take the only decrypted message.
    ///
    /// Panics unless there is exactly one outcome, which is a decryption.
    fn into_single_decrypted(self) -> crate::DecryptedMessage;

    /// Take the reason the input message was deferred.
    ///
    /// Panics unless there is exactly one outcome, and it is a deferral.
    fn into_single_deferred(self) -> crate::DeferralReason;

    /// Take the reason that the input message was rejected.
    ///
    /// Panics unless there is exactly one outcome, and it is a rejection.
    fn into_single_rejected(self) -> crate::RejectionReason;
}

impl DecryptedMessagesExt for Vec<crate::DecryptionOutcome> {
    #[track_caller]
    fn into_single_decrypted(self) -> crate::DecryptedMessage {
        let len = self.len();
        let Ok([outcome]) = <[_; 1]>::try_from(self) else {
            panic!("expected exactly one decryption outcome, but got {len}");
        };
        let crate::DecryptionOutcome::Decrypted(message) = outcome else {
            dbg!(&outcome);
            panic!("expected a decrypted message but got another outcome");
        };
        message
    }

    #[track_caller]
    fn into_single_deferred(self) -> crate::DeferralReason {
        let len = self.len();
        let Ok([outcome]) = <[_; 1]>::try_from(self) else {
            panic!("expected exactly one decryption outcome, but got {len}");
        };
        let crate::DecryptionOutcome::Deferred(reason) = outcome else {
            dbg!(&outcome);
            panic!("expected a deferral reason but got another outcome");
        };
        reason
    }

    #[track_caller]
    fn into_single_rejected(self) -> crate::RejectionReason {
        let len = self.len();
        let Ok([outcome]) = <[_; 1]>::try_from(self) else {
            panic!("expected exactly one decryption outcome, but got {len}");
        };
        let crate::DecryptionOutcome::Rejected(reason) = outcome else {
            dbg!(&outcome);
            panic!("expected a rejection reason but got another outcome");
        };
        reason
    }
}

/// Helpers for a single outcome returned by `ConversationMut::decrypt_message`.
pub trait DecryptionOutcomeExt {
    /// The decrypted message, if the message was decrypted.
    fn as_decrypted(&self) -> Option<&crate::DecryptedMessage>;

    /// Take the decrypted message.
    ///
    /// Panics if the message was not decrypted.
    fn into_decrypted(self) -> crate::DecryptedMessage;
}

impl DecryptionOutcomeExt for crate::DecryptionOutcome {
    fn as_decrypted(&self) -> Option<&crate::DecryptedMessage> {
        match self {
            crate::DecryptionOutcome::Decrypted(message) => Some(message),
            _ => None,
        }
    }

    #[track_caller]
    fn into_decrypted(self) -> crate::DecryptedMessage {
        match self {
            crate::DecryptionOutcome::Decrypted(message) => message,
            other => panic!("expected a decrypted message, but got {other:?}"),
        }
    }
}
