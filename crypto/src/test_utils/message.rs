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
}

impl DecryptedMessagesExt for Vec<crate::DecryptionOutcome> {
    #[track_caller]
    fn into_single_decrypted(self) -> crate::DecryptedMessage {
        let len = self.len();
        let Ok([crate::DecryptionOutcome::Decrypted(message)]) = <[_; 1]>::try_from(self) else {
            panic!("expected exactly one decrypted message, but got {len} outcome(s)");
        };
        message
    }

    #[track_caller]
    fn into_single_deferred(self) -> crate::DeferralReason {
        let len = self.len();
        let Ok([crate::DecryptionOutcome::Deferred(reason)]) = <[_; 1]>::try_from(self) else {
            panic!("expected exactly one deferred message, but got {len} outcome(s)");
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
