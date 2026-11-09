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
    /// Panics unless there is exactly one: either the input message was deferred, or it unblocked some buffered
    /// messages which were decrypted along with it.
    fn into_single(self) -> crate::DecryptedMessage;
}

impl DecryptedMessagesExt for Vec<crate::DecryptedMessage> {
    #[track_caller]
    fn into_single(self) -> crate::DecryptedMessage {
        let len = self.len();
        let Ok([message]) = <[_; 1]>::try_from(self) else {
            panic!("expected exactly one decrypted message, but got {len}");
        };
        message
    }
}
