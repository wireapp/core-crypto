use crate::{
    Sha256Hash,
    ancillary::{ConversationId, ConversationIdRef},
};

/// Owned primary key for [`InboxMessage`][crate::entities::InboxMessage].
#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_more::Constructor)]
pub struct InboxMessagePk {
    pub(super) conversation_id: ConversationId,
    pub(super) message_hash: Sha256Hash,
}

impl InboxMessagePk {
    pub fn borrow(&self) -> InboxMessagePkRef<'_> {
        InboxMessagePkRef {
            conversation_id_ref: self.conversation_id.as_ref(),
            message_hash: self.message_hash,
        }
    }
}

/// Borrowed primary key for [`InboxMessage`][crate::entities::InboxMessage].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, derive_more::Constructor)]
pub struct InboxMessagePkRef<'a> {
    pub(super) conversation_id_ref: &'a ConversationIdRef,
    pub(super) message_hash: Sha256Hash,
}

impl From<InboxMessagePkRef<'_>> for InboxMessagePk {
    fn from(value: InboxMessagePkRef<'_>) -> Self {
        Self::new(value.conversation_id_ref.into(), value.message_hash)
    }
}
