use crate::entities::{ConversationId, ConversationIdRef};

/// Owned key shared by the targeted and transient message receive counters.
#[derive(Clone, Debug, Hash, PartialEq, Eq, derive_more::Constructor)]
pub struct MessageRxCounterPk {
    pub(super) conversation_id: ConversationId,
    pub(super) sender_idx: u32,
    pub(super) epoch: u64,
}

/// Borrowed form of [`MessageRxCounterPk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, derive_more::Constructor)]
pub struct MessageRxCounterPkRef<'a> {
    pub(super) conversation_id: &'a ConversationIdRef,
    pub(super) sender_idx: u32,
    pub(super) epoch: u64,
}

impl From<MessageRxCounterPkRef<'_>> for MessageRxCounterPk {
    fn from(key: MessageRxCounterPkRef<'_>) -> Self {
        Self::new(key.conversation_id.into(), key.sender_idx, key.epoch)
    }
}
