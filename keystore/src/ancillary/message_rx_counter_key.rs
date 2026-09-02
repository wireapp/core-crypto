use crate::ancillary::{ConversationId, ConversationIdRef};

/// Owned key shared by the targeted and transient message receive counters.
#[derive(Clone, Debug, Hash, PartialEq, Eq, derive_more::Constructor)]
pub struct MessageRxCounterPk {
    pub(crate) conversation_id: ConversationId,
    pub(crate) sender_idx: u32,
    pub(crate) epoch: u64,
}

/// Borrowed form of [`MessageRxCounterPk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, derive_more::Constructor)]
pub struct MessageRxCounterPkRef<'a> {
    pub(crate) conversation_id: &'a ConversationIdRef,
    pub(crate) sender_idx: u32,
    pub(crate) epoch: u64,
}

impl From<MessageRxCounterPkRef<'_>> for MessageRxCounterPk {
    fn from(key: MessageRxCounterPkRef<'_>) -> Self {
        Self::new(key.conversation_id.into(), key.sender_idx, key.epoch)
    }
}
