/// Owned key shared by the targeted and transient message receive counters.
#[derive(Clone, Debug, Hash, PartialEq, Eq, derive_more::Constructor)]
pub struct MessageRxCounterPk {
    pub(super) conversation_id: Vec<u8>,
    pub(super) sender_idx: u32,
    pub(super) epoch: u64,
}

/// Borrowed form of [`MessageRxCounterPk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, derive_more::Constructor)]
pub struct MessageRxCounterPkRef<'a> {
    pub(super) conversation_id: &'a [u8],
    pub(super) sender_idx: u32,
    pub(super) epoch: u64,
}

impl From<MessageRxCounterPkRef<'_>> for MessageRxCounterPk {
    fn from(key: MessageRxCounterPkRef<'_>) -> Self {
        Self::new(key.conversation_id.to_vec(), key.sender_idx, key.epoch)
    }
}
