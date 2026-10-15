use crate::ancillary::ConversationIdRef;

/// Some data, e.g., [`TntSecret`][crate::entities::mls::TntSecret]s, need to be cleaned up if they belong to a
/// conversation epoch that is older than a given epoch. To enable this, `SearchableEntity` is implemented with this
/// search key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_more::Constructor)]
pub struct ConversationEpochsOlderThan<'a> {
    pub(crate) conversation_id: &'a ConversationIdRef,
    pub(crate) epoch: u64,
}
