use crate::ancillary::ConversationIdRef;

/// Some data, e.g., [`OldEpochData`][crate::entities::mls::OldEpochData], need to be cleaned up if they belong to a
/// conversation epoch that is greater than or equal to a given epoch. To enable this, `SearchableEntity` is implemented
/// with this search key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_more::Constructor)]
pub struct ConversationEpochsNewerThan<'a> {
    pub(crate) conversation_id: &'a ConversationIdRef,
    pub(crate) epoch: u64,
}
