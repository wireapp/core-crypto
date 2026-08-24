/// Some data, e.g., [`TntSecret`][crate::entities::mls::TntSecret]s, need to be cleaned up if they belong to a
/// conversation epoch that is older than a given epoch. To enable this, `SearchableEntity` is implemented with this
/// search key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, derive_more::Constructor)]
pub struct ConversationEpochsOlderThan {
    pub(crate) conversation_id: Vec<u8>,
    pub(crate) epoch: u64,
}
