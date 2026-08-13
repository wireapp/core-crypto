/// Type-safe reference to a conversation id.
///
/// [`MlsPendingMessage`][crate::entities::MlsPendingMessage]s are keyed individually by a hash of their contents, but
/// callers almost always want every buffered message of one conversation at once. This type is the search key
/// which makes that possible.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, derive_more::From, derive_more::Into, derive_more::Deref,
)]
#[deref(forward)]
pub struct ConversationId(Vec<u8>);
