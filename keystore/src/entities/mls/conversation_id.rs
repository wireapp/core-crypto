use rusqlite::{ToSql, types::ToSqlOutput};

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

impl From<&[u8]> for ConversationId {
    fn from(value: &[u8]) -> Self {
        value.to_owned().into()
    }
}

impl From<&ConversationIdRef> for ConversationId {
    fn from(value: &ConversationIdRef) -> Self {
        value.bytes().into()
    }
}

impl AsRef<ConversationIdRef> for ConversationId {
    fn as_ref(&self) -> &ConversationIdRef {
        ConversationIdRef::new(&self.0)
    }
}

impl ConversationId {
    /// Express this conversation id as a byte slice.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Reference to a ConversationId.
///
/// This type is `!Sized` and is only ever seen as a reference, like `str` or `[u8]`.
//
// pattern from https://stackoverflow.com/a/64990850
#[repr(transparent)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConversationIdRef([u8]);

impl ConversationIdRef {
    /// Creates a `ConversationId` Ref, needed to implement `Borrow<ConversationIdRef>` for `T`
    pub const fn new(bytes: &[u8]) -> &ConversationIdRef {
        // safety: because of `repr(transparent)` we know that `ConversationIdRef` has a memory layout
        // identical to `[u8]`, so we can perform this cast
        unsafe { &*(bytes as *const [u8] as *const ConversationIdRef) }
    }

    /// Express this conversation id as a byte slice.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for ConversationIdRef {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ToSql for ConversationIdRef {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        self.as_ref().to_sql()
    }
}

// Cross-type equality so that `&ConversationIdRef` can be used to look up an entry
// in a hash-keyed collection (e.g. `schnellru::LruMap<ConversationId, _>`) without
// allocating a `ConversationId`. The `Hash` derives on both types compare equal
// bytes to equal hashes, keeping these impls consistent with the `Hash` impls.
impl PartialEq<ConversationId> for ConversationIdRef {
    fn eq(&self, other: &ConversationId) -> bool {
        self.bytes() == other.bytes()
    }
}

impl PartialEq<ConversationIdRef> for ConversationId {
    fn eq(&self, other: &ConversationIdRef) -> bool {
        self.bytes() == other.bytes()
    }
}
