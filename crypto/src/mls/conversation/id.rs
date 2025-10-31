use std::{
    borrow::{Borrow, Cow},
    ops::Deref,
};

/// A unique identifier for a group/conversation. The identifier must be unique within a client.
#[derive(
    core_crypto_macros::Debug,
    derive_more::AsRef,
    derive_more::From,
    derive_more::Into,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Clone,
)]
#[sensitive]
#[as_ref([u8])]
#[from(&[u8], Vec<u8>)]
pub struct ConversationId(Vec<u8>);

impl Borrow<ConversationIdRef> for ConversationId {
    fn borrow(&self) -> &ConversationIdRef {
        ConversationIdRef::new(&self.0)
    }
}

impl Deref for ConversationId {
    type Target = ConversationIdRef;

    fn deref(&self) -> &Self::Target {
        ConversationIdRef::new(&self.0)
    }
}

impl From<ConversationId> for Cow<'_, [u8]> {
    fn from(value: ConversationId) -> Self {
        Cow::Owned(value.0)
    }
}

impl<'a> From<&'a ConversationId> for Cow<'a, [u8]> {
    fn from(value: &'a ConversationId) -> Self {
        Cow::Borrowed(value.as_ref())
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
    pub fn new<Bytes>(bytes: &Bytes) -> &ConversationIdRef
    where
        Bytes: AsRef<[u8]> + ?Sized,
    {
        // safety: because of `repr(transparent)` we know that `ConversationIdRef` has a memory layout
        // identical to `[u8]`, so we can perform this cast
        unsafe { &*(bytes.as_ref() as *const [u8] as *const ConversationIdRef) }
    }
}

impl ConversationIdRef {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.0.to_owned()
    }
}

impl ToOwned for ConversationIdRef {
    type Owned = ConversationId;

    fn to_owned(&self) -> Self::Owned {
        ConversationId(self.0.to_owned())
    }
}

impl AsRef<[u8]> for ConversationIdRef {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a ConversationIdRef> for Cow<'a, [u8]> {
    fn from(value: &'a ConversationIdRef) -> Self {
        Cow::Borrowed(value.as_ref())
    }
}
