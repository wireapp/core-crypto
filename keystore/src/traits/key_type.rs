use std::{
    any::Any,
    borrow::Cow,
    fmt,
    hash::{Hash, Hasher},
};

/// A dynamic identity type for our entities.
///
/// `EntityId` is mostly sufficient as a table name plus an `Arc<dyn Any>`.
/// But it needs some utility traits in order to accommodate our use cases,
/// and we can't derive or manually implement them on their own precisely because
/// the relevant type has been erased.
///
/// This trait bridges the gap by providing dyn-compatible helpers.
/// There's a blanket impl for every possible valid type.
pub trait DynEntityId: Any + Send + Sync + fmt::Debug {
    /// dyn-compatible hash implementation. Prefer the normal `hash` implemenation where possible.
    //
    // The `Hash` trait is bounded on a `H: Hasher` type parameter.
    // That's not dyn-compatible, so we have to delegate to it with this function.
    fn dyn_hash(&self, state: &mut dyn Hasher);
    /// dyn-compatible equality implementation. Prefer the normal `==` implementation where possible.
    fn dyn_eq(&self, other: &dyn DynEntityId) -> bool;
}

impl<T> DynEntityId for T
where
    T: Any + Send + Sync + fmt::Debug + Hash + Eq,
{
    fn dyn_hash(&self, mut state: &mut dyn Hasher) {
        // the double-`mut` on `state` is not accidental: we need the state itself
        // to be mutable so we can mutably borrow it. We need the mutable reference
        // to satisfy the hasher trait. Deref coersion makes everything line up.
        self.hash(&mut state);
    }

    fn dyn_eq(&self, other: &dyn DynEntityId) -> bool {
        (other as &dyn Any)
            .downcast_ref::<T>()
            .is_some_and(|other| self == other)
    }
}

/// A Key Type is a type which can act as a key for a database.
///
/// This might be a primary key, in which case the key uniquely identifies either 0 or 1 entries in the database.
/// Or it might be a search key, in which case the key could match any number of entries.
pub trait KeyType: Send + Sync + Sized {
    /// Get a unique binary representation of this key.
    ///
    /// For simple keys it can just be the borrowed form of the key itself,
    /// but for complex keys it could be the run length encoding of each field of the key.
    fn bytes(&self) -> Cow<'_, [u8]>;
}

/// An owned key type can be converted to from arbitrary bytes.
pub trait OwnedKeyType: 'static + KeyType {
    /// Parse some bytes into an instance of this type.
    ///
    /// We're just going with `Option` instead of `CryptoKeystoreResult` for now because
    /// the hopeful assumption is that this is going to be a rare occurrence that doesn't
    /// need much explanation.
    fn from_bytes(bytes: &[u8]) -> Option<Self>;
}

macro_rules! impl_keytype {
    ($t:ty, |$self:ident| $bytes:expr) => {
        impl KeyType for $t {
            fn bytes(&$self) -> Cow<'_, [u8]> {
                $bytes.into()
            }
        }
    };
    ($t:ty, |$self:ident| $bytes:expr, |$bytes_id:ident| $from_bytes:expr) => {
        impl_keytype!($t, |$self| $bytes);

        impl OwnedKeyType for $t {
            fn from_bytes($bytes_id: &[u8]) -> Option<Self> {
                $from_bytes
            }
        }
    };


}

// useful for unique entities; non-allocating
impl_keytype!((), |self| Vec::new(), |bytes| bytes.is_empty().then_some(()));
impl_keytype!(&[u8], |self| *self);
impl_keytype!(Vec<u8>, |self| self.as_slice(), |bytes| Some(bytes.into()));
impl_keytype!(&str, |self| self.as_bytes());
impl_keytype!(String, |self| self.as_bytes(), |bytes| str::from_utf8(bytes)
    .ok()
    .map(ToOwned::to_owned));

macro_rules! impl_keytype_for_integer {
    ($t:ty) => {
        impl_keytype!($t, |self| Vec::from(self.to_le_bytes()), |bytes| {
            let array = bytes.try_into().ok()?;
            Some(<$t>::from_le_bytes(array))
        });
    };
}

impl_keytype_for_integer!(u8);
impl_keytype_for_integer!(u16);
impl_keytype_for_integer!(u32);
impl_keytype_for_integer!(u64);
impl_keytype_for_integer!(u128);
impl_keytype_for_integer!(i8);
impl_keytype_for_integer!(i16);
impl_keytype_for_integer!(i32);
impl_keytype_for_integer!(i64);
impl_keytype_for_integer!(i128);
