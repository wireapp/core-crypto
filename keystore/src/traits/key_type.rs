use std::borrow::Cow;

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

/// Some unique entities use a single byte as a key type
impl_keytype!([u8; 1], |self| self, |bytes| bytes.try_into().ok());
