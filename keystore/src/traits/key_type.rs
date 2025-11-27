use std::borrow::Cow;

/// A Key Type is a type which can act as a key for a database.
///
/// This might be a primary key, in which case the key uniquely identifies either 0 or 1 entries in the database.
/// Or it might be a search key, in which case the key could match any number of entries.
pub trait KeyType: Send + Sync {
    /// Get a unique binary representation of this key.
    ///
    /// For simple keys it can just be the borrowed form of the key itself,
    /// but for complex keys it could be the run length encoding of each field of the key.
    fn bytes(&self) -> Cow<'_, [u8]>;
}

macro_rules! impl_keytype {
    ($t:ty, |$self:ident| $impl:expr) => {
        impl KeyType for $t {
            fn bytes(&$self) -> Cow<'_, [u8]> {
                $impl.into()
            }
        }
    };
}

impl_keytype!(&[u8], |self| *self);
impl_keytype!(Vec<u8>, |self| self.as_slice());
impl_keytype!(&str, |self| self.as_bytes());
impl_keytype!(String, |self| self.as_bytes());

macro_rules! impl_keytype_for_integer {
    ($t:ty) => {
        impl KeyType for $t {
            fn bytes(&self) -> Cow<'_, [u8]> {
                Vec::from(self.to_le_bytes()).into()
            }
        }
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
