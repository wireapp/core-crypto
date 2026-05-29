mod qualified;
use std::{
    borrow::{Borrow, Cow},
    fmt,
    ops::Deref,
};

// use base64::Engine as _;
pub use qualified::QualifiedClientId;
use uuid::Uuid;

use super::error::{Error, Result};

/// A Client identifier
///
/// A unique identifier for clients. A client is an identifier for each App a user is using, such as desktop,
/// mobile, etc. Users can have multiple clients.
/// More information [here](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html#name-group-members-and-clients)
#[derive(
    core_crypto_macros::Debug, Clone, Eq, PartialOrd, Ord, Hash, derive_more::Into, serde::Serialize, serde::Deserialize,
)]
#[sensitive]
pub struct ClientId(Vec<u8>);

pub struct SerializedClientId {
    pub user_id: Uuid,
    pub device_id: String,
    pub domain: String,
}

impl ClientId {
    /// user-id & device-id separator
    pub const DELIMITER: &'static str = ":";

    pub fn new(user_id: &str, device_id: &str, domain: &str) -> Result<Self> {
        let delimiter = Self::DELIMITER;
        let string = format!("{user_id}{delimiter}{device_id}@{domain}");
        let bytes = string.into_bytes();
        Self::try_parse_bytes(&bytes)?;
        Ok(Self(bytes))
    }

    pub fn serialize(&self) -> SerializedClientId {
        let (user_id, device_id, domain) =
            Self::try_parse_bytes(&self.0).expect("We verified that this works upon initialization");

        SerializedClientId {
            user_id,
            device_id: format!("{:x}", device_id),
            domain,
        }
    }

    pub(crate) fn new_from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Self::try_parse_bytes(&bytes)?;
        Ok(Self(bytes))
    }

    fn try_parse_bytes(bytes: &[u8]) -> Result<(Uuid, u64, String)> {
        let client_id = std::str::from_utf8(bytes).map_err(|_| Error::InvalidQualifiedClientId)?;
        let (user_id, rest) = client_id
            .split_once(Self::DELIMITER)
            .ok_or(Error::InvalidQualifiedClientId)?;
        let user_id = Self::parse_user_id(user_id)?;
        let (device_id, domain) = rest.split_once('@').ok_or(Error::InvalidQualifiedClientId)?;
        let device_id = Self::parse_device_id(device_id)?;
        Ok((user_id, device_id, domain.to_owned()))
    }

    /// Parse the user id, assuming string representation of a UUIDv4.
    /// TODO(SimonThormeyer): Should this be the base64-encoded string instead?
    fn parse_user_id(user_id: &str) -> Result<Uuid> {
        // let user_id = base64::prelude::BASE64_URL_SAFE_NO_PAD
        //     .decode(user_id)
        //     .map_err(|_| Error::InvalidQualifiedClientId)?;
        let uuid = Uuid::try_parse(&user_id).map_err(|_| Error::InvalidQualifiedClientId)?;
        Ok(uuid)
    }

    fn parse_device_id(device_id: &str) -> Result<u64> {
        u64::from_str_radix(device_id, 16).map_err(|_| Error::InvalidQualifiedClientId)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl TryFrom<&[u8]> for ClientId {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::try_parse_bytes(&value)?;
        Ok(Self(value.into()))
    }
}

impl TryFrom<Box<[u8]>> for ClientId {
    type Error = Error;

    fn try_from(value: Box<[u8]>) -> Result<Self> {
        value.try_into()
    }
}

impl<const N: usize> TryFrom<[u8; N]> for ClientId {
    type Error = Error;

    fn try_from(value: [u8; N]) -> Result<Self> {
        value.try_into()
    }
}

impl From<ClientId> for Box<[u8]> {
    fn from(value: ClientId) -> Self {
        value.0.into_boxed_slice()
    }
}

impl Deref for ClientId {
    type Target = ClientIdRef;

    fn deref(&self) -> &Self::Target {
        ClientIdRef::new(&self.0)
    }
}

impl AsRef<[u8]> for ClientId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<ClientIdRef> for ClientId {
    fn as_ref(&self) -> &ClientIdRef {
        ClientIdRef::new(&self.0)
    }
}

impl From<ClientId> for Cow<'_, [u8]> {
    fn from(value: ClientId) -> Self {
        Cow::Owned(value.0)
    }
}

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_slice()))
    }
}

impl std::str::FromStr for ClientId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(hex::decode(s).unwrap_or_else(|_| s.as_bytes().to_vec())))
    }
}

impl<T> PartialEq<T> for ClientId
where
    ClientIdRef: PartialEq<T>,
{
    fn eq(&self, other: &T) -> bool {
        (**self).eq(other)
    }
}

#[cfg(test)]
impl From<&str> for ClientId {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().into())
    }
}

/// Reference to a [`ClientId`].
///
/// This type is `!Sized` and is only ever seen as a reference, like `str` or `[u8]`.
//
// pattern from https://stackoverflow.com/a/64990850
#[repr(transparent)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, derive_more::Deref)]
pub struct ClientIdRef([u8]);

impl ClientIdRef {
    /// Creates a `ClientId` Ref, needed to implement `Borrow<ClientIdRef>` for `T`
    pub fn new<Bytes>(bytes: &Bytes) -> &ClientIdRef
    where
        Bytes: AsRef<[u8]> + ?Sized,
    {
        // safety: because of `repr(transparent)` we know that `ClientIdRef` has a memory layout
        // identical to `[u8]`, so we can perform this cast
        unsafe { &*(bytes.as_ref() as *const [u8] as *const ClientIdRef) }
    }

    /// View this reference as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}

impl<'a> From<&'a [u8]> for &'a ClientIdRef {
    fn from(value: &'a [u8]) -> Self {
        ClientIdRef::new(value)
    }
}

impl<'a> From<&'a Vec<u8>> for &'a ClientIdRef {
    fn from(value: &'a Vec<u8>) -> Self {
        ClientIdRef::new(value.as_slice())
    }
}

impl Borrow<ClientIdRef> for ClientId {
    fn borrow(&self) -> &ClientIdRef {
        ClientIdRef::new(&self.0)
    }
}

impl Borrow<ClientIdRef> for &'_ ClientId {
    fn borrow(&self) -> &ClientIdRef {
        ClientIdRef::new(&*self.0)
    }
}

impl ToOwned for ClientIdRef {
    type Owned = ClientId;

    fn to_owned(&self) -> Self::Owned {
        ClientId(self.0.to_owned())
    }
}

impl AsRef<[u8]> for ClientIdRef {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a ClientIdRef> for Cow<'a, [u8]> {
    fn from(value: &'a ClientIdRef) -> Self {
        Cow::Borrowed(value.as_ref())
    }
}

impl PartialEq<ClientId> for ClientIdRef {
    fn eq(&self, other: &ClientId) -> bool {
        &self.0 == other.as_slice()
    }
}

impl PartialEq<[u8]> for ClientIdRef {
    fn eq(&self, other: &[u8]) -> bool {
        &self.0 == other
    }
}

impl PartialEq<&'_ [u8]> for ClientIdRef {
    fn eq(&self, other: &&'_ [u8]) -> bool {
        &self.0 == *other
    }
}

impl std::fmt::Display for ClientIdRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

macro_rules! impl_eq {
    ($( $t:ty => |$self:ident, $other:ident| $impl:expr ; )+) => {
        $(
            impl PartialEq<$t> for ClientIdRef {
                fn eq(&self, other: &$t) -> bool {
                    let $self = self;
                    let $other = other;
                    $impl
                }
            }

            impl PartialEq<ClientIdRef> for $t {
                fn eq(&self, other: &ClientIdRef) -> bool {
                    other.eq(self)
                }
            }

            impl PartialEq<$t> for &'_ ClientIdRef {
                fn eq(&self, other: &$t) -> bool {
                    let $self = self;
                    let $other = other;
                    $impl
                }
            }

            impl PartialEq<&'_ ClientIdRef> for $t {
                fn eq(&self, other: &&'_ ClientIdRef) -> bool {
                    other.eq(self)
                }
            }
        )+
    };
}

impl_eq!(
    Vec<u8> => |me, other| me.0.eq(other.as_slice());
    Cow<'_, ClientIdRef> => |me, other| me.eq(&other.as_slice());
);

// we can't use `core_crypto_macros::Debug` to generate this because `ClientIdRef: !Sized`,
// and the `log` crate maintainers did not explicitly opt-in to allowing `!Sized` in their
// `Value::from_debug` impl, even though it might make sense to.
//
// this has the consequence that we can't natively log a `ClientIdRef` as a value;
// if we want to, we have to do `id_ref.to_owned()`. Which might be ok.
impl fmt::Debug for ClientIdRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ClientIdRef")
            .field(&obfuscate::Obfuscated::from(&self.0))
            .finish()
    }
}

type LegacyClientId = wire_e2e_identity::legacy::id::ClientId;

impl From<ClientId> for LegacyClientId {
    fn from(value: ClientId) -> Self {
        Self::from(value.0)
    }
}
#[cfg(test)]
impl ClientId {
    pub(crate) fn to_user_id(&self) -> String {
        let self_bytes: &[u8] = &self.0;
        wire_e2e_identity::legacy::id::WireQualifiedClientId::try_from(self_bytes)
            .unwrap()
            .get_user_id()
    }

    pub(crate) fn to_string_triple(&self) -> [String; 3] {
        let cid = wire_e2e_identity::legacy::id::ClientId::from(self.0.clone());
        let qualified_id = wire_e2e_identity::legacy::id::QualifiedE2eiClientId::from(cid);
        let id_string: String = qualified_id.try_into().unwrap();
        [id_string, "".into(), self.to_user_id()]
    }
}
