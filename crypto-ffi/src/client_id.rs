/// A Client identifier
///
/// A unique identifier for clients. A client is an identifier for each App a user is using, such as desktop,
/// mobile, etc. Users can have multiple clients.
/// More information [here](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html#name-group-members-and-clients)
#[derive(Debug, Clone, Eq, Hash, PartialEq, derive_more::From, uniffi::Object)]
pub struct ClientId(pub(crate) core_crypto::ClientId);

#[uniffi::export]
impl ClientId {
    /// Instantiate a client id from a byte array.
    #[uniffi::constructor]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes.into())
    }

    /// Copy the id into a new byte array.
    pub fn copy_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl AsRef<core_crypto::ClientIdRef> for ClientId {
    fn as_ref(&self) -> &core_crypto::ClientIdRef {
        core_crypto::ClientIdRef::new(&self.0)
    }
}
