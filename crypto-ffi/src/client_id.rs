use crate::bytes_wrapper::bytes_wrapper;

bytes_wrapper!(
    /// A unique identifier for an MLS client.
    ///
    /// Each app instance a user is running, such as desktop or mobile, is a separate client
    /// with its own client id. A single user may therefore have multiple clients.
    /// More information: <https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html#name-group-members-and-clients>
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    #[uniffi::export(Eq, Hash)]
    ClientId infallibly wraps core_crypto::ClientId; copy_bytes
);

impl AsRef<core_crypto::ClientIdRef> for ClientId {
    fn as_ref(&self) -> &core_crypto::ClientIdRef {
        core_crypto::ClientIdRef::new(&self.0)
    }
}
