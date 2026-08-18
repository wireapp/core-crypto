// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

pub(crate) type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("credential not found")]
    CredentialNotFound,
    #[error(transparent)]
    Keystore(#[from] crate::KeystoreError),
    #[error(transparent)]
    Recursive(#[from] crate::RecursiveError),
    #[error("TLS deserializing {item}")]
    TlsDeserialize {
        #[source]
        source: tls_codec::Error,
        item: &'static str,
    },
}

impl Error {
    pub fn tls_deserialize(item: &'static str) -> impl FnOnce(tls_codec::Error) -> Self {
        move |source| Self::TlsDeserialize { source, item }
    }
}
