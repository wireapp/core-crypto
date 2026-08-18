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
    #[error(transparent)]
    Tls(#[from] crate::TlsCodecError),
}
