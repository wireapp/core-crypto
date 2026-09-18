/// An identity operation failed.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Error(#[from] x509_cert::der::Error);
