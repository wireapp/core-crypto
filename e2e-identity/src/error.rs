// We allow missing documentation in the error module because the types are generally
// self-descriptive.
#![allow(missing_docs)]

pub type E2eIdentityResult<T> = Result<T, E2eIdentityError>;

/// All e2e identity related errors
#[derive(Debug, thiserror::Error)]
pub enum E2eIdentityError {
    /// Acme error
    #[error(transparent)]
    AcmeError(#[from] crate::acme::RustyAcmeError),
    /// Error creating the client Dpop token
    #[error(transparent)]
    JwtError(#[from] rusty_jwt_tools::prelude::RustyJwtError),
    /// Core JWT error
    #[error(transparent)]
    JwtSimpleError(#[from] jwt_simple::Error),
    #[error(transparent)]
    PkiEnvError(#[from] crate::pki_env::Error),
    #[error(transparent)]
    X509Error(#[from] crate::validation::RustyX509CheckError),
}
