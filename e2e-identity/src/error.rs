/// Wrapper over a [Result] with a [RustyAcmeError] error
pub type E2eIdentityResult<T> = Result<T, E2eIdentityError>;

/// All e2e identity related errors
#[derive(Debug, thiserror::Error)]
pub enum E2eIdentityError {
    /// Json error
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    /// Acme error
    #[error(transparent)]
    AcmeError(#[from] rusty_acme::prelude::RustyAcmeError),
    /// Error creating the client Dpop token
    #[error(transparent)]
    JwtError(#[from] rusty_jwt_tools::prelude::RustyJwtError),
    /// Core JWT error
    #[error(transparent)]
    JwtSimpleError(#[from] jwt_simple::Error),
}
