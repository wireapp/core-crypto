/// Wrapper over a [Result] with an ACME error
pub(crate) type Result<T> = core::result::Result<T, Error>;

/// All errors which [crate::acme] might throw
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid Json representation
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Error while building a JWT
    #[error(transparent)]
    Jwt(#[from] rusty_jwt_tools::prelude::RustyJwtError),
    /// Failed mapping an ASN.1 ObjectIdentifier
    #[error(transparent)]
    Oid(#[from] x509_cert::der::oid::Error),
    /// Failed mapping a DER certificate
    #[error(transparent)]
    Der(#[from] x509_cert::der::Error),
    /// Error while parsing a PEM document
    #[error(transparent)]
    Pem(#[from] pem::PemError),
    /// Pkcs8 error
    #[error(transparent)]
    Pkcs8(#[from] ed25519_dalek::pkcs8::Error),
    /// Error while handling a JWT
    #[error(transparent)]
    RawJwt(#[from] jwt_simple::Error),
    /// Error with hand-rolled signature
    #[error(transparent)]
    Signature(#[from] signature::Error),
    /// We have done something terribly wrong
    #[error("We have done something terribly wrong and it needs to be fixed")]
    Implementation,
    /// This library has been used the wrong way by users
    #[error("This library has been used the wrong way by users because {0}")]
    ClientImplementation(&'static str),
    /// Smallstep ACME server is not correctly implemented
    #[error("Incorrect response from ACME server because {0}")]
    SmallstepImplementation(&'static str),
    /// Error while processing an account
    #[error(transparent)]
    Account(#[from] crate::acme::account::AcmeAccountError),
    /// Error while processing an order
    #[error(transparent)]
    Order(#[from] crate::acme::order::AcmeOrderError),
    /// Error while processing an authorization
    #[error(transparent)]
    Authz(#[from] crate::acme::authz::AcmeAuthzError),
    /// Error while validating a challenge
    #[error(transparent)]
    Challenge(#[from] crate::acme::chall::AcmeChallError),
    /// Error while finalizing an order
    #[error(transparent)]
    Finalize(#[from] crate::acme::finalize::AcmeFinalizeError),
    /// UTF-8 parsing error
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
}
