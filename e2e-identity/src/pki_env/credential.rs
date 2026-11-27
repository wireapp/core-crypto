//! Types for validating an MLS credential against the PKI environment.

/// A borrowed view of an MLS credential, as far as validation needs it.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CredentialRef<'a> {
    /// A basic credential, which is only an identity.
    Basic { identity: &'a [u8] },
    /// An X509 credential: a chain of DER-encoded certificates, leaf first.
    X509 { certificates: &'a [&'a [u8]] },
}

/// The outcome of validating a credential.
#[derive(Debug, derive_more::Display, Default, Clone, Copy, Eq, PartialEq)]
pub enum CredentialAuthenticationStatus {
    /// Validation couldn't reach a verdict, for example because the PKI environment isn't set up.
    #[default]
    Unknown,
    Valid,
    Invalid,
    Expired,
    Revoked,
}
