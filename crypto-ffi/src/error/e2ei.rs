use wire_e2e_identity::{
    AcmeError, E2eIdentityError,
    acquisition::{AcquisitionError, CertificateError},
    pki_env::{self, hooks::PkiEnvironmentHooksError},
    validation,
};

use crate::CipherSuite;

/// Errors produced by the end-to-end identity layer.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[expect(missing_docs)] // error variants are self-describing
pub enum E2eiError {
    #[error("Certificate acquisition is not supported for {cipher_suite:?}")]
    UnsupportedCipherSuite { cipher_suite: CipherSuite },
    /// One of the `PkiEnvironmentHooks` callbacks returned an error.
    #[error("A PKI environment hook failed: {reason}")]
    HookFailed { reason: String },
    #[error("HTTP response is missing header '{header}'")]
    MissingHeader { header: String },
    #[error("The trust anchor certificate couldn't be loaded from the database.")]
    NoTrustAnchor,
    #[error("The trust anchor certificate already exists in the database.")]
    TrustAnchorAlreadyExists,
    #[error("Failed to fetch CRL from '{uri}': HTTP {status}")]
    CrlFetchUnsuccessful { uri: String, status: u16 },
    /// The ACME account is invalid, revoked or deactivated.
    #[error("ACME account error: {msg}")]
    AcmeAccount { msg: String },
    /// The ACME order is invalid, not yet valid, expired, or has the wrong identifiers.
    #[error("ACME order error: {msg}")]
    AcmeOrder { msg: String },
    /// An ACME authorization or challenge failed, or the challenge is still being processed.
    #[error("ACME challenge error: {msg}")]
    AcmeChallenge { msg: String },
    /// The client ID, display name, handle or domain in the certificate is missing, malformed or
    /// does not match the expected one.
    #[error("Invalid identifier: {msg}")]
    InvalidIdentifier { msg: String },
    /// The certificate is malformed, or does not match the signing keypair.
    #[error("Invalid certificate: {msg}")]
    InvalidCertificate { msg: String },
    #[error("{msg}")]
    Other { msg: String },
}

impl E2eiError {
    fn other(err: &impl ToString) -> Self {
        Self::Other { msg: err.to_string() }
    }
}

// The matches below deliberately have no wildcard arm: a new upstream variant should force us to
// decide where it belongs, rather than silently ending up in `Other`.

impl From<&E2eIdentityError> for E2eiError {
    fn from(value: &E2eIdentityError) -> Self {
        match value {
            E2eIdentityError::UnsupportedCipherSuite(cipher_suite) => Self::UnsupportedCipherSuite {
                cipher_suite: (*cipher_suite).into(),
            },
            E2eIdentityError::AcmeError(err) => err.into(),
            E2eIdentityError::JwtError(_) | E2eIdentityError::JsonWebTokenError(_) => Self::other(value),
            E2eIdentityError::PkiEnvError(err) => err.into(),
            E2eIdentityError::ValidationError(err) => err.into(),
        }
    }
}

impl From<&AcquisitionError> for E2eiError {
    fn from(value: &AcquisitionError) -> Self {
        match value {
            AcquisitionError::UnsupportedCipherSuite(cipher_suite) => Self::UnsupportedCipherSuite {
                cipher_suite: (*cipher_suite).into(),
            },
            AcquisitionError::HookFailed(err) => err.into(),
            AcquisitionError::MissingHeader(header) => Self::MissingHeader {
                header: (*header).to_owned(),
            },
            AcquisitionError::Acme(err) => err.into(),
            AcquisitionError::InvalidCertificate(err) => err.into(),
            AcquisitionError::Json(_) | AcquisitionError::RustyJwtError(_) | AcquisitionError::JsonWebToken(_) => {
                Self::other(value)
            }
        }
    }
}

impl From<&PkiEnvironmentHooksError> for E2eiError {
    fn from(value: &PkiEnvironmentHooksError) -> Self {
        Self::HookFailed {
            reason: value.reason.clone(),
        }
    }
}

impl From<&pki_env::Error> for E2eiError {
    fn from(value: &pki_env::Error) -> Self {
        match value {
            pki_env::Error::NoTrustAnchor => Self::NoTrustAnchor,
            pki_env::Error::TrustAnchorAlreadyExists => Self::TrustAnchorAlreadyExists,
            pki_env::Error::CrlFetchUnsuccessful { uri, status } => Self::CrlFetchUnsuccessful {
                uri: uri.clone(),
                status: *status,
            },
            pki_env::Error::HooksError(err) => err.into(),
            pki_env::Error::Validation(err) => err.into(),
            pki_env::Error::UrlError(_)
            | pki_env::Error::JsonError(_)
            | pki_env::Error::X509CertDerError(_)
            | pki_env::Error::KeystoreError(_)
            | pki_env::Error::Certval(_)
            | pki_env::Error::Spki(_) => Self::other(value),
        }
    }
}

impl From<&validation::Error> for E2eiError {
    fn from(value: &validation::Error) -> Self {
        match value {
            validation::Error::MissingSki => Self::InvalidCertificate { msg: value.to_string() },
            validation::Error::LockPoisonError
            | validation::Error::CannotDetermineCurrentTime
            | validation::Error::CannotDetermineVerificationStatus
            | validation::Error::ImplementationError
            | validation::Error::DerError(_)
            | validation::Error::PemError(_)
            | validation::Error::CertValError(_) => Self::other(value),
        }
    }
}

impl From<&AcmeError> for E2eiError {
    fn from(value: &AcmeError) -> Self {
        let msg = value.to_string();
        match value {
            AcmeError::Account(_) => Self::AcmeAccount { msg },
            AcmeError::Order(_) | AcmeError::Finalize(_) => Self::AcmeOrder { msg },
            AcmeError::Authz(_) | AcmeError::Challenge(_) => Self::AcmeChallenge { msg },
            AcmeError::Implementation
            | AcmeError::ClientImplementation(_)
            | AcmeError::SmallstepImplementation(_)
            | AcmeError::Json(_)
            | AcmeError::Jwt(_)
            | AcmeError::X509CertBuilder(_)
            | AcmeError::Oid(_)
            | AcmeError::Der(_)
            | AcmeError::Pem(_)
            | AcmeError::Pkcs8(_)
            | AcmeError::JsonWebToken(_)
            | AcmeError::Signature(_)
            | AcmeError::Utf8(_) => Self::other(value),
        }
    }
}

impl From<&CertificateError> for E2eiError {
    fn from(value: &CertificateError) -> Self {
        match value {
            CertificateError::InvalidClientId
            | CertificateError::ClientIdMismatch
            | CertificateError::DisplayNameMismatch
            | CertificateError::HandleMismatch
            | CertificateError::DomainMismatch
            | CertificateError::MissingDisplayName
            | CertificateError::MissingHandle
            | CertificateError::MissingDomain
            | CertificateError::MissingClientId => Self::InvalidIdentifier { msg: value.to_string() },
            CertificateError::InvalidFormat
            | CertificateError::AlgorithmMismatch
            | CertificateError::KeyMismatch
            | CertificateError::InvalidSigningKeypair
            | CertificateError::UnsupportedPublicKey => Self::InvalidCertificate { msg: value.to_string() },
            CertificateError::Validation(err) => err.into(),
            CertificateError::Acme(err) => err.into(),
            CertificateError::Der(_)
            | CertificateError::Utf8(_)
            | CertificateError::RustyJwtError(_)
            | CertificateError::JsonWebToken(_) => Self::other(value),
        }
    }
}
