use certval::PathValidationStatus;

pub mod reexports {
    pub use certval;
}

use revocation::PkiEnvironment;

pub mod revocation;

#[derive(Debug, thiserror::Error)]
pub enum RustyX509CheckError {
    /// Failed mapping a DER certificate
    #[error(transparent)]
    DerError(#[from] x509_cert::der::Error),
    /// PEM de/serialization error
    #[error("PEM en/decoding error: {0}")]
    PemError(x509_cert::der::pem::Error),
    /// Poisoned lock error
    #[error("A lock has been poisoned and cannot be recovered from.")]
    LockPoisonError,
    /// Error for when the current UNIX epoch time cannot be determined.
    #[error("Cannot determine current UNIX epoch")]
    CannotDetermineCurrentTime,
    /// Certificate / revocation validation error
    #[error("Certificate validation error: {0}")]
    CertValError(certval::Error),
    /// Error when we have no idea what the cert status is
    #[error("Something went wrong, we cannot determine if this certificate is OK. You might want to ignore this")]
    CannotDetermineVerificationStatus,
    /// Required 'Subject Key Identifier' extension is missing
    #[error("Required 'Subject Key Identifier' extension is missing")]
    MissingSki,
    /// Implementation error
    #[error("Implementation error")]
    ImplementationError,
}

impl From<x509_cert::der::pem::Error> for RustyX509CheckError {
    fn from(value: x509_cert::der::pem::Error) -> Self {
        RustyX509CheckError::PemError(value)
    }
}

impl From<certval::Error> for RustyX509CheckError {
    fn from(value: certval::Error) -> Self {
        RustyX509CheckError::CertValError(value)
    }
}

pub type RustyX509CheckResult<T> = Result<T, RustyX509CheckError>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IdentityStatus {
    /// All is fine
    Valid,
    /// The Certificate is expired
    Expired,
    /// The Certificate is revoked
    Revoked,
}

impl IdentityStatus {
    pub fn from_cert(cert: &x509_cert::Certificate, env: Option<&PkiEnvironment>) -> Self {
        match env.map(|e| e.validate_cert_and_revocation(cert)) {
            Some(Err(RustyX509CheckError::CertValError(certval::Error::PathValidation(e)))) => match e {
                PathValidationStatus::InvalidNotAfterDate => IdentityStatus::Expired,
                PathValidationStatus::CertificateRevoked
                | PathValidationStatus::CertificateRevokedEndEntity
                | PathValidationStatus::NoPathsFound
                | PathValidationStatus::CertificateRevokedIntermediateCa => IdentityStatus::Revoked,
                _ => IdentityStatus::Valid,
            },
            _ => IdentityStatus::Valid,
        }
    }
}

/// Extracts the CRL Distribution points that are FullName URIs from the Certificate
pub fn extract_crl_uris(
    cert: &x509_cert::Certificate,
) -> RustyX509CheckResult<Option<std::collections::HashSet<String>>> {
    use certval::validator::{PDVCertificate, PDVExtension};
    use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};

    Ok(PDVCertificate::try_from(cert.clone())?
        .parsed_extensions
        .get(&const_oid::db::rfc5280::ID_CE_CRL_DISTRIBUTION_POINTS)
        .and_then(|ext| {
            let PDVExtension::CrlDistributionPoints(crl_distribution_points) = ext else {
                return None;
            };

            Some(crl_distribution_points.0.iter().fold(
                Default::default(),
                |mut set: std::collections::HashSet<String>, dp| {
                    if let Some(DistributionPointName::FullName(dp_full_names)) = dp.distribution_point.as_ref() {
                        for gn in dp_full_names.iter() {
                            if let GeneralName::UniformResourceIdentifier(uri) = gn {
                                set.insert(uri.to_string());
                            }
                        }
                    }

                    set
                },
            ))
        }))
}

/// Extracts the expiration date from a parsed CRL
pub fn extract_expiration_from_crl(crl: &x509_cert::crl::CertificateList) -> Option<u64> {
    crl.tbs_cert_list.next_update.map(|t| t.to_unix_duration().as_secs())
}
