use std::time::Duration;

use certval::{
    CertSource, CertVector, CertificationPath, CertificationPathResults, CertificationPathSettings, DeferDecodeSigned,
    EXTS_OF_INTEREST, ExtensionProcessing as _, PDVTrustAnchorChoice, PathValidationStatus, TaSource, TimeOfInterest,
    check_revocation, validate_path_rfc5280,
    validator::{PDVCertificate, path_validator::check_validity},
    verify_signatures,
};
use const_oid::AssociatedOid;
use x509_cert::{
    certificate::Raw,
    der::{Decode, Encode},
};

mod cache;
mod crl_info;
mod crl_store;
mod misc;

use cache::RevocationCache;
use crl_store::CrlStore;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityStatus {
    /// All is fine
    Valid,
    /// The Certificate is expired
    Expired,
    /// The Certificate is revoked
    Revoked,
}

impl IdentityStatus {
    pub async fn from_cert(cert: &x509_cert::Certificate, env: &crate::pki_env::PkiEnvironment) -> Self {
        match env.validate_cert(cert).await {
            Err(RustyX509CheckError::CertValError(certval::Error::PathValidation(e))) => match e {
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
        .get_extension(&const_oid::db::rfc5280::ID_CE_CRL_DISTRIBUTION_POINTS)?
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

#[derive(Default)]
pub struct PkiEnvironmentParams<'a> {
    /// Intermediate CAs and cross-signed CAs
    pub intermediates: &'a [x509_cert::Certificate],
    /// Trust Anchor roots
    pub trust_roots: &'a [x509_cert::anchor::TrustAnchorChoice],
    /// CRLs to add to the revocation check
    pub crls: &'a [x509_cert::crl::CertificateList<Raw>],
}

pub struct PkiEnvironment {
    pe: certval::environment::PkiEnvironment,
}

impl std::ops::Deref for PkiEnvironment {
    type Target = certval::environment::PkiEnvironment;

    fn deref(&self) -> &Self::Target {
        &self.pe
    }
}

impl std::ops::DerefMut for PkiEnvironment {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.pe
    }
}

impl std::fmt::Debug for PkiEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkiEnvironment").field("pe", &"[OPAQUE]").finish()
    }
}

fn check_cpr(cpr: CertificationPathResults) -> RustyX509CheckResult<()> {
    if let Some(validation_status) = cpr.get_validation_status() {
        match validation_status {
            certval::PathValidationStatus::Valid => Ok(()),
            // No CRL is available, this is fine
            certval::PathValidationStatus::RevocationStatusNotDetermined
            | certval::PathValidationStatus::RevocationStatusNotAvailable => Ok(()),
            validation_status => Err(RustyX509CheckError::CertValError(certval::Error::PathValidation(
                validation_status,
            ))),
        }
    } else {
        Err(RustyX509CheckError::CannotDetermineVerificationStatus)
    }
}

pub(crate) fn now() -> RustyX509CheckResult<u64> {
    Ok(web_time::SystemTime::now()
        .duration_since(web_time::SystemTime::UNIX_EPOCH)
        .map_err(|_| RustyX509CheckError::CannotDetermineCurrentTime)?
        .as_secs())
}

impl PkiEnvironment {
    /// Initializes a certval PkiEnvironment using the provided params
    pub fn init(params: PkiEnvironmentParams) -> RustyX509CheckResult<PkiEnvironment> {
        let toi = TimeOfInterest::from_unix_secs(now()?)?;

        let mut cps = CertificationPathSettings::new();
        cps.set_time_of_interest(toi);

        // Make a Certificate source for intermediate CA certs
        let mut cert_source = CertSource::new();
        for (i, cert) in params.intermediates.iter().enumerate() {
            cert_source.push(certval::CertFile {
                filename: format!("Intermediate CA #{i} [{}]", cert.tbs_certificate().subject()),
                bytes: cert.to_der()?,
            });
        }

        cert_source.initialize(&cps)?;

        // Make a TrustAnchor source
        let mut trust_anchors = TaSource::new();
        for (i, root) in params.trust_roots.iter().enumerate() {
            trust_anchors.push(certval::CertFile {
                filename: format!("TrustAnchor #{i}"),
                bytes: root.to_der()?,
            });
        }

        trust_anchors.initialize()?;

        let revocation_cache = RevocationCache::default();

        // Make a CRL source
        let crl_source = CrlStore::from(params.crls);
        crl_source.index_crls(toi)?;

        let mut pe = certval::environment::PkiEnvironment::default();
        pe.populate_5280_pki_environment();
        pe.add_trust_anchor_source(Box::new(trust_anchors));
        pe.add_crl_source(Box::new(crl_source));
        pe.add_revocation_cache(Box::new(revocation_cache));

        cert_source.find_all_partial_paths(&pe, &cps);

        pe.add_certificate_source(Box::new(cert_source));

        Ok(Self { pe })
    }

    pub(crate) fn validate_cert(
        &self,
        end_identity_cert: &x509_cert::Certificate,
        perform_revocation_check: bool,
    ) -> RustyX509CheckResult<()> {
        let toi = TimeOfInterest::from_unix_secs(now()?)?;

        let mut cps = CertificationPathSettings::default();
        cps.set_time_of_interest(toi);
        cps.set_require_ta_store(true);
        cps.set_forbid_self_signed_ee(true);

        let mut end_identity_cert = PDVCertificate::try_from(end_identity_cert.clone())?;
        end_identity_cert.parse_extensions(EXTS_OF_INTEREST);

        let mut paths = vec![];
        self.pe.get_paths_for_target(&end_identity_cert, &mut paths, 0, toi)?;

        if paths.is_empty() {
            return Err(RustyX509CheckError::CertValError(certval::Error::PathValidation(
                certval::PathValidationStatus::NoPathsFound,
            )));
        }

        let mut result = Ok(());

        let any_path_validates = paths.into_iter().any(|mut path| {
            let mut cpr = CertificationPathResults::new();
            let _ = validate_path_rfc5280(&self.pe, &cps, &mut path, &mut cpr);
            let r = check_cpr(cpr);
            if r.is_err() {
                result = r;
                return false;
            }

            if perform_revocation_check {
                cps.set_check_crls(true);
                cps.set_revocation_max_age(Duration::from_hours(24));
                let mut cpr = CertificationPathResults::new();
                let _ = check_revocation(&self.pe, &cps, &mut path, &mut cpr);
                let r = check_cpr(cpr);
                if r.is_err() {
                    result = r;
                    return false;
                }
            }

            true
        });

        if any_path_validates { Ok(()) } else { result }
    }
}

pub(crate) fn validate_trust_anchor_cert(
    pe: &certval::environment::PkiEnvironment,
    cert: &x509_cert::Certificate,
) -> RustyX509CheckResult<()> {
    let toi = TimeOfInterest::from_unix_secs(now()?)?;

    let mut cps = CertificationPathSettings::default();
    cps.set_time_of_interest(toi);

    let mut cert = PDVCertificate::try_from(cert.clone())?;
    cert.parse_extensions(EXTS_OF_INTEREST);

    let ta = PDVTrustAnchorChoice::try_from(x509_cert::anchor::TrustAnchorChoice::Certificate(
        cert.decoded().clone(),
    ))?;
    let mut certification_path = CertificationPath::new(ta, vec![], cert);

    check_validity(pe, &cps, &mut certification_path, &mut CertificationPathResults::new())?;
    verify_signatures(pe, &cps, &mut certification_path, &mut CertificationPathResults::new())?;

    Ok(())
}

pub(crate) fn validate_crl(
    pe: &certval::environment::PkiEnvironment,
    crl_raw: &[u8],
) -> RustyX509CheckResult<x509_cert::crl::CertificateList<Raw>> {
    let crl = x509_cert::crl::CertificateList::from_der(crl_raw)?;

    let mut spki_list = vec![];
    if let Some(aki) = crl.tbs_cert_list.crl_extensions.as_ref().and_then(|extensions| {
        extensions
            .iter()
            .find(|ext| ext.extn_id == x509_cert::ext::pkix::AuthorityKeyIdentifier::OID)
    }) {
        let akid = aki.extn_value.as_bytes();
        if let Ok(ta) = pe.get_trust_anchor(akid) {
            spki_list.push(certval::source::ta_source::get_subject_public_key_info_from_trust_anchor(&ta.decoded_ta));
        } else if let Ok(intermediates) = pe.get_intermediates_by_skid(akid) {
            spki_list.extend(
                intermediates
                    .into_iter()
                    .map(|c| c.decoded().tbs_certificate().subject_public_key_info()),
            );
        }
    }

    if let Ok(ta) = pe.get_trust_anchor_by_name(&crl.tbs_cert_list.issuer) {
        let spki = certval::source::ta_source::get_subject_public_key_info_from_trust_anchor(&ta.decoded_ta);
        if !spki_list.contains(&spki) {
            spki_list.push(spki);
        }
    }

    spki_list.extend(
        pe.get_cert_by_name(&crl.tbs_cert_list.issuer)
            .into_iter()
            .map(|c| c.decoded().tbs_certificate().subject_public_key_info()),
    );

    spki_list.dedup();

    let crl_defer = DeferDecodeSigned::from_der(crl_raw)?;

    let any_spki_verifies = spki_list.into_iter().any(|spki| {
        pe.verify_signature_message(
            pe,
            &crl_defer.tbs_field,
            crl.signature.raw_bytes(),
            &crl.signature_algorithm,
            spki,
        )
        .is_ok()
    });

    if any_spki_verifies {
        Ok(crl)
    } else {
        Err(RustyX509CheckError::CertValError(certval::Error::PathValidation(
            certval::PathValidationStatus::SignatureVerificationFailure,
        )))
    }
}
