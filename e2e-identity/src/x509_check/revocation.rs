#![allow(dead_code)]

use certval::{
    CertSource, CertVector, CertificationPath, CertificationPathResults, CertificationPathSettings, DeferDecodeSigned,
    EXTS_OF_INTEREST, ExtensionProcessing, PDVTrustAnchorChoice, TaSource, check_revocation, get_validation_status,
    populate_5280_pki_environment, set_check_crls, set_forbid_self_signed_ee, set_require_ta_store,
    set_time_of_interest, validate_path_rfc5280,
    validator::{PDVCertificate, path_validator::check_validity},
    verify_signatures,
};
use const_oid::AssociatedOid;
use crl_store::CrlStore;
use x509_cert::{
    der::{Decode, DecodePem, Encode},
    ext::pkix::AuthorityKeyIdentifier,
};

use super::{RustyX509CheckError, RustyX509CheckResult, revocation::cache::RevocationCache};

mod cache;
mod crl_info;
mod crl_store;
mod misc;

#[derive(Default)]
pub struct PkiEnvironmentParams<'a> {
    /// Intermediate CAs and cross-signed CAs
    pub intermediates: &'a [x509_cert::Certificate],
    /// Trust Anchor roots
    pub trust_roots: &'a [x509_cert::anchor::TrustAnchorChoice],
    /// CRLs to add to the revocation check
    pub crls: &'a [x509_cert::crl::CertificateList],
    /// Time of interest for CRL verfication. If not provided, will default to current UNIX epoch
    pub time_of_interest: Option<u64>,
}

pub struct PkiEnvironment {
    pe: certval::environment::PkiEnvironment,
    toi: u64,
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
        f.debug_struct("PkiEnvironment")
            .field("pe", &"[OPAQUE]")
            .field("toi", &self.toi)
            .finish()
    }
}

fn check_cpr(cpr: CertificationPathResults) -> RustyX509CheckResult<()> {
    if let Some(validation_status) = get_validation_status(&cpr) {
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

impl PkiEnvironment {
    pub fn decode_pem_cert(pem: String) -> RustyX509CheckResult<x509_cert::Certificate> {
        Ok(x509_cert::Certificate::from_pem(pem)?)
    }

    pub fn decode_der_crl(crl_der: Vec<u8>) -> RustyX509CheckResult<x509_cert::crl::CertificateList> {
        Ok(x509_cert::crl::CertificateList::from_der(&crl_der)?)
    }

    pub fn extract_ski_aki_from_cert(cert: &x509_cert::Certificate) -> RustyX509CheckResult<(String, Option<String>)> {
        let cert = PDVCertificate::try_from(cert.clone())?;

        let ski = cert
            .get_extension(&const_oid::db::rfc5912::ID_CE_SUBJECT_KEY_IDENTIFIER)?
            .ok_or(RustyX509CheckError::MissingSki)?;
        let ski = match ski {
            certval::PDVExtension::SubjectKeyIdentifier(ski) => hex::encode(ski.0.as_bytes()),
            _ => return Err(RustyX509CheckError::ImplementationError),
        };

        let aki = cert
            .get_extension(&const_oid::db::rfc5912::ID_CE_AUTHORITY_KEY_IDENTIFIER)?
            .and_then(|ext| match ext {
                certval::PDVExtension::AuthorityKeyIdentifier(AuthorityKeyIdentifier { key_identifier, .. }) => {
                    key_identifier.as_ref()
                }
                _ => None,
            })
            .map(|ki| hex::encode(ki.as_bytes()));

        Ok((ski, aki))
    }

    pub fn encode_cert_to_der(cert: &x509_cert::Certificate) -> RustyX509CheckResult<Vec<u8>> {
        Ok(cert.to_der()?)
    }

    pub fn encode_crl_to_der(crl: &x509_cert::crl::CertificateList) -> RustyX509CheckResult<Vec<u8>> {
        Ok(crl.to_der()?)
    }

    /// Initializes a certval PkiEnvironment using the provided params
    pub fn init(params: PkiEnvironmentParams) -> RustyX509CheckResult<PkiEnvironment> {
        let toi = if let Some(toi) = params.time_of_interest {
            toi
        } else {
            web_time::SystemTime::now()
                .duration_since(web_time::SystemTime::UNIX_EPOCH)
                .map_err(|_| RustyX509CheckError::CannotDetermineCurrentTime)?
                .as_secs()
        };

        let mut cps = CertificationPathSettings::new();
        set_time_of_interest(&mut cps, toi);

        // Make a Certificate source for intermediate CA certs
        let mut cert_source = CertSource::new();
        for (i, cert) in params.intermediates.iter().enumerate() {
            cert_source.push(certval::CertFile {
                filename: format!("Intermediate CA #{i} [{}]", cert.tbs_certificate.subject),
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
        populate_5280_pki_environment(&mut pe);
        pe.add_trust_anchor_source(Box::new(trust_anchors));
        pe.add_crl_source(Box::new(crl_source));
        pe.add_revocation_cache(Box::new(revocation_cache));

        cert_source.find_all_partial_paths(&pe, &cps);

        pe.add_certificate_source(Box::new(cert_source));

        Ok(Self { pe, toi })
    }

    /// Overrides TIME_OF_INTEREST for certificate verifications based on a moment in the past or future
    pub fn set_time_of_interest(&mut self, toi: u64) {
        self.toi = toi;
    }

    /// Updates the TIME_OF_INTEREST for certificate checks to be `now`
    pub fn refresh_time_of_interest(&mut self) -> RustyX509CheckResult<()> {
        self.set_time_of_interest(
            web_time::SystemTime::now()
                .duration_since(web_time::SystemTime::UNIX_EPOCH)
                .map_err(|_| RustyX509CheckError::CannotDetermineCurrentTime)?
                .as_secs(),
        );

        Ok(())
    }

    pub fn validate_trust_anchor_cert(&self, cert: &x509_cert::Certificate) -> RustyX509CheckResult<()> {
        let mut cps = CertificationPathSettings::default();
        set_time_of_interest(&mut cps, self.toi);

        let mut cert = PDVCertificate::try_from(cert.clone())?;
        cert.parse_extensions(EXTS_OF_INTEREST);

        let ta = PDVTrustAnchorChoice::try_from(x509_cert::anchor::TrustAnchorChoice::Certificate(
            cert.decoded_cert.clone(),
        ))?;
        let mut certification_path = CertificationPath::new(ta, vec![], cert);

        check_validity(
            &self.pe,
            &cps,
            &mut certification_path,
            &mut CertificationPathResults::new(),
        )?;

        verify_signatures(
            &self.pe,
            &cps,
            &mut certification_path,
            &mut CertificationPathResults::new(),
        )?;

        Ok(())
    }

    #[inline]
    #[deprecated = "This method is not to be used as it causes spurious verification failures because of re-encoding the DER repr of the CRL. Use `validate_crl_with_raw`"]
    pub fn validate_crl(&self, crl: &x509_cert::crl::CertificateList) -> RustyX509CheckResult<()> {
        let _ = self.validate_crl_with_raw(&crl.to_der()?)?;
        Ok(())
    }

    pub fn validate_crl_with_raw(&self, crl_raw: &[u8]) -> RustyX509CheckResult<x509_cert::crl::CertificateList> {
        let crl = x509_cert::crl::CertificateList::from_der(crl_raw)?;

        let mut spki_list = vec![];
        if let Some(aki) = crl.tbs_cert_list.crl_extensions.as_ref().and_then(|extensions| {
            extensions
                .iter()
                .find(|ext| ext.extn_id == x509_cert::ext::pkix::AuthorityKeyIdentifier::OID)
        }) {
            let akid = aki.extn_value.as_bytes();
            if let Ok(ta) = self.pe.get_trust_anchor(akid) {
                spki_list
                    .push(certval::source::ta_source::get_subject_public_key_info_from_trust_anchor(&ta.decoded_ta));
            } else if let Ok(intermediates) = self.pe.get_intermediates_by_skid(akid) {
                spki_list.extend(
                    intermediates
                        .into_iter()
                        .map(|c| &c.decoded_cert.tbs_certificate.subject_public_key_info),
                );
            }
        }

        if let Ok(ta) = self.pe.get_trust_anchor_by_name(&crl.tbs_cert_list.issuer) {
            let spki = certval::source::ta_source::get_subject_public_key_info_from_trust_anchor(&ta.decoded_ta);
            if !spki_list.contains(&spki) {
                spki_list.push(spki);
            }
        }

        spki_list.extend(
            self.pe
                .get_cert_by_name(&crl.tbs_cert_list.issuer)
                .into_iter()
                .map(|c| &c.decoded_cert.tbs_certificate.subject_public_key_info),
        );

        spki_list.dedup();

        let crl_defer = DeferDecodeSigned::from_der(crl_raw)?;

        let any_spki_verifies = spki_list.into_iter().any(|spki| {
            self.pe
                .verify_signature_message(
                    &self.pe,
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

    fn validate_cert_internal(
        &self,
        end_identity_cert: &x509_cert::Certificate,
        perform_revocation_check: bool,
    ) -> RustyX509CheckResult<()> {
        let mut cps = CertificationPathSettings::default();
        set_time_of_interest(&mut cps, self.toi);
        set_require_ta_store(&mut cps, true);
        set_forbid_self_signed_ee(&mut cps, true);

        let mut end_identity_cert = PDVCertificate::try_from(end_identity_cert.clone())?;
        end_identity_cert.parse_extensions(EXTS_OF_INTEREST);

        let mut paths = vec![];
        self.pe
            .get_paths_for_target(&self.pe, &end_identity_cert, &mut paths, 0, self.toi)?;

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
                set_check_crls(&mut cps, true);
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

    #[inline]
    pub fn validate_cert(&self, end_identity_cert: &x509_cert::Certificate) -> RustyX509CheckResult<()> {
        self.validate_cert_internal(end_identity_cert, false)
    }

    #[inline]
    pub fn validate_cert_and_revocation(&self, end_identity_cert: &x509_cert::Certificate) -> RustyX509CheckResult<()> {
        self.validate_cert_internal(end_identity_cert, true)
    }
}
