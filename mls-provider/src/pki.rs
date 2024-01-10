use crate::error::{MlsProviderError, MlsProviderResult};
use openmls_traits::types::SignatureScheme;

pub struct Ed25519PkiSignature(ed25519_dalek::Signature);
impl spki::SignatureBitStringEncoding for Ed25519PkiSignature {
    fn to_bitstring(&self) -> spki::der::Result<spki::der::asn1::BitString> {
        spki::der::asn1::BitString::new(0, self.0.to_vec())
    }
}

#[derive(Debug, Clone)]
pub struct Ed25519PkiKeypair(ed25519_dalek::SigningKey);

impl spki::SignatureAlgorithmIdentifier for Ed25519PkiKeypair {
    type Params = spki::der::AnyRef<'static>;
    const SIGNATURE_ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Self::Params> = ed25519_dalek::pkcs8::ALGORITHM_ID;
}

impl signature::Keypair for Ed25519PkiKeypair {
    type VerifyingKey = <ed25519_dalek::SigningKey as signature::Keypair>::VerifyingKey;
    fn verifying_key(&self) -> Self::VerifyingKey {
        self.0.verifying_key()
    }
}

impl signature::Signer<Ed25519PkiSignature> for Ed25519PkiKeypair {
    fn try_sign(&self, message: &[u8]) -> Result<Ed25519PkiSignature, ed25519_dalek::SignatureError> {
        self.0.try_sign(message).map(Ed25519PkiSignature)
    }
}

#[derive(Debug, Clone)]
pub enum PkiKeypair {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    Ed25519(Ed25519PkiKeypair),
}

pub use x509_cert::builder::Profile as CertProfile;

pub struct CertificateGenerationArgs<'a> {
    pub signature_scheme: SignatureScheme,
    pub profile: CertProfile,
    pub serial: u32,
    pub validity_from_now: std::time::Duration,
    pub org: &'a str,
    pub common_name: Option<&'a str>,
    pub domain: Option<&'a str>,
    pub crl_dps: Option<&'a [&'a str]>,
    pub signer: Option<&'a PkiKeypair>,
    pub is_ca: bool,
}

fn get_keyusage(is_ca: bool) -> x509_cert::ext::pkix::KeyUsage {
    let mut flags = x509_cert::der::flagset::FlagSet::default();
    flags |= x509_cert::ext::pkix::KeyUsages::DigitalSignature;
    flags |= x509_cert::ext::pkix::KeyUsages::NonRepudiation;
    flags |= x509_cert::ext::pkix::KeyUsages::KeyEncipherment;
    flags |= x509_cert::ext::pkix::KeyUsages::KeyAgreement;
    if is_ca {
        flags |= x509_cert::ext::pkix::KeyUsages::KeyCertSign;
        flags |= x509_cert::ext::pkix::KeyUsages::CRLSign;
    }
    x509_cert::ext::pkix::KeyUsage(flags)
}

macro_rules! impl_certgen {
    (
        $signer:expr, $signer_keypair:expr, $sig_type:path,
        $skid:expr, $profile:expr, $own_spki:expr,
        $serial:expr, $subject:expr, $domain:expr, $validity:expr,
        $crl_dps:expr, $is_ca:expr
    ) => {{
        let mut builder = x509_cert::builder::CertificateBuilder::new(
            $profile,
            $serial,
            $validity,
            $subject,
            $own_spki,
            $signer_keypair,
        )
        .map_err(|_| MlsProviderError::CertificateGenerationError)?;

        builder
            .add_extension(&$skid)
            .map_err(|_| MlsProviderError::CertificateGenerationError)?;

        builder
            .add_extension(&get_keyusage($is_ca))
            .map_err(|_| MlsProviderError::CertificateGenerationError)?;

        builder
            .add_extension(&$signer.akid()?)
            .map_err(|_| MlsProviderError::CertificateGenerationError)?;

        if let Some(san) = $domain {
            builder
                .add_extension(&x509_cert::ext::pkix::SubjectAltName(vec![
                    x509_cert::ext::pkix::name::GeneralName::DnsName(
                        san.to_string()
                            .try_into()
                            .map_err(|_| MlsProviderError::CertificateGenerationError)?,
                    ),
                ]))
                .map_err(|_| MlsProviderError::CertificateGenerationError)?;
        }

        if let Some(crl_dps) = $crl_dps {
            let mut crl_distribution_points = vec![];
            for dp in crl_dps {
                crl_distribution_points.push(x509_cert::ext::pkix::crl::dp::DistributionPoint {
                    distribution_point: Some(x509_cert::ext::pkix::name::DistributionPointName::FullName(vec![
                        x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                            dp.to_string()
                                .try_into()
                                .map_err(|_| MlsProviderError::CertificateGenerationError)?,
                        ),
                    ])),
                    crl_issuer: None,
                    reasons: None,
                });
            }
            builder
                .add_extension(&x509_cert::ext::pkix::CrlDistributionPoints(crl_distribution_points))
                .map_err(|_| MlsProviderError::CertificateGenerationError)?;
        }

        builder
            .build::<$sig_type>()
            .map_err(|_| MlsProviderError::CertificateGenerationError)?
    }};
}

impl PkiKeypair {
    pub fn new(signature_scheme: SignatureScheme, sk: Vec<u8>) -> MlsProviderResult<Self> {
        match signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(PkiKeypair::P256(
                p256::ecdsa::SigningKey::from_bytes(sk.as_slice().into())
                    .map_err(|_| MlsProviderError::CertificateGenerationError)?,
            )),
            SignatureScheme::ECDSA_SECP384R1_SHA384 => Ok(PkiKeypair::P384(
                p384::ecdsa::SigningKey::from_bytes(sk.as_slice().into())
                    .map_err(|_| MlsProviderError::CertificateGenerationError)?,
            )),
            SignatureScheme::ED25519 => Ok(PkiKeypair::Ed25519(Ed25519PkiKeypair(
                ed25519_dalek::SigningKey::try_from(sk.as_slice())
                    .map_err(|_| MlsProviderError::CertificateGenerationError)?,
            ))),
            _ => Err(MlsProviderError::UnsupportedSignatureScheme),
        }
    }

    pub fn spki(&self) -> MlsProviderResult<spki::SubjectPublicKeyInfoOwned> {
        match self {
            Self::P256(sk) => Ok(spki::SubjectPublicKeyInfoOwned::from_key(*sk.verifying_key())
                .map_err(|_| MlsProviderError::CertificateGenerationError)?),
            Self::P384(sk) => Ok(spki::SubjectPublicKeyInfoOwned::from_key(*sk.verifying_key())
                .map_err(|_| MlsProviderError::CertificateGenerationError)?),
            Self::Ed25519(sk) => Ok(spki::SubjectPublicKeyInfoOwned::from_key(sk.0.verifying_key())
                .map_err(|_| MlsProviderError::CertificateGenerationError)?),
        }
    }

    pub fn akid(&self) -> MlsProviderResult<x509_cert::ext::pkix::AuthorityKeyIdentifier> {
        let spki = self.spki()?;
        let spki_fingerprint = spki
            .fingerprint_bytes()
            .map_err(|_| MlsProviderError::CertificateGenerationError)?;

        Ok(x509_cert::ext::pkix::AuthorityKeyIdentifier {
            key_identifier: Some(
                spki::der::asn1::OctetString::new(spki_fingerprint)
                    .map_err(|_| MlsProviderError::CertificateGenerationError)?,
            ),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        })
    }

    pub fn revoke_certs(
        &self,
        issuer_cert: &x509_cert::Certificate,
        revoked_cert_serial_numbers: Vec<u32>,
    ) -> MlsProviderResult<x509_cert::crl::CertificateList> {
        let now = fluvio_wasm_timer::SystemTime::now()
            .duration_since(fluvio_wasm_timer::UNIX_EPOCH)
            .map_err(|_| MlsProviderError::CertificateGenerationError)?;
        let now = x509_cert::der::asn1::GeneralizedTime::from_unix_duration(now)
            .map_err(|_| MlsProviderError::CertificateGenerationError)?;
        let now = x509_cert::time::Time::GeneralTime(now);

        let revoked_certificates = revoked_cert_serial_numbers
            .into_iter()
            .map(|serial_number| x509_cert::crl::RevokedCert {
                serial_number: x509_cert::serial_number::SerialNumber::from(serial_number),
                revocation_date: now,
                crl_entry_extensions: None,
            })
            .collect();

        let tbs_cert_list = x509_cert::crl::TbsCertList {
            version: x509_cert::Version::V3,
            signature: issuer_cert.signature_algorithm.clone(),
            issuer: issuer_cert.tbs_certificate.subject.clone(),
            this_update: now,
            next_update: None,
            revoked_certificates: Some(revoked_certificates),
            crl_extensions: None,
        };

        use spki::der::Encode as _;

        let tbs = tbs_cert_list
            .to_der()
            .map_err(|_| MlsProviderError::CertificateGenerationError)?;

        use signature::Signer as _;

        let signature: Vec<u8> = match self {
            PkiKeypair::P256(sk) => signature::Signer::<p256::ecdsa::DerSignature>::try_sign(sk, &tbs)?
                .to_der()
                .map_err(|_| MlsProviderError::CertificateGenerationError),
            PkiKeypair::P384(sk) => signature::Signer::<p384::ecdsa::DerSignature>::try_sign(sk, &tbs)?
                .to_der()
                .map_err(|_| MlsProviderError::CertificateGenerationError),
            PkiKeypair::Ed25519(sk) => Ok(sk.try_sign(&tbs)?.0.to_vec()),
        }?;

        let signature =
            spki::der::asn1::BitString::new(0, signature).map_err(|_| MlsProviderError::CertificateGenerationError)?;

        Ok(x509_cert::crl::CertificateList {
            tbs_cert_list,
            signature_algorithm: issuer_cert.signature_algorithm.clone(),
            signature,
        })
    }

    pub fn re_sign(
        &self,
        signer_cert: &x509_cert::Certificate,
        target: &x509_cert::Certificate,
    ) -> MlsProviderResult<x509_cert::Certificate> {
        let mut target = target.clone();
        target.tbs_certificate.issuer = signer_cert.tbs_certificate.subject.clone();
        let our_spki = self.spki()?;
        let akid = self.akid()?;
        use x509_cert::ext::AsExtension as _;
        // Insert AKID
        if let Some(exts) = &mut target.tbs_certificate.extensions {
            exts.push(
                akid.to_extension(&target.tbs_certificate.subject, &[])
                    .map_err(|_| MlsProviderError::CertificateGenerationError)?,
            );
        } else {
            target.tbs_certificate.extensions = Some(vec![akid
                .to_extension(&target.tbs_certificate.subject, &[])
                .map_err(|_| MlsProviderError::CertificateGenerationError)?]);
        }

        // Update Serial
        target.tbs_certificate.serial_number =
            x509_cert::serial_number::SerialNumber::<x509_cert::certificate::Rfc5280>::from(rand::random::<u16>());

        // Re-sign
        use spki::der::Encode as _;
        let tbs = target
            .tbs_certificate
            .to_der()
            .map_err(|_| MlsProviderError::CertificateGenerationError)?;

        use signature::Signer as _;

        let signature: Vec<u8> = match self {
            PkiKeypair::P256(sk) => signature::Signer::<p256::ecdsa::DerSignature>::try_sign(sk, &tbs)?
                .to_der()
                .map_err(|_| MlsProviderError::CertificateGenerationError),
            PkiKeypair::P384(sk) => signature::Signer::<p384::ecdsa::DerSignature>::try_sign(sk, &tbs)?
                .to_der()
                .map_err(|_| MlsProviderError::CertificateGenerationError),
            PkiKeypair::Ed25519(sk) => Ok(sk.try_sign(&tbs)?.0.to_vec()),
        }?;

        target.signature_algorithm = our_spki.algorithm;
        target.signature =
            spki::der::asn1::BitString::new(0, signature).map_err(|_| MlsProviderError::CertificateGenerationError)?;

        Ok(target)
    }

    pub fn generate_cert(&self, args: CertificateGenerationArgs) -> MlsProviderResult<x509_cert::Certificate> {
        use std::str::FromStr as _;
        use x509_cert::builder::Builder as _;
        let mut subject_fmt = format!("O={}", args.org);
        if let Some(cn) = args.common_name {
            subject_fmt.push_str(&format!("CN={}", cn));
        }

        let subject =
            x509_cert::name::Name::from_str(&subject_fmt).map_err(|_| MlsProviderError::CertificateGenerationError)?;
        let validity = x509_cert::time::Validity::from_now(args.validity_from_now)
            .map_err(|_| MlsProviderError::CertificateGenerationError)?;
        let serial_number = x509_cert::serial_number::SerialNumber::from(args.serial);
        let spki = self.spki()?;
        let spki_fingerprint = spki
            .fingerprint_bytes()
            .map_err(|_| MlsProviderError::CertificateGenerationError)?;
        let skid = x509_cert::ext::pkix::SubjectKeyIdentifier(
            spki::der::asn1::OctetString::new(spki_fingerprint)
                .map_err(|_| MlsProviderError::CertificateGenerationError)?,
        );

        let signer = args.signer.unwrap_or(self);

        let cert = match signer {
            PkiKeypair::P256(kp) => {
                impl_certgen!(
                    signer,
                    kp,
                    p256::ecdsa::DerSignature,
                    skid,
                    args.profile,
                    spki,
                    serial_number,
                    subject,
                    args.domain,
                    validity,
                    args.crl_dps,
                    args.is_ca
                )
            }
            PkiKeypair::P384(kp) => {
                impl_certgen!(
                    signer,
                    kp,
                    p384::ecdsa::DerSignature,
                    skid,
                    args.profile,
                    spki,
                    serial_number,
                    subject,
                    args.domain,
                    validity,
                    args.crl_dps,
                    args.is_ca
                )
            }
            PkiKeypair::Ed25519(kp) => {
                impl_certgen!(
                    signer,
                    kp,
                    Ed25519PkiSignature,
                    skid,
                    args.profile,
                    spki,
                    serial_number,
                    subject,
                    args.domain,
                    validity,
                    args.crl_dps,
                    args.is_ca
                )
            }
        };

        Ok(cert)
    }
}
