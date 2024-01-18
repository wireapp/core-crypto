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

impl PkiKeypair {
    pub fn signing_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::P256(sk) => sk.to_bytes().to_vec(),
            Self::P384(sk) => sk.to_bytes().to_vec(),
            Self::Ed25519(sk) => sk.0.to_bytes().to_vec(),
        }
    }

    pub fn public_key_identifier(&self) -> Vec<u8> {
        let pk_bytes = match self {
            Self::P256(sk) => sk.verifying_key().to_sec1_bytes().to_vec(),
            Self::P384(sk) => sk.verifying_key().to_sec1_bytes().to_vec(),
            Self::Ed25519(sk) => sk.0.verifying_key().to_bytes().to_vec(),
        };
        use sha1::Digest as _;
        sha1::Sha1::digest(pk_bytes).to_vec()
    }
}

pub use x509_cert::builder::Profile as CertProfile;

pub struct CertificateGenerationArgs<'a> {
    pub signature_scheme: SignatureScheme,
    pub profile: CertProfile,
    pub serial: u32,
    pub validity_from_now: std::time::Duration,
    pub org: &'a str,
    pub common_name: Option<&'a str>,
    pub alternative_names: Option<&'a [&'a str]>,
    pub domain: Option<&'a str>,
    pub crl_dps: Option<&'a [&'a str]>,
    pub signer: Option<&'a PkiKeypair>,
    pub is_ca: bool,
    pub is_root: bool,
}

// fn get_ca_keyusage() -> x509_cert::ext::pkix::KeyUsage {
//     let mut flags = x509_cert::der::flagset::FlagSet::default();
//     flags |= x509_cert::ext::pkix::KeyUsages::KeyCertSign;
//     flags |= x509_cert::ext::pkix::KeyUsages::CRLSign;
//     x509_cert::ext::pkix::KeyUsage(flags)
// }

fn get_extended_keyusage(is_ca: bool) -> x509_cert::ext::pkix::ExtendedKeyUsage {
    let mut ext_keyusages = vec![];
    if !is_ca {
        // ID_KP_CLIENT_AUTH
        ext_keyusages.push(spki::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2"));
    }

    x509_cert::ext::pkix::ExtendedKeyUsage(ext_keyusages)
}

macro_rules! impl_certgen {
    (
        $signer:expr, $signer_keypair:expr, $sig_type:path,
        $profile:expr, $own_spki:expr, $serial:expr,
        $subject:expr, $org:expr, $domain:expr, $validity:expr, $alt_names:expr,
        $crl_dps:expr, $is_ca:expr, $is_root:expr
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

        // builder
        //     .add_extension(&$skid)
        //     .map_err(|_| MlsProviderError::CertificateGenerationError)?;

        // if $is_ca {
        //     builder
        //         .add_extension(&get_ca_keyusage())
        //         .map_err(|_| MlsProviderError::CertificateGenerationError)?;
        // }

        builder
            .add_extension(&get_extended_keyusage($is_ca))
            .map_err(|_| MlsProviderError::CertificateGenerationError)?;

        if !$is_ca {
            if let Some(alt_names) = $alt_names {
                let mut alt_names_list = vec![];
                for alt_name in alt_names {
                    alt_names_list.push(x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                        alt_name
                            .to_string()
                            .try_into()
                            .map_err(|_| MlsProviderError::CertificateGenerationError)?,
                    ));
                }

                builder
                    .add_extension(&x509_cert::ext::pkix::SubjectAltName(alt_names_list))
                    .map_err(|_| MlsProviderError::CertificateGenerationError)?;
            }
        } else {
            let mut permitted_subtrees = vec![x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                format!(".{}", $org)
                    .try_into()
                    .map_err(|_| MlsProviderError::CertificateGenerationError)?,
            )];

            if let Some(domain) = $domain {
                // Add Domain DNS SAN
                builder
                    .add_extension(&x509_cert::ext::pkix::SubjectAltName(vec![
                        x509_cert::ext::pkix::name::GeneralName::DnsName(
                            domain
                                .to_string()
                                .try_into()
                                .map_err(|_| MlsProviderError::CertificateGenerationError)?,
                        ),
                    ]))
                    .map_err(|_| MlsProviderError::CertificateGenerationError)?;

                permitted_subtrees.push(x509_cert::ext::pkix::name::GeneralName::DnsName(
                    domain
                        .to_string()
                        .try_into()
                        .map_err(|_| MlsProviderError::CertificateGenerationError)?,
                ));
            }

            if !$is_root {
                builder
                    .add_extension(&x509_cert::ext::pkix::NameConstraints {
                        permitted_subtrees: Some(
                            permitted_subtrees
                                .into_iter()
                                .map(|base| x509_cert::ext::pkix::constraints::name::GeneralSubtree {
                                    base,
                                    minimum: 0,
                                    maximum: None,
                                })
                                .collect(),
                        ),

                        excluded_subtrees: None,
                    })
                    .map_err(|_| MlsProviderError::CertificateGenerationError)?;
            }
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
        Ok(x509_cert::ext::pkix::AuthorityKeyIdentifier {
            key_identifier: Some(
                spki::der::asn1::OctetString::new(self.public_key_identifier())
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
            subject_fmt.push_str(&format!(",CN={}", cn));
        }

        let subject =
            x509_cert::name::Name::from_str(&subject_fmt).map_err(|_| MlsProviderError::CertificateGenerationError)?;
        let validity = x509_cert::time::Validity::from_now(args.validity_from_now)
            .map_err(|_| MlsProviderError::CertificateGenerationError)?;
        let serial_number = x509_cert::serial_number::SerialNumber::from(args.serial);
        let spki = self.spki()?;

        let signer = args.signer.unwrap_or(self);

        let cert = match signer {
            PkiKeypair::P256(kp) => {
                impl_certgen!(
                    signer,
                    kp,
                    p256::ecdsa::DerSignature,
                    args.profile,
                    spki,
                    serial_number,
                    subject,
                    args.org,
                    args.domain,
                    validity,
                    args.alternative_names,
                    args.crl_dps,
                    args.is_ca,
                    args.is_root
                )
            }
            PkiKeypair::P384(kp) => {
                impl_certgen!(
                    signer,
                    kp,
                    p384::ecdsa::DerSignature,
                    args.profile,
                    spki,
                    serial_number,
                    subject,
                    args.org,
                    args.domain,
                    validity,
                    args.alternative_names,
                    args.crl_dps,
                    args.is_ca,
                    args.is_root
                )
            }
            PkiKeypair::Ed25519(kp) => {
                impl_certgen!(
                    signer,
                    kp,
                    Ed25519PkiSignature,
                    args.profile,
                    spki,
                    serial_number,
                    subject,
                    args.org,
                    args.domain,
                    validity,
                    args.alternative_names,
                    args.crl_dps,
                    args.is_ca,
                    args.is_root
                )
            }
        };

        Ok(cert)
    }
}
