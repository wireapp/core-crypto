use std::str::FromStr as _;

use ecdsa::SignatureEncoding as _;
use openmls_traits::{crypto::OpenMlsCrypto, types::SignatureScheme};
use spki::{SignatureAlgorithmIdentifier, der::referenced::RefToOwned};
use x509_cert::{
    builder::{Builder as _, CertificateBuilder, profile::BuilderProfile},
    name::Name,
    time::Validity,
};

use crate::error::{E2eIdentityError, E2eIdentityResult};

#[derive(Clone)]
pub enum PkiKeypair {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    P521(p521::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

impl std::fmt::Debug for PkiKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkiKeypair")
            .field(
                "type",
                &match self {
                    Self::P256(_k) => "P256",
                    Self::P384(_k) => "P384",
                    Self::P521(_k) => "P521",
                    Self::Ed25519(_k) => "Ed25519",
                },
            )
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl PkiKeypair {
    pub fn signing_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::P256(sk) => sk.to_bytes().to_vec(),
            Self::P384(sk) => sk.to_bytes().to_vec(),
            Self::P521(sk) => sk.to_bytes().to_vec(),
            Self::Ed25519(sk) => sk.to_bytes().to_vec(),
        }
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::P256(sk) => sk.verifying_key().to_sec1_bytes().to_vec(),
            Self::P384(sk) => sk.verifying_key().to_sec1_bytes().to_vec(),
            Self::P521(sk) => sk.verifying_key().to_sec1_bytes().to_vec(),
            Self::Ed25519(sk) => sk.verifying_key().to_bytes().to_vec(),
        }
    }

    pub fn public_key_identifier(&self) -> Vec<u8> {
        use sha1::Digest as _;
        sha1::Sha1::digest(self.public_key_bytes()).to_vec()
    }
}

#[derive(Debug)]
pub struct CertificateGenerationArgs<'a> {
    pub signature_scheme: SignatureScheme,
    pub issuer: Option<String>,
    pub serial: u64,
    /// Duration since UNIX EPOCH
    pub validity_start: Option<std::time::Duration>,
    /// Duration relative to `validity_start` if present. Otherwise relative to now
    pub validity_from_start: std::time::Duration,
    pub org: &'a str,
    pub common_name: Option<&'a str>,
    pub alternative_names: Option<&'a [&'a str]>,
    pub domain: Option<&'a str>,
    pub crl_dps: Option<&'a [&'a str]>,
    pub signer: Option<&'a PkiKeypair>,
    pub is_ca: bool,
    pub is_root: bool,
}

fn get_extended_keyusage(is_ca: bool) -> x509_cert::ext::pkix::ExtendedKeyUsage {
    let mut ext_keyusages = vec![];
    if !is_ca {
        ext_keyusages.push(x509_cert::der::oid::db::rfc5280::ID_KP_CLIENT_AUTH);
    }

    x509_cert::ext::pkix::ExtendedKeyUsage(ext_keyusages)
}

fn subject(args: &CertificateGenerationArgs) -> E2eIdentityResult<Name> {
    let mut subject_fmt = String::new();
    if let Some(cn) = args.common_name {
        subject_fmt.push_str(&format!("CN={cn},"));
    }
    subject_fmt.push_str(&format!("O={},C=DE", args.org));
    Name::from_str(&subject_fmt).map_err(|_| E2eIdentityError::CertificateGenerationError)
}

fn validity(args: &CertificateGenerationArgs) -> E2eIdentityResult<Validity> {
    let validity_start = if let Some(validity_start) = args.validity_start {
        validity_start
    } else {
        web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map_err(|_| E2eIdentityError::CertificateGenerationError)?
    } - std::time::Duration::from_secs(1); // to prevent time clipping

    let not_before = x509_cert::der::asn1::GeneralizedTime::from_unix_duration(validity_start)
        .map_err(|_| E2eIdentityError::CertificateGenerationError)?
        .into();
    let not_after =
        x509_cert::der::asn1::GeneralizedTime::from_unix_duration(validity_start + args.validity_from_start)
            .map_err(|_| E2eIdentityError::CertificateGenerationError)?
            .into();
    Ok(Validity::new(not_before, not_after))
}

fn add_crl_distribution_points<P: BuilderProfile>(
    builder: &mut CertificateBuilder<P>,
    args: &CertificateGenerationArgs,
) -> E2eIdentityResult<()> {
    if let Some(crl_dps) = args.crl_dps {
        let mut crl_distribution_points = vec![];
        for dp in crl_dps {
            crl_distribution_points.push(x509_cert::ext::pkix::crl::dp::DistributionPoint {
                distribution_point: Some(x509_cert::ext::pkix::name::DistributionPointName::FullName(vec![
                    x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                        dp.to_string()
                            .try_into()
                            .map_err(|_| E2eIdentityError::CertificateGenerationError)?,
                    ),
                ])),
                crl_issuer: None,
                reasons: None,
            });
        }
        builder
            .add_extension(&x509_cert::ext::pkix::CrlDistributionPoints(crl_distribution_points))
            .map_err(|_| E2eIdentityError::CertificateGenerationError)?;
    }
    Ok(())
}

fn generate_cert_root<Signature: spki::SignatureBitStringEncoding, S>(
    args: &CertificateGenerationArgs,
    issuer_spki: spki::SubjectPublicKeyInfoOwned,
    keypair: S,
) -> E2eIdentityResult<x509_cert::Certificate>
where
    S: signature::Signer<Signature> + spki::SignatureAlgorithmIdentifier + signature::KeypairRef,
    S::VerifyingKey: spki::EncodePublicKey,
{
    let subject = subject(args)?;
    let validity = validity(args)?;
    let serial_number = x509_cert::serial_number::SerialNumber::from(args.serial);

    let profile = x509_cert::builder::profile::cabf::Root::new(false, subject).expect("create root profile");
    let mut builder = CertificateBuilder::new(profile, serial_number, validity, issuer_spki)
        .map_err(|_| E2eIdentityError::CertificateGenerationError)?;

    builder
        .add_extension(&args.signer.unwrap().akid()?)
        .map_err(|_| E2eIdentityError::CertificateGenerationError)?;
    builder
        .add_extension(&get_extended_keyusage(true))
        .map_err(|_| E2eIdentityError::CertificateGenerationError)?;

    let mut permitted_subtrees = vec![
        x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
            args.org
                .to_string()
                .try_into()
                .map_err(|_| E2eIdentityError::CertificateGenerationError)?,
        ),
        x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
            args.org
                .to_string()
                .try_into()
                .map_err(|_| E2eIdentityError::CertificateGenerationError)?,
        ),
    ];

    if let Some(domain) = args.domain {
        // Add Domain DNS SAN
        builder
            .add_extension(&x509_cert::ext::pkix::SubjectAltName(vec![
                x509_cert::ext::pkix::name::GeneralName::DnsName(
                    domain
                        .to_string()
                        .try_into()
                        .map_err(|_| E2eIdentityError::CertificateGenerationError)?,
                ),
            ]))
            .map_err(|_| E2eIdentityError::CertificateGenerationError)?;

        permitted_subtrees.push(x509_cert::ext::pkix::name::GeneralName::DnsName(
            domain
                .to_string()
                .try_into()
                .map_err(|_| E2eIdentityError::CertificateGenerationError)?,
        ));
    }

    add_crl_distribution_points(&mut builder, args)?;

    builder
        .build::<_, Signature>(&keypair)
        .map_err(|_| E2eIdentityError::CertificateGenerationError)
}

fn generate_cert_intermediate<Signature: spki::SignatureBitStringEncoding, S>(
    args: &CertificateGenerationArgs,
    issuer: Name,
    issuer_spki: spki::SubjectPublicKeyInfoOwned,
    keypair: S,
) -> E2eIdentityResult<x509_cert::Certificate>
where
    S: signature::Signer<Signature> + spki::SignatureAlgorithmIdentifier + signature::KeypairRef,
    S::VerifyingKey: spki::EncodePublicKey,
{
    let subject = subject(args)?;
    let validity = validity(args)?;
    let serial_number = x509_cert::serial_number::SerialNumber::from(args.serial);

    let profile = x509_cert::builder::profile::cabf::tls::Subordinate {
        issuer,
        subject,
        path_len_constraint: Some(1),
        emits_ocsp_response: false,
        client_auth: false,
    };
    let mut builder = CertificateBuilder::new(profile, serial_number, validity, issuer_spki)
        .map_err(|_| E2eIdentityError::CertificateGenerationError)?;

    builder
        .add_extension(&get_extended_keyusage(true))
        .map_err(|_| E2eIdentityError::CertificateGenerationError)?;

    let mut permitted_subtrees = vec![
        x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
            args.org
                .to_string()
                .try_into()
                .map_err(|_| E2eIdentityError::CertificateGenerationError)?,
        ),
        x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
            args.org
                .to_string()
                .try_into()
                .map_err(|_| E2eIdentityError::CertificateGenerationError)?,
        ),
    ];

    if let Some(domain) = args.domain {
        // Add Domain DNS SAN
        builder
            .add_extension(&x509_cert::ext::pkix::SubjectAltName(vec![
                x509_cert::ext::pkix::name::GeneralName::DnsName(
                    domain
                        .to_string()
                        .try_into()
                        .map_err(|_| E2eIdentityError::CertificateGenerationError)?,
                ),
            ]))
            .map_err(|_| E2eIdentityError::CertificateGenerationError)?;

        permitted_subtrees.push(x509_cert::ext::pkix::name::GeneralName::DnsName(
            domain
                .to_string()
                .try_into()
                .map_err(|_| E2eIdentityError::CertificateGenerationError)?,
        ));
    }

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
        .map_err(|_| E2eIdentityError::CertificateGenerationError)?;

    add_crl_distribution_points(&mut builder, args)?;

    builder
        .build::<_, Signature>(&keypair)
        .map_err(|_| E2eIdentityError::CertificateGenerationError)
}

struct EndEntity {
    pub issuer: Name,
    pub subject: Name,
}

use x509_cert::ext::{
    Extension, ToExtension,
    pkix::{AuthorityKeyIdentifier, KeyUsage, KeyUsages},
};

impl BuilderProfile for EndEntity {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: spki::SubjectPublicKeyInfoRef<'_>,
        issuer_spk: spki::SubjectPublicKeyInfoRef<'_>,
        tbs: &x509_cert::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let mut extensions: Vec<Extension> = vec![];

        let akid = AuthorityKeyIdentifier::try_from(issuer_spk.clone())?;
        extensions.push(akid.to_extension(tbs.subject(), &extensions)?);

        let key_usage = KeyUsage(KeyUsages::DigitalSignature.into());
        extensions.push(key_usage.to_extension(tbs.subject(), &extensions)?);

        Ok(extensions)
    }
}

fn generate_cert_end_entity<Signature: spki::SignatureBitStringEncoding, S>(
    args: &CertificateGenerationArgs,
    issuer: Name,
    issuer_spki: spki::SubjectPublicKeyInfoOwned,
    keypair: S,
) -> E2eIdentityResult<x509_cert::Certificate>
where
    S: signature::Signer<Signature> + spki::SignatureAlgorithmIdentifier + signature::KeypairRef,
    S::VerifyingKey: spki::EncodePublicKey,
{
    let subject = subject(args)?;
    let validity = validity(args)?;
    let serial_number = x509_cert::serial_number::SerialNumber::from(args.serial);

    let profile = EndEntity { subject, issuer };
    let mut builder = CertificateBuilder::new(profile, serial_number, validity, issuer_spki)
        .map_err(|_| E2eIdentityError::CertificateGenerationError)?;

    builder
        .add_extension(&get_extended_keyusage(false))
        .map_err(|_| E2eIdentityError::CertificateGenerationError)?;

    if let Some(alt_names) = args.alternative_names {
        let mut alt_names_list = vec![];
        for alt_name in alt_names {
            alt_names_list.push(x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                alt_name
                    .to_string()
                    .try_into()
                    .map_err(|_| E2eIdentityError::CertificateGenerationError)?,
            ));
        }

        builder
            .add_extension(&x509_cert::ext::pkix::SubjectAltName(alt_names_list))
            .map_err(|_| E2eIdentityError::CertificateGenerationError)?;
    }

    add_crl_distribution_points(&mut builder, args)?;

    builder
        .build::<_, Signature>(&keypair)
        .map_err(|_| E2eIdentityError::CertificateGenerationError)
}

impl PkiKeypair {
    pub fn new(signature_scheme: SignatureScheme, sk: Vec<u8>) -> E2eIdentityResult<Self> {
        match signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(PkiKeypair::P256(
                p256::ecdsa::SigningKey::from_slice(sk.as_slice())
                    .map_err(|_| E2eIdentityError::CertificateGenerationError)?,
            )),
            SignatureScheme::ECDSA_SECP384R1_SHA384 => Ok(PkiKeypair::P384(
                p384::ecdsa::SigningKey::from_slice(sk.as_slice())
                    .map_err(|_| E2eIdentityError::CertificateGenerationError)?,
            )),
            SignatureScheme::ECDSA_SECP521R1_SHA512 => Ok(PkiKeypair::P521(
                p521::ecdsa::SigningKey::from_slice(sk.as_slice())
                    .map_err(|_| E2eIdentityError::CertificateGenerationError)?,
            )),
            SignatureScheme::ED25519 => Ok(PkiKeypair::Ed25519(ed25519_dalek::SigningKey::from_bytes(
                sk.as_slice()
                    .try_into()
                    .expect("private key must be exactly {ed25519_dalek::SECRET_KEY_LENGTH} bytes"),
            ))),
            _ => Err(E2eIdentityError::UnsupportedSignatureScheme),
        }
    }

    pub fn signature_algorithm(&self) -> spki::AlgorithmIdentifierRef<'_> {
        match self {
            Self::P256(_) => p256::ecdsa::SigningKey::SIGNATURE_ALGORITHM_IDENTIFIER,
            Self::P384(_) => p384::ecdsa::SigningKey::SIGNATURE_ALGORITHM_IDENTIFIER,
            Self::P521(_) => spki::AlgorithmIdentifierRef {
                oid: ecdsa::ECDSA_SHA512_OID,
                parameters: None,
            },
            Self::Ed25519(_) => ed25519_dalek::pkcs8::ALGORITHM_ID,
        }
    }

    pub fn spki(&self) -> E2eIdentityResult<spki::SubjectPublicKeyInfoOwned> {
        match self {
            Self::P256(sk) => Ok(spki::SubjectPublicKeyInfoOwned::from_key(sk.verifying_key())
                .map_err(|_| E2eIdentityError::CertificateGenerationError)?),
            Self::P384(sk) => Ok(spki::SubjectPublicKeyInfoOwned::from_key(sk.verifying_key())
                .map_err(|_| E2eIdentityError::CertificateGenerationError)?),
            Self::P521(sk) => Ok(spki::SubjectPublicKeyInfoOwned::from_key(sk.verifying_key())
                .map_err(|_| E2eIdentityError::CertificateGenerationError)?),
            Self::Ed25519(sk) => Ok(spki::SubjectPublicKeyInfoOwned::from_key(&sk.verifying_key())
                .map_err(|_| E2eIdentityError::CertificateGenerationError)?),
        }
    }

    pub fn akid(&self) -> E2eIdentityResult<x509_cert::ext::pkix::AuthorityKeyIdentifier> {
        Ok(x509_cert::ext::pkix::AuthorityKeyIdentifier {
            key_identifier: Some(
                spki::der::asn1::OctetString::new(self.public_key_identifier())
                    .map_err(|_| E2eIdentityError::CertificateGenerationError)?,
            ),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        })
    }

    pub fn revoke_certs(
        &self,
        issuer_cert: &x509_cert::Certificate,
        revoked_cert_serial_numbers: Vec<Vec<u8>>,
    ) -> E2eIdentityResult<x509_cert::crl::CertificateList> {
        let signature_algorithm = self.signature_algorithm();
        let now = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map_err(|_| E2eIdentityError::CertificateGenerationError)?;
        let now = x509_cert::der::asn1::GeneralizedTime::from_unix_duration(now)
            .map_err(|_| E2eIdentityError::CertificateGenerationError)?;
        let now = x509_cert::time::Time::GeneralTime(now);

        let revoked_certificates = revoked_cert_serial_numbers
            .into_iter()
            .map(|serial_number| x509_cert::crl::RevokedCert {
                serial_number: x509_cert::serial_number::SerialNumber::new(&serial_number)
                    .expect("Non-positive serial number"),
                revocation_date: now,
                crl_entry_extensions: None,
            })
            .collect();

        let tbs_cert_list = x509_cert::crl::TbsCertList {
            version: x509_cert::Version::V3,
            signature: signature_algorithm.ref_to_owned(),
            issuer: issuer_cert.tbs_certificate().subject().clone(),
            this_update: now,
            next_update: None,
            revoked_certificates: Some(revoked_certificates),
            crl_extensions: None,
        };

        use spki::der::Encode as _;

        let tbs = tbs_cert_list
            .to_der()
            .map_err(|_| E2eIdentityError::CertificateGenerationError)?;

        use signature::Signer as _;
        let signature: Vec<u8> = match self {
            PkiKeypair::P256(sk) => {
                let signature: p256::ecdsa::Signature = sk.sign(&tbs);
                signature.to_der().to_vec()
            }
            PkiKeypair::P384(sk) => {
                let signature: p384::ecdsa::Signature = sk.sign(&tbs);
                signature.to_der().to_vec()
            }
            PkiKeypair::P521(sk) => {
                let signature: p521::ecdsa::Signature = sk.sign(&tbs);
                signature.to_der().to_vec()
            }
            PkiKeypair::Ed25519(sk) => {
                let signature = sk.sign(&tbs);
                signature.to_vec()
            }
        };

        let signature =
            spki::der::asn1::BitString::new(0, signature).map_err(|_| E2eIdentityError::CertificateGenerationError)?;

        Ok(x509_cert::crl::CertificateList {
            tbs_cert_list,
            signature_algorithm: signature_algorithm.ref_to_owned(),
            signature,
        })
    }

    pub fn generate_cert<'a>(
        &'a self,
        mut args: CertificateGenerationArgs<'a>,
    ) -> E2eIdentityResult<x509_cert::Certificate> {
        if args.signer.is_none() {
            args.signer = Some(self)
        }
        let signer = args.signer.unwrap();

        let spki = self.spki()?;
        let issuer = if let Some(ref issuer) = args.issuer {
            Name::from_str(issuer.as_ref()).unwrap()
        } else {
            Name::default()
        };

        let cert = match (args.is_root, args.is_ca) {
            (true, false) => unreachable!("cannot be a root CA without being a CA"),
            (true, true) => match signer {
                PkiKeypair::Ed25519(kp) => generate_cert_root(&args, spki, kp.clone())?,
                PkiKeypair::P256(kp) => {
                    generate_cert_root::<p256::ecdsa::DerSignature, p256::ecdsa::SigningKey>(&args, spki, kp.clone())?
                }
                PkiKeypair::P384(kp) => {
                    generate_cert_root::<p384::ecdsa::DerSignature, p384::ecdsa::SigningKey>(&args, spki, kp.clone())?
                }
                PkiKeypair::P521(kp) => {
                    generate_cert_root::<p521::ecdsa::DerSignature, p521::ecdsa::SigningKey>(&args, spki, kp.clone())?
                }
            },
            (false, true) => {
                match signer {
                    PkiKeypair::Ed25519(kp) => generate_cert_intermediate(&args, issuer, spki, kp.clone())?,
                    PkiKeypair::P256(kp) => generate_cert_intermediate::<
                        p256::ecdsa::DerSignature,
                        p256::ecdsa::SigningKey,
                    >(&args, issuer, spki, kp.clone())?,
                    PkiKeypair::P384(kp) => generate_cert_intermediate::<
                        p384::ecdsa::DerSignature,
                        p384::ecdsa::SigningKey,
                    >(&args, issuer, spki, kp.clone())?,
                    PkiKeypair::P521(kp) => generate_cert_intermediate::<
                        p521::ecdsa::DerSignature,
                        p521::ecdsa::SigningKey,
                    >(&args, issuer, spki, kp.clone())?,
                }
            }
            (false, false) => {
                match signer {
                    PkiKeypair::Ed25519(kp) => generate_cert_end_entity(&args, issuer, spki, kp.clone())?,
                    PkiKeypair::P256(kp) => generate_cert_end_entity::<
                        p256::ecdsa::DerSignature,
                        p256::ecdsa::SigningKey,
                    >(&args, issuer, spki, kp.clone())?,
                    PkiKeypair::P384(kp) => generate_cert_end_entity::<
                        p384::ecdsa::DerSignature,
                        p384::ecdsa::SigningKey,
                    >(&args, issuer, spki, kp.clone())?,
                    PkiKeypair::P521(kp) => generate_cert_end_entity::<
                        p521::ecdsa::DerSignature,
                        p521::ecdsa::SigningKey,
                    >(&args, issuer, spki, kp.clone())?,
                }
            }
        };

        Ok(cert)
    }

    pub fn rand(alg: SignatureScheme, crypto: &impl OpenMlsCrypto) -> super::E2eIdentityResult<Self> {
        Self::new(
            alg,
            crypto
                .signature_key_gen(alg)
                .map_err(|_| super::E2eIdentityError::SignatureKeyGenerationFailed)?
                .0,
        )
    }
}
