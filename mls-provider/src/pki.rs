use crate::error::{MlsProviderError, MlsProviderResult};
use async_lock::RwLock;
use async_lock::RwLockReadGuard;
use openmls_traits::{
    authentication_service::{CredentialAuthenticationStatus, CredentialRef},
    types::SignatureScheme,
};
use spki::SignatureAlgorithmIdentifier;
use spki::der::referenced::RefToOwned;
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct PkiEnvironmentProvider(Arc<RwLock<Option<wire_e2e_identity::prelude::x509::revocation::PkiEnvironment>>>);

impl From<wire_e2e_identity::prelude::x509::revocation::PkiEnvironment> for PkiEnvironmentProvider {
    fn from(value: wire_e2e_identity::prelude::x509::revocation::PkiEnvironment) -> Self {
        Self(Arc::new(Some(value).into()))
    }
}

impl PkiEnvironmentProvider {
    pub async fn refresh_time_of_interest(&self) {
        if let Some(pki) = self.0.write().await.as_mut() {
            let _ = pki.refresh_time_of_interest();
        }
    }

    pub async fn borrow(
        &self,
    ) -> RwLockReadGuard<Option<wire_e2e_identity::prelude::x509::revocation::PkiEnvironment>> {
        self.0.read().await
    }

    pub async fn is_env_setup(&self) -> bool {
        self.0.read().await.is_some()
    }

    pub async fn update_env(
        &self,
        env: wire_e2e_identity::prelude::x509::revocation::PkiEnvironment,
    ) -> MlsProviderResult<()> {
        self.0.write().await.replace(env);
        Ok(())
    }

    #[allow(dead_code)]
    async fn dump_certs(&self) {
        use x509_cert::der::EncodePem as _;
        let env = self.0.read().await;
        let pki_env = env.as_ref().expect("No pki env");
        for (i, ta) in pki_env.get_trust_anchors().unwrap().iter().enumerate() {
            let x509_cert::anchor::TrustAnchorChoice::Certificate(ta_cert) = &ta.decoded_ta else {
                unreachable!("Kaboom");
            };
            println!(
                "Trust Anchor #{i}: \n{}",
                ta_cert.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap()
            )
        }

        for (i, cert) in pki_env.get_intermediates().unwrap().iter().enumerate() {
            println!(
                "Intermediate #{i}: \n{}",
                cert.decoded_cert.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap()
            )
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl openmls_traits::authentication_service::AuthenticationServiceDelegate for PkiEnvironmentProvider {
    async fn validate_credential<'a>(&'a self, credential: CredentialRef<'a>) -> CredentialAuthenticationStatus {
        match credential {
            // We assume that Basic credentials are always valid
            CredentialRef::Basic { identity: _ } => CredentialAuthenticationStatus::Valid,

            CredentialRef::X509 { certificates } => {
                self.refresh_time_of_interest().await;

                let binding = self.0.read().await;
                let Some(pki_env) = binding.as_ref() else {
                    // This implies that we have a Basic client without a PKI environment setup. Hence they cannot validate X509 credentials they see.
                    // So we consider it as always valid as we have no way to assert the validity
                    return CredentialAuthenticationStatus::Valid;
                };

                use x509_cert::der::Decode as _;
                let Some(cert) = certificates
                    .first()
                    .and_then(|cert_raw| x509_cert::Certificate::from_der(cert_raw).ok())
                else {
                    return CredentialAuthenticationStatus::Invalid;
                };

                if let Err(validation_error) = pki_env.validate_cert_and_revocation(&cert) {
                    use wire_e2e_identity::prelude::x509::{
                        RustyX509CheckError,
                        reexports::certval::{Error as CertvalError, PathValidationStatus},
                    };

                    if let RustyX509CheckError::CertValError(CertvalError::PathValidation(
                        certificate_validation_error,
                    )) = validation_error
                    {
                        match certificate_validation_error {
                            PathValidationStatus::Valid
                            | PathValidationStatus::RevocationStatusNotAvailable
                            | PathValidationStatus::RevocationStatusNotDetermined => {}
                            PathValidationStatus::CertificateRevoked
                            | PathValidationStatus::CertificateRevokedEndEntity
                            | PathValidationStatus::CertificateRevokedIntermediateCa => {
                                // ? Revoked credentials are A-OK. They still degrade conversations though.
                                // return CredentialAuthenticationStatus::Revoked;
                            }
                            PathValidationStatus::InvalidNotAfterDate => {
                                // ? Expired credentials are A-OK. They still degrade conversations though.
                                // return CredentialAuthenticationStatus::Expired;
                            }
                            _ => return CredentialAuthenticationStatus::Invalid,
                        }
                    } else {
                        return CredentialAuthenticationStatus::Unknown;
                    }
                }

                CredentialAuthenticationStatus::Valid
            }
        }
    }
}

pub struct Ed25519PkiSignature(ed25519_dalek::Signature);
impl spki::SignatureBitStringEncoding for Ed25519PkiSignature {
    fn to_bitstring(&self) -> spki::der::Result<spki::der::asn1::BitString> {
        spki::der::asn1::BitString::new(0, self.0.to_vec())
    }
}

#[derive(Debug, Clone)]
pub struct Ed25519PkiKeypair(ed25519_dalek::SigningKey);

impl Ed25519PkiKeypair {
    pub fn keypair_bytes(&self) -> Vec<u8> {
        self.0.to_keypair_bytes().to_vec()
    }
}

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

#[derive(Clone)]
pub struct P521PkiVerifyingKey(ecdsa::VerifyingKey<p521::NistP521>);
impl From<ecdsa::VerifyingKey<p521::NistP521>> for P521PkiVerifyingKey {
    fn from(k: ecdsa::VerifyingKey<p521::NistP521>) -> Self {
        Self(k)
    }
}

impl std::ops::Deref for P521PkiVerifyingKey {
    type Target = ecdsa::VerifyingKey<p521::NistP521>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl p521::pkcs8::EncodePublicKey for P521PkiVerifyingKey {
    fn to_public_key_der(&self) -> spki::Result<spki::Document> {
        self.0.to_public_key_der()
    }
}

#[derive(Clone)]
pub struct P521PkiKeypair(ecdsa::SigningKey<p521::NistP521>);

impl spki::SignatureAlgorithmIdentifier for P521PkiKeypair {
    type Params = spki::ObjectIdentifier;
    const SIGNATURE_ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Self::Params> = spki::AlgorithmIdentifier {
        oid: ecdsa::ECDSA_SHA512_OID,
        parameters: None,
    };
}

impl signature::Keypair for P521PkiKeypair {
    type VerifyingKey = P521PkiVerifyingKey;
    fn verifying_key(&self) -> Self::VerifyingKey {
        (*self.0.verifying_key()).into()
    }
}

impl signature::Signer<p521::ecdsa::DerSignature> for P521PkiKeypair {
    fn try_sign(&self, message: &[u8]) -> Result<p521::ecdsa::DerSignature, p521::ecdsa::Error> {
        let sk = p521::ecdsa::SigningKey::from(self.0.clone());
        Ok(sk.try_sign(message)?.to_der())
    }
}

#[derive(Clone)]
pub enum PkiKeypair {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    P521(P521PkiKeypair),
    Ed25519(Ed25519PkiKeypair),
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
            Self::P521(sk) => sk.0.to_bytes().to_vec(),
            Self::Ed25519(sk) => sk.0.to_bytes().to_vec(),
        }
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::P256(sk) => sk.verifying_key().to_sec1_bytes().to_vec(),
            Self::P384(sk) => sk.verifying_key().to_sec1_bytes().to_vec(),
            Self::P521(sk) => sk.0.verifying_key().to_sec1_bytes().to_vec(),
            Self::Ed25519(sk) => sk.0.verifying_key().to_bytes().to_vec(),
        }
    }

    pub fn public_key_identifier(&self) -> Vec<u8> {
        use sha1::Digest as _;
        sha1::Sha1::digest(self.public_key_bytes()).to_vec()
    }
}

pub use x509_cert::builder::Profile as CertProfile;

pub struct CertificateGenerationArgs<'a> {
    pub signature_scheme: SignatureScheme,
    pub profile: CertProfile,
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

macro_rules! impl_certgen {
    (
        $signer:expr, $signer_keypair:expr, $sig_type:path,
        $profile:expr, $own_spki:expr, $serial:expr,
        $subject:expr, $org:expr, $domain:expr, $validity:expr, $alt_names:expr,
        $crl_dps:expr, $is_ca:expr, $is_root:expr
    ) => {{
        let add_akid = $is_ca && $profile == x509_cert::builder::Profile::Root;

        let mut builder = x509_cert::builder::CertificateBuilder::new(
            $profile,
            $serial,
            $validity,
            $subject,
            $own_spki,
            $signer_keypair,
        )
        .map_err(|_| MlsProviderError::CertificateGenerationError)?;

        if add_akid {
            builder
                .add_extension(&$signer.akid()?)
                .map_err(|_| MlsProviderError::CertificateGenerationError)?;
        }

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
            let mut permitted_subtrees = vec![
                x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                    format!(".{}", $org)
                        .try_into()
                        .map_err(|_| MlsProviderError::CertificateGenerationError)?,
                ),
                x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                    format!("{}", $org)
                        .try_into()
                        .map_err(|_| MlsProviderError::CertificateGenerationError)?,
                ),
            ];

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
                p256::ecdsa::SigningKey::from_slice(sk.as_slice())
                    .map_err(|_| MlsProviderError::CertificateGenerationError)?,
            )),
            SignatureScheme::ECDSA_SECP384R1_SHA384 => Ok(PkiKeypair::P384(
                p384::ecdsa::SigningKey::from_slice(sk.as_slice())
                    .map_err(|_| MlsProviderError::CertificateGenerationError)?,
            )),
            SignatureScheme::ECDSA_SECP521R1_SHA512 => Ok(PkiKeypair::P521(P521PkiKeypair(
                ecdsa::SigningKey::<p521::NistP521>::from_slice(sk.as_slice())
                    .map_err(|_| MlsProviderError::CertificateGenerationError)?,
            ))),
            SignatureScheme::ED25519 => Ok(PkiKeypair::Ed25519(Ed25519PkiKeypair(
                crate::RustCrypto::normalize_ed25519_key(sk.as_slice())
                    .map_err(|_| MlsProviderError::CertificateGenerationError)?,
            ))),
            _ => Err(MlsProviderError::UnsupportedSignatureScheme),
        }
    }

    pub fn signature_algorithm(&self) -> spki::AlgorithmIdentifierRef {
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

    pub fn spki(&self) -> MlsProviderResult<spki::SubjectPublicKeyInfoOwned> {
        match self {
            Self::P256(sk) => Ok(spki::SubjectPublicKeyInfoOwned::from_key(*sk.verifying_key())
                .map_err(|_| MlsProviderError::CertificateGenerationError)?),
            Self::P384(sk) => Ok(spki::SubjectPublicKeyInfoOwned::from_key(*sk.verifying_key())
                .map_err(|_| MlsProviderError::CertificateGenerationError)?),
            Self::P521(sk) => Ok(spki::SubjectPublicKeyInfoOwned::from_key(*sk.0.verifying_key())
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
        revoked_cert_serial_numbers: Vec<Vec<u8>>,
    ) -> MlsProviderResult<x509_cert::crl::CertificateList> {
        let signature_algorithm = self.signature_algorithm();
        let now = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map_err(|_| MlsProviderError::CertificateGenerationError)?;
        let now = x509_cert::der::asn1::GeneralizedTime::from_unix_duration(now)
            .map_err(|_| MlsProviderError::CertificateGenerationError)?;
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
            PkiKeypair::P521(sk) => {
                let sk = p521::ecdsa::SigningKey::from(sk.0.clone());
                let signature: p521::ecdsa::DerSignature = sk.try_sign(&tbs)?.to_der();

                signature
                    .to_der()
                    .map_err(|_| MlsProviderError::CertificateGenerationError)
            }
            PkiKeypair::Ed25519(sk) => Ok(sk.try_sign(&tbs)?.0.to_vec()),
        }?;

        let signature =
            spki::der::asn1::BitString::new(0, signature).map_err(|_| MlsProviderError::CertificateGenerationError)?;

        Ok(x509_cert::crl::CertificateList {
            tbs_cert_list,
            signature_algorithm: signature_algorithm.ref_to_owned(),
            signature,
        })
    }

    pub fn re_sign(
        &self,
        signer_cert: &x509_cert::Certificate,
        target: &x509_cert::Certificate,
        validity: Option<std::time::Duration>,
    ) -> MlsProviderResult<x509_cert::Certificate> {
        let mut target = target.clone();
        target.tbs_certificate.issuer = signer_cert.tbs_certificate.subject.clone();
        let akid = self.akid()?;
        use x509_cert::ext::AsExtension as _;
        // Insert AKID
        let akid_ext = akid
            .to_extension(&target.tbs_certificate.subject, &[])
            .map_err(|_| MlsProviderError::CertificateGenerationError)?;
        if let Some(exts) = &mut target.tbs_certificate.extensions {
            use x509_cert::der::oid::AssociatedOid as _;

            if let Some(akid_ext_index) = exts
                .iter_mut()
                .enumerate()
                .find_map(|(i, ext)| (ext.extn_id == x509_cert::ext::pkix::AuthorityKeyIdentifier::OID).then_some(i))
            {
                exts.remove(akid_ext_index);
                exts.insert(akid_ext_index, akid_ext);
            } else {
                exts.push(akid_ext);
            }
        } else {
            target.tbs_certificate.extensions = Some(vec![akid_ext]);
        }

        // Refresh validity if provided
        if let Some(validity) = validity {
            target.tbs_certificate.validity = x509_cert::time::Validity::from_now(validity)
                .map_err(|_| MlsProviderError::CertificateGenerationError)?;
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
            PkiKeypair::P521(sk) => {
                let sk = p521::ecdsa::SigningKey::from(sk.0.clone());
                let signature: p521::ecdsa::DerSignature = sk.try_sign(&tbs)?.to_der();

                signature
                    .to_der()
                    .map_err(|_| MlsProviderError::CertificateGenerationError)
            }
            PkiKeypair::Ed25519(sk) => Ok(sk.try_sign(&tbs)?.0.to_vec()),
        }?;

        target.signature_algorithm = self.signature_algorithm().ref_to_owned();
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

        let validity_start = if let Some(validity_start) = args.validity_start {
            validity_start
        } else {
            web_time::SystemTime::now()
                .duration_since(web_time::UNIX_EPOCH)
                .map_err(|_| MlsProviderError::CertificateGenerationError)?
        } - std::time::Duration::from_secs(1); // to prevent time clipping

        let validity = {
            let not_before = x509_cert::der::asn1::GeneralizedTime::from_unix_duration(validity_start)
                .map_err(|_| MlsProviderError::CertificateGenerationError)?
                .into();
            let not_after =
                x509_cert::der::asn1::GeneralizedTime::from_unix_duration(validity_start + args.validity_from_start)
                    .map_err(|_| MlsProviderError::CertificateGenerationError)?
                    .into();
            x509_cert::time::Validity { not_before, not_after }
        };

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
            PkiKeypair::P521(kp) => {
                impl_certgen!(
                    signer,
                    kp,
                    p521::ecdsa::DerSignature,
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

    pub fn rand_unchecked(alg: SignatureScheme) -> Self {
        let provider = crate::RustCrypto::default();
        use openmls_traits::crypto::OpenMlsCrypto;
        Self::new(alg, provider.signature_key_gen(alg).unwrap().0).unwrap()
    }

    pub fn rand(alg: SignatureScheme, crypto: &crate::RustCrypto) -> crate::MlsProviderResult<Self> {
        use openmls_traits::crypto::OpenMlsCrypto as _;
        Self::new(
            alg,
            crypto
                .signature_key_gen(alg)
                .map_err(|_| crate::MlsProviderError::UnsufficientEntropy)?
                .0,
        )
    }
}
