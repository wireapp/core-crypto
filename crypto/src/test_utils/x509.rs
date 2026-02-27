use std::{fmt::Display, time::Duration};

use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, types::SignatureScheme};
use wire_e2e_identity::legacy::id::QualifiedE2eiClientId;
use x509_cert::der::EncodePem;

use crate::{
    CertificateBundle,
    mls::session::identifier::ClientIdentifier,
    mls_provider::{CRYPTO, CertProfile, CertificateGenerationArgs, MlsCryptoProvider, PkiKeypair},
    transaction_context::TransactionContext,
};

const DOMAIN: &str = "wire.com";
const DEFAULT_CRL_DOMAIN: &str = "localhost";

pub(crate) fn qualified_e2ei_cid() -> QualifiedE2eiClientId {
    qualified_e2ei_cid_from_user_id(&uuid::Uuid::new_v4())
}

pub(crate) fn qualified_e2ei_cid_with_domain(domain: &str) -> QualifiedE2eiClientId {
    qualified_e2ei_cid_from_user_id_and_domain(&uuid::Uuid::new_v4(), domain)
}

pub(crate) fn qualified_e2ei_cid_from_user_id(user_id: &uuid::Uuid) -> QualifiedE2eiClientId {
    qualified_e2ei_cid_from_user_id_and_domain(user_id, DOMAIN)
}

pub(crate) fn qualified_e2ei_cid_from_user_id_and_domain(user_id: &uuid::Uuid, domain: &str) -> QualifiedE2eiClientId {
    use base64::Engine as _;

    let user_id = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(user_id.as_bytes());

    let device_id = rand::random::<u64>();
    let client_id = format!("{user_id}:{device_id:x}@{domain}");
    QualifiedE2eiClientId::from(wire_e2e_identity::legacy::id::ClientId::from(client_id.into_bytes()))
}

/// Params for generating the Certificate chain
#[derive(Debug, Clone)]
pub struct CertificateParams {
    pub org: String,
    pub common_name: Option<String>,
    pub handle: Option<String>,
    pub client_id: Option<String>,
    pub domain: Option<String>,
    pub cert_keypair: Option<PkiKeypair>,
    /// When the certificate becomes valid - UNIX timestamp
    pub validity_start: Option<Duration>,
    /// Expiration of the certificate; It is relative to either now (when `validity_start` is not provided) or
    /// `validity_start`
    pub expiration: Duration,
}

impl Default for CertificateParams {
    fn default() -> Self {
        Self {
            org: "world.com".into(),
            common_name: Some("World Domination".into()),
            handle: None,
            client_id: None,
            domain: Some("world.com".into()),
            cert_keypair: None,
            validity_start: None,
            expiration: std::time::Duration::from_secs(86400),
        }
    }
}

impl CertificateParams {
    fn get_crl_dp(&self) -> String {
        let crl_domain = if let Some(domain) = self.domain.as_deref() {
            domain
        } else {
            DEFAULT_CRL_DOMAIN
        };

        format!("http://{crl_domain}/crl.der")
    }
}

#[derive(Clone, Debug)]
pub struct X509TestChainActor {
    pub name: String,
    pub handle: String,
    pub client_id: String,
    pub is_revoked: bool,
    pub certificate: X509Certificate,
}

#[derive(Debug, Clone)]
pub struct X509TestChainActorArg {
    pub name: String,
    pub handle: String,
    pub client_id: String,
    pub is_revoked: bool,
}

#[derive(Debug, Clone)]
pub struct X509TestChain {
    pub trust_anchor: X509Certificate,
    pub intermediates: Vec<X509Certificate>,
    pub crls: std::collections::HashMap<String, x509_cert::crl::CertificateList>,
    pub actors: Vec<X509TestChainActor>,
}

#[derive(Debug)]
pub struct X509TestChainArgs {
    pub root_params: CertificateParams,
    pub local_ca_params: CertificateParams,
    pub signature_scheme: SignatureScheme,
    pub local_actors: Vec<X509TestChainActorArg>,
    pub dump_pem_certs: bool,
}

// Helps debugging certificate chains by printing the PEM into the stdout
impl Display for X509TestChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.trust_anchor
                .certificate
                .to_pem(x509_cert::der::pem::LineEnding::LF)
                .unwrap()
        )?;
        self.intermediates.iter().try_for_each(|certificate| {
            write!(
                f,
                "{}",
                certificate
                    .certificate
                    .to_pem(x509_cert::der::pem::LineEnding::LF)
                    .unwrap()
            )
        })?;
        writeln!(f, "actors")?;
        self.actors.iter().try_for_each(|actor| {
            write!(
                f,
                "{}",
                &actor
                    .certificate
                    .certificate
                    .to_pem(x509_cert::der::pem::LineEnding::LF)
                    .unwrap()
            )
        })
    }
}

impl X509TestChain {
    pub fn init_empty(signature_scheme: SignatureScheme) -> Self {
        let default_params = CertificateParams::default();
        let root_params = {
            let mut params = default_params.clone();
            if let Some(root_cn) = &default_params.common_name {
                params.common_name.replace(format!("{root_cn} Root CA"));
            }
            params
        };
        let local_ca_params = {
            let mut params = default_params.clone();
            if let Some(root_cn) = &default_params.common_name {
                params.common_name.replace(format!("{root_cn} Intermediate CA"));
            }
            params
        };

        X509TestChain::init(X509TestChainArgs {
            root_params,
            local_ca_params,
            signature_scheme,
            local_actors: vec![],
            dump_pem_certs: false,
        })
    }

    pub fn init_for_random_clients(signature_scheme: SignatureScheme, count: usize) -> Self {
        let default_params = CertificateParams::default();
        let root_params = {
            let mut params = default_params.clone();
            if let Some(root_cn) = &default_params.common_name {
                params.common_name.replace(format!("{root_cn} Root CA"));
            }
            params
        };
        let local_ca_params = {
            let mut params = default_params.clone();
            if let Some(root_cn) = &default_params.common_name {
                params.common_name.replace(format!("{root_cn} Intermediate CA"));
            }
            params
        };

        let actor_names = (0..count)
            .map(|i| match i {
                0 => "Alice",
                1 => "Bob",
                2 => "Charlie",
                3 => "David",
                4 => "Erin",
                5 => "Frank",
                _ => unimplemented!("Add more actor names"),
            })
            .collect::<Vec<&'static str>>();

        let local_actors = actor_names
            .into_iter()
            .map(|first_name| X509TestChainActorArg {
                name: first_name.to_string(),
                handle: format!("{}_wire", first_name.to_lowercase()),
                client_id: qualified_e2ei_cid_with_domain(local_ca_params.domain.as_ref().unwrap())
                    .try_into()
                    .unwrap(),
                is_revoked: false,
            })
            .collect();

        X509TestChain::init(X509TestChainArgs {
            root_params,
            local_ca_params,
            signature_scheme,
            local_actors,
            dump_pem_certs: false,
        })
    }

    pub fn init(args: X509TestChainArgs) -> Self {
        let trust_anchor = X509Certificate::create_root_cert_ta(args.root_params.clone(), args.signature_scheme);
        let local_intermediate = trust_anchor.create_and_sign_intermediate(args.local_ca_params.clone());

        if args.dump_pem_certs {
            use x509_cert::der::EncodePem as _;
            println!(
                "Trust Anchor => \n{}",
                trust_anchor
                    .certificate
                    .to_pem(x509_cert::der::pem::LineEnding::LF)
                    .unwrap()
            );
            println!(
                "Local Intermediate CA => \n{}",
                local_intermediate
                    .certificate
                    .to_pem(x509_cert::der::pem::LineEnding::LF)
                    .unwrap()
            );
        }

        let actors: Vec<_> = args
            .local_actors
            .into_iter()
            .map(|actor| {
                let certificate = local_intermediate.create_and_sign_end_identity(CertificateParams {
                    org: args.local_ca_params.org.clone(),
                    common_name: Some(actor.name.clone()),
                    handle: Some(actor.handle.clone()),
                    client_id: Some(actor.client_id.clone()),
                    domain: args.local_ca_params.domain.clone(),
                    cert_keypair: None,
                    validity_start: None,
                    expiration: args.local_ca_params.expiration,
                });

                if args.dump_pem_certs {
                    use x509_cert::der::EncodePem as _;
                    println!(
                        "{} [{}] | {} => \n{}",
                        actor.name,
                        actor.handle,
                        actor.client_id,
                        certificate
                            .certificate
                            .to_pem(x509_cert::der::pem::LineEnding::LF)
                            .unwrap()
                    );
                }

                X509TestChainActor {
                    name: actor.name,
                    handle: actor.handle,
                    client_id: actor.client_id,
                    certificate,
                    is_revoked: actor.is_revoked,
                }
            })
            .collect();

        let mut crls = std::collections::HashMap::new();

        let revoked_serial_numbers: Vec<Vec<u8>> = actors
            .iter()
            .filter(|&actor| actor.is_revoked)
            .map(|actor| {
                actor
                    .certificate
                    .certificate
                    .tbs_certificate
                    .serial_number
                    .as_bytes()
                    .into()
            })
            .collect();

        let local_crl_dp = local_intermediate.crl_dps.first().unwrap().clone();

        let crl = local_intermediate
            .pki_keypair
            .revoke_certs(&local_intermediate.certificate, revoked_serial_numbers)
            .unwrap();

        crls.insert(local_crl_dp, crl);

        Self {
            trust_anchor,
            intermediates: vec![local_intermediate],
            crls,
            actors,
        }
    }

    pub async fn register_with_central(&self, context: &TransactionContext) {
        use x509_cert::der::{Encode as _, EncodePem as _};
        match context
            .e2ei_register_acme_ca(
                self.trust_anchor
                    .certificate
                    .to_pem(x509_cert::der::pem::LineEnding::LF)
                    .unwrap(),
            )
            .await
        {
            Ok(_) | Err(crate::transaction_context::e2e_identity::Error::TrustAnchorAlreadyRegistered) => {}
            Err(e) => panic!("{e:?}"),
        }

        for intermediate in &self.intermediates {
            let pem = intermediate
                .certificate
                .to_pem(x509_cert::der::pem::LineEnding::LF)
                .unwrap();

            context.e2ei_register_intermediate_ca_pem(pem).await.unwrap();
        }

        for (crl_dp, crl) in &self.crls {
            context
                .e2ei_register_crl(crl_dp.clone(), crl.to_der().unwrap())
                .await
                .unwrap();
        }
    }

    pub async fn register_with_provider(&self, backend: &MlsCryptoProvider) {
        let trust_roots = vec![x509_cert::anchor::TrustAnchorChoice::Certificate(
            self.trust_anchor.certificate.clone(),
        )];
        let intermediates: Vec<_> = self
            .intermediates
            .iter()
            .map(|intermediate| intermediate.certificate.clone())
            .collect();
        let crls: Vec<_> = self.crls.values().cloned().collect();
        let params = wire_e2e_identity::x509_check::revocation::PkiEnvironmentParams {
            trust_roots: &trust_roots,
            intermediates: &intermediates,
            crls: &crls,
            time_of_interest: None,
        };

        let pki_env = wire_e2e_identity::x509_check::revocation::PkiEnvironment::init(params).unwrap();
        backend.update_pki_env(Some(pki_env)).await;
    }

    pub fn find_local_intermediate_ca(&self) -> &X509Certificate {
        self.intermediates
            .iter()
            .find(|cert| !cert.is_federated && cert.cert_type == X509CertificateType::IntermediateCA)
            .expect("Cannot find Local (owned) Intermediate CA. Something isn't right in the setup of X509TestChain")
    }

    pub fn issue_simple_certificate_bundle(
        &mut self,
        name: &str,
        expiration: Option<std::time::Duration>,
    ) -> (ClientIdentifier, &X509Certificate) {
        let intermediate = self.find_local_intermediate_ca();

        let common_name = format!("{name} Smith");
        let handle = format!("{}_wire", name.to_lowercase());
        let client_id: String = qualified_e2ei_cid_with_domain("world.com").try_into().unwrap();
        let mut cert_params = CertificateParams {
            common_name: Some(common_name.clone()),
            handle: Some(handle.clone()),
            client_id: Some(client_id.clone()),
            ..Default::default()
        };

        if let Some(expiration) = expiration {
            cert_params.expiration = expiration;
        }

        let certificate = intermediate.create_and_sign_end_identity(cert_params);

        let sc = intermediate.signature_scheme;
        let cert_bundle = CertificateBundle::from_certificate_and_issuer(&certificate, intermediate);

        self.actors.push(X509TestChainActor {
            name: common_name,
            handle,
            client_id,
            is_revoked: false,
            certificate,
        });

        let cert = &self.actors.last().unwrap().certificate;

        (ClientIdentifier::X509([(sc, cert_bundle)].into()), cert)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum X509CertificateType {
    Root,
    IntermediateCA,
    EndIdentity,
}

#[derive(Clone, derive_more::Debug)]
pub struct X509Certificate {
    pub pki_keypair: PkiKeypair,
    pub signature_scheme: SignatureScheme,
    #[debug("<elided>")]
    pub certificate: x509_cert::Certificate,
    pub cert_type: X509CertificateType,
    pub is_federated: bool,
    pub crl_dps: Vec<String>,
}

impl X509Certificate {
    pub fn create_root_cert_ta(params: CertificateParams, signature_scheme: SignatureScheme) -> Self {
        let serial = u16::from_le_bytes(CRYPTO.random_array().unwrap());

        let crl_dps = vec![params.get_crl_dp()];
        let pki_keypair = params.cert_keypair.unwrap_or_else(|| {
            let (sk, _) = CRYPTO.signature_key_gen(signature_scheme).unwrap();
            PkiKeypair::new(signature_scheme, sk).unwrap()
        });

        let certificate = pki_keypair
            .generate_cert(CertificateGenerationArgs {
                signature_scheme,
                profile: CertProfile::Root,
                serial: serial as _,
                validity_start: None,
                validity_from_start: params.expiration,
                org: &params.org,
                common_name: params.common_name.as_deref(),
                domain: params.domain.as_deref(),
                alternative_names: None,
                crl_dps: Some(&[&crl_dps[0]]),
                signer: None,
                is_ca: true,
                is_root: true,
            })
            .unwrap();

        Self {
            pki_keypair,
            signature_scheme,
            certificate,
            cert_type: X509CertificateType::Root,
            is_federated: false,
            crl_dps,
        }
    }

    pub fn create_and_sign_intermediate(&self, params: CertificateParams) -> X509Certificate {
        let signature_scheme = self.signature_scheme;

        let serial = u16::from_le_bytes(CRYPTO.random_array().unwrap());

        let crl_dps = vec![params.get_crl_dp()];
        let pki_keypair = params.cert_keypair.unwrap_or_else(|| {
            let (sk, _) = CRYPTO.signature_key_gen(signature_scheme).unwrap();
            PkiKeypair::new(signature_scheme, sk).unwrap()
        });

        let certificate = pki_keypair
            .generate_cert(CertificateGenerationArgs {
                signature_scheme,
                profile: CertProfile::SubCA {
                    issuer: self.certificate.tbs_certificate.subject.clone(),
                    path_len_constraint: Some(1),
                },
                serial: serial as _,
                validity_start: None,
                validity_from_start: params.expiration,
                org: &params.org,
                common_name: params.common_name.as_deref(),
                domain: params.domain.as_deref(),
                alternative_names: None,
                crl_dps: Some(&[&crl_dps[0]]),
                signer: Some(&self.pki_keypair),
                is_ca: true,
                is_root: false,
            })
            .unwrap();

        Self {
            pki_keypair,
            signature_scheme,
            certificate,
            cert_type: X509CertificateType::IntermediateCA,
            is_federated: false,
            crl_dps,
        }
    }

    pub fn create_and_sign_end_identity(&self, params: CertificateParams) -> X509Certificate {
        let signature_scheme = self.signature_scheme;
        let serial = u64::from_le_bytes(CRYPTO.random_array().unwrap());

        let crl_dps = vec![params.get_crl_dp()];
        let pki_keypair = params.cert_keypair.unwrap_or_else(|| {
            let (sk, _) = CRYPTO.signature_key_gen(signature_scheme).unwrap();
            PkiKeypair::new(signature_scheme, sk).unwrap()
        });

        let mut alternative_names = vec![];
        if let Some(handle) = &params.handle {
            if let Some(domain) = &params.domain {
                let qualified_handle = wire_e2e_identity::Handle::from(handle.as_str())
                    .try_to_qualified(domain.as_str())
                    .unwrap();

                alternative_names.push(qualified_handle.to_string());
            } else {
                alternative_names.push(handle.clone());
            }
        }

        if let Some(client_id) = &params.client_id {
            let qualified_client_id = wire_e2e_identity::E2eiClientId::try_from_qualified(client_id)
                .unwrap()
                .to_uri();

            alternative_names.push(qualified_client_id);
        }

        let alternative_names_ref: Vec<_> = alternative_names.iter().map(String::as_str).collect();

        let certificate = pki_keypair
            .generate_cert(CertificateGenerationArgs {
                signature_scheme,
                profile: CertProfile::Leaf {
                    issuer: self.certificate.tbs_certificate.subject.clone(),
                    enable_key_agreement: false,
                    enable_key_encipherment: false,
                    include_subject_key_identifier: true,
                },
                serial: serial as _,
                validity_start: params.validity_start,
                validity_from_start: params.expiration,
                org: &params.org,
                common_name: params.common_name.as_deref(),
                domain: params.domain.as_deref(),
                alternative_names: Some(&alternative_names_ref),
                crl_dps: Some(&[&crl_dps[0]]),
                signer: Some(&self.pki_keypair),
                is_ca: false,
                is_root: false,
            })
            .unwrap();

        Self {
            pki_keypair,
            signature_scheme,
            certificate,
            cert_type: X509CertificateType::EndIdentity,
            is_federated: false,
            crl_dps,
        }
    }
}
