use std::time::Duration;

use mls_crypto_provider::{CertProfile, CertificateGenerationArgs, PkiKeypair, RustCrypto};
use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, types::SignatureScheme};

const DEFAULT_CRL_DOMAIN: &'static str = "localhost";

/// Params for generating the Certificate chain
#[derive(Debug, Clone)]
pub struct CertificateParams {
    pub org: String,
    pub common_name: Option<String>,
    pub handle: Option<String>,
    pub client_id: Option<String>,
    pub domain: Option<String>,
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

#[derive(Debug)]
pub struct X509TestChain {
    pub trust_anchor: X509Certificate,
    pub intermediates: Vec<X509Certificate>,
    pub crls: std::collections::HashMap<String, x509_cert::crl::CertificateList>,
    pub actors: Vec<X509TestChainActor>,
}

#[derive(Debug)]
pub struct X509TestChainArgs<'a> {
    pub root_params: CertificateParams,
    pub local_ca_params: CertificateParams,
    pub signature_scheme: SignatureScheme,
    pub federated_test_chains: &'a [X509TestChain],
    pub local_actors: Vec<X509TestChainActorArg>,
    pub dump_pem_certs: bool,
}

impl X509TestChain {
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

        let mut actors: Vec<_> = args
            .local_actors
            .into_iter()
            .map(|actor| {
                let certificate = local_intermediate.create_and_sign_end_identity(CertificateParams {
                    org: args.local_ca_params.org.clone(),
                    common_name: Some(actor.name.clone()),
                    handle: Some(actor.handle.clone()),
                    client_id: Some(actor.client_id.clone()),
                    domain: args.local_ca_params.domain.clone(),
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

        let revoked_serial_numbers: Vec<u32> = actors
            .iter()
            .filter(|actor| actor.is_revoked)
            .map(|actor| {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(actor.certificate.certificate.tbs_certificate.serial_number.as_bytes());
                u32::from_le_bytes(bytes)
            })
            .collect();

        let local_crl_dp = local_intermediate.crl_dps.first().unwrap().clone();

        let crl = local_intermediate
            .pki_keypair
            .revoke_certs(&local_intermediate.certificate, revoked_serial_numbers)
            .unwrap();

        crls.insert(local_crl_dp, crl);

        let mut intermediates = vec![local_intermediate];
        for federated_chain in args.federated_test_chains {
            crls.extend(federated_chain.crls.clone());

            for fed_intermediate in &federated_chain.intermediates {
                let cross_signed_intermediate = trust_anchor.cross_sign_intermediate(fed_intermediate);

                if args.dump_pem_certs {
                    use x509_cert::der::EncodePem as _;
                    println!(
                        "{} => \n{}",
                        cross_signed_intermediate
                            .certificate
                            .tbs_certificate
                            .subject
                            .to_string(),
                        cross_signed_intermediate
                            .certificate
                            .to_pem(x509_cert::der::pem::LineEnding::LF)
                            .unwrap()
                    );
                }

                intermediates.push(cross_signed_intermediate);
            }

            actors.extend(federated_chain.actors.clone());
        }

        Self {
            trust_anchor,
            intermediates,
            crls,
            actors,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum X509CertificateType {
    Root,
    IntermediateCA,
    EndIdentity,
}

#[derive(Clone, Debug)]
pub struct X509Certificate {
    pub pki_keypair: PkiKeypair,
    pub signature_scheme: SignatureScheme,
    pub certificate: x509_cert::Certificate,
    pub cert_type: X509CertificateType,
    pub crl_dps: Vec<String>,
}

impl X509Certificate {
    pub fn create_root_cert_ta(params: CertificateParams, signature_scheme: SignatureScheme) -> Self {
        let crypto = RustCrypto::default();
        let serial = u16::from_le_bytes(crypto.random_array().unwrap());

        let (sk, _) = crypto.signature_key_gen(signature_scheme).unwrap();
        let pki_keypair = PkiKeypair::new(signature_scheme, sk).unwrap();

        let crl_dps = vec![params.get_crl_dp()];

        let certificate = pki_keypair
            .generate_cert(CertificateGenerationArgs {
                signature_scheme,
                profile: CertProfile::Root,
                serial: serial as _,
                validity_from_now: params.expiration,
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
            crl_dps,
        }
    }

    pub fn create_and_sign_intermediate(&self, params: CertificateParams) -> X509Certificate {
        let crypto = RustCrypto::default();
        let signature_scheme = self.signature_scheme;
        let (sk, _) = crypto.signature_key_gen(signature_scheme).unwrap();
        let pki_keypair = PkiKeypair::new(signature_scheme, sk).unwrap();
        let serial = u16::from_le_bytes(crypto.random_array().unwrap());

        let crl_dps = vec![params.get_crl_dp()];

        let certificate = pki_keypair
            .generate_cert(CertificateGenerationArgs {
                signature_scheme,
                profile: CertProfile::SubCA {
                    issuer: self.certificate.tbs_certificate.subject.clone(),
                    path_len_constraint: Some(1),
                },
                serial: serial as _,
                validity_from_now: params.expiration,
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
            crl_dps,
        }
    }

    pub fn cross_sign_intermediate(&self, intermediate: &X509Certificate) -> X509Certificate {
        let cross_signed_cert = self
            .pki_keypair
            .re_sign(&self.certificate, &intermediate.certificate)
            .unwrap();

        Self {
            certificate: cross_signed_cert,
            pki_keypair: intermediate.pki_keypair.clone(),
            cert_type: intermediate.cert_type,
            signature_scheme: intermediate.signature_scheme,
            crl_dps: vec![],
        }
    }

    pub fn create_and_sign_end_identity(&self, params: CertificateParams) -> X509Certificate {
        let crypto = RustCrypto::default();
        let signature_scheme = self.signature_scheme;
        let (sk, _) = crypto.signature_key_gen(signature_scheme).unwrap();
        let pki_keypair = PkiKeypair::new(signature_scheme, sk).unwrap();
        let serial = u16::from_le_bytes(crypto.random_array().unwrap());

        let crl_dps = vec![params.get_crl_dp()];

        let mut alternative_names = vec![];
        if let Some(handle) = &params.handle {
            if let Some(domain) = &params.domain {
                let qualified_handle = wire_e2e_identity::prelude::Handle::from(handle.as_str())
                    .try_to_qualified(domain.as_str())
                    .unwrap();

                alternative_names.push(qualified_handle.to_string());
            } else {
                alternative_names.push(handle.clone());
            }
        }

        if let Some(client_id) = &params.client_id {
            let qualified_client_id = wire_e2e_identity::prelude::E2eiClientId::try_from_qualified(&client_id)
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
                },
                serial: serial as _,
                validity_from_now: params.expiration,
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
            crl_dps,
        }
    }
}
