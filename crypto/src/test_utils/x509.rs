use std::time::Duration;

use mls_crypto_provider::{CertProfile, CertificateGenerationArgs, PkiKeypair, RustCrypto};
use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, types::SignatureScheme};

const DEFAULT_CRL_DOMAIN: &'static str = "localhost";

/// Params for generating the Certificate chain
#[derive(Debug, Clone)]
pub struct CertificateParams {
    pub org: String,
    pub common_name: Option<String>,
    pub domain: Option<String>,
    pub expiration: Duration,
}

impl Default for CertificateParams {
    fn default() -> Self {
        Self {
            org: "World Domination Inc".into(),
            common_name: Some("World Domination".into()),
            domain: Some("world.com".into()),
            expiration: std::time::Duration::MAX,
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

#[derive(Clone)]
pub struct X509TestChainActor {
    pub name: String,
    pub client_id: String,
    pub certificate: X509Certificate,
}

pub struct X509TestChain {
    pub trust_anchor: X509Certificate,
    pub intermediates: Vec<X509Certificate>,
    pub crls: std::collections::HashMap<String, x509_cert::crl::CertificateList>,
    pub actors: std::collections::HashMap<String, X509TestChainActor>,
}

pub struct X509TestChainArgs<'a> {
    pub local_params: CertificateParams,
    pub signature_scheme: SignatureScheme,
    pub federated_test_chains: &'a [X509TestChain],
    pub revoked_certs: &'a [X509Certificate],
    /// List of (name, clientID); name is "alice" for example
    pub local_actors: Vec<(String, String)>,
}

impl X509TestChain {
    pub fn init(args: X509TestChainArgs) -> Self {
        let trust_anchor = X509Certificate::create_root_cert_ta(args.local_params.clone(), args.signature_scheme);
        let local_intermediate = trust_anchor.create_and_sign_intermediate(args.local_params.clone());

        let mut actors =
            args.local_actors
                .into_iter()
                .fold(std::collections::HashMap::new(), |mut acc, (name, client_id)| {
                    let certificate = local_intermediate.create_and_sign_end_identity(CertificateParams {
                        org: args.local_params.org.clone(),
                        common_name: Some(client_id.clone()),
                        domain: args.local_params.domain.clone(),
                        expiration: args.local_params.expiration,
                    });
                    let actor = X509TestChainActor {
                        name: name.clone(),
                        client_id,
                        certificate,
                    };
                    acc.insert(name, actor);
                    acc
                });

        let mut crls = std::collections::HashMap::new();

        let mut intermediates = vec![local_intermediate];
        for federated_chain in args.federated_test_chains {
            crls.extend(federated_chain.crls.clone());

            for fed_intermediate in &federated_chain.intermediates {
                intermediates.push(trust_anchor.cross_sign_intermediate(fed_intermediate));
            }

            actors.extend(federated_chain.actors.clone());
        }

        let revoked_serial_numbers: Vec<u32> = args
            .revoked_certs
            .iter()
            .map(|cert| {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(cert.certificate.tbs_certificate.serial_number.as_bytes());
                u32::from_le_bytes(bytes)
            })
            .collect();

        let local_crl_dp = trust_anchor.crl_dps.first().unwrap().clone();

        let crl = trust_anchor
            .pki_keypair
            .revoke_certs(&trust_anchor.certificate, revoked_serial_numbers)
            .unwrap();

        crls.insert(local_crl_dp, crl);

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

#[derive(Clone)]
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
                crl_dps: Some(&[&crl_dps[0]]),
                signer: None,
                is_ca: true,
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
                    path_len_constraint: None,
                },
                serial: serial as _,
                validity_from_now: std::time::Duration::MAX,
                org: &params.org,
                common_name: params.common_name.as_deref(),
                domain: params.domain.as_deref(),
                crl_dps: Some(&[&crl_dps[0]]),
                signer: Some(&self.pki_keypair),
                is_ca: true,
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

        let certificate = pki_keypair
            .generate_cert(CertificateGenerationArgs {
                signature_scheme,
                profile: CertProfile::Leaf {
                    issuer: self.certificate.tbs_certificate.issuer.clone(),
                    enable_key_agreement: false,
                    enable_key_encipherment: false,
                },
                serial: serial as _,
                validity_from_now: std::time::Duration::MAX,
                org: &params.org,
                common_name: params.common_name.as_deref(),
                domain: params.domain.as_deref(),
                crl_dps: Some(&[&crl_dps[0]]),
                signer: Some(&self.pki_keypair),
                is_ca: false,
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
