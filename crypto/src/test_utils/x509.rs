use crate::{
    e2e_identity::id::QualifiedE2eiClientId,
    mls::client::identifier::ClientIdentifier,
    prelude::E2eIdentityError,
    CryptoError,
};
use std::{fmt::Display, time::Duration};

use crate::mls::context::CentralContext;
use mls_crypto_provider::{CertProfile, CertificateGenerationArgs, MlsCryptoProvider, PkiKeypair, RustCrypto};
use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, types::SignatureScheme};
use x509_cert::der::EncodePem;

const DEFAULT_CRL_DOMAIN: &str = "localhost";

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
    /// Expiration of the certificate; It is relative to either now (when `validity_start` is not provided) or `validity_start`
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
                params.common_name.replace(format!("{} Root CA", root_cn));
            }
            params
        };
        let local_ca_params = {
            let mut params = default_params.clone();
            if let Some(root_cn) = &default_params.common_name {
                params.common_name.replace(format!("{} Intermediate CA", root_cn));
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
                params.common_name.replace(format!("{} Root CA", root_cn));
            }
            params
        };
        let local_ca_params = {
            let mut params = default_params.clone();
            if let Some(root_cn) = &default_params.common_name {
                params.common_name.replace(format!("{} Intermediate CA", root_cn));
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
                client_id: QualifiedE2eiClientId::generate_with_domain(local_ca_params.domain.as_ref().unwrap())
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

    /// Mutually cross-sign intermediate certificates from both chains.
    /// re-signed by the root of the other and added to its chain and vice-versa
    pub fn cross_sign(&mut self, other_chain: &mut Self) {
        self.crls.extend(other_chain.crls.drain());
        other_chain.crls = self.crls.clone();

        let mut self_new_intermediates = vec![];
        for intermediate in &other_chain.intermediates {
            let cross_signed_intermediate = self.trust_anchor.cross_sign_intermediate(intermediate);
            self_new_intermediates.push(cross_signed_intermediate);
        }

        let mut other_new_intermediates = vec![];
        for intermediate in &self.intermediates {
            let cross_signed_intermediate = other_chain.trust_anchor.cross_sign_intermediate(intermediate);
            other_new_intermediates.push(cross_signed_intermediate);
        }

        self.intermediates.append(&mut self_new_intermediates);
        other_chain.intermediates.append(&mut other_new_intermediates);

        for actor in self.actors.iter_mut().chain(other_chain.actors.iter_mut()) {
            actor.certificate.is_federated = true;
        }
        let self_actors = self.actors.clone();

        // doing this way to preserve the ordering of the actors
        self.actors.extend(other_chain.actors.iter().cloned());
        other_chain.actors.extend(self_actors);
    }

    pub async fn register_with_central(&self, context: &CentralContext) {
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
            Ok(_) | Err(CryptoError::E2eiError(E2eIdentityError::TrustAnchorAlreadyRegistered)) => {}
            Err(e) => panic!("{:?}", e),
        }

        for intermediate in &self.intermediates {
            context
                .e2ei_register_intermediate_ca_pem(
                    intermediate
                        .certificate
                        .to_pem(x509_cert::der::pem::LineEnding::LF)
                        .unwrap(),
                )
                .await
                .unwrap();
        }

        for (crl_dp, crl) in &self.crls {
            context
                .e2ei_register_crl(crl_dp.clone(), crl.to_der().unwrap())
                .await
                .unwrap();
        }
        context.finish().await.unwrap();
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
        let params = wire_e2e_identity::prelude::x509::revocation::PkiEnvironmentParams {
            trust_roots: &trust_roots,
            intermediates: &intermediates,
            crls: &crls,
            time_of_interest: None,
        };

        let pki_env = wire_e2e_identity::prelude::x509::revocation::PkiEnvironment::init(params).unwrap();
        backend.update_pki_env(pki_env).await.unwrap()
    }

    pub fn find_local_intermediate_ca(&self) -> &X509Certificate {
        self.intermediates
            .iter()
            .find(|cert| !cert.is_federated && cert.cert_type == X509CertificateType::IntermediateCA)
            .expect("Cannot find Local (owned) Intermediate CA. Something isn't right in the setup of X509TestChain")
    }

    pub fn find_certificate_for_actor(&self, actor_name: &str) -> Option<&X509Certificate> {
        self.actors
            .iter()
            .find_map(|actor| (actor.name == actor_name).then_some(&actor.certificate))
    }

    pub fn issue_simple_certificate_bundle(
        &mut self,
        name: &str,
        expiration: Option<std::time::Duration>,
    ) -> (ClientIdentifier, &X509Certificate) {
        let intermediate = self.find_local_intermediate_ca();

        let common_name = format!("{name} Smith");
        let handle = format!("{}_wire", name.to_lowercase());
        let client_id: String = QualifiedE2eiClientId::generate_with_domain("wire.com")
            .try_into()
            .unwrap();
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

        self.actors.push(X509TestChainActor {
            name: common_name,
            handle,
            client_id,
            is_revoked: false,
            certificate,
        });

        let cert = &self.actors.last().unwrap().certificate;

        (ClientIdentifier::X509([(sc, cert.into())].into()), cert)
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
    pub is_federated: bool,
    pub crl_dps: Vec<String>,
}

impl X509Certificate {
    pub fn create_root_cert_ta(params: CertificateParams, signature_scheme: SignatureScheme) -> Self {
        let crypto = RustCrypto::default();
        let serial = u16::from_le_bytes(crypto.random_array().unwrap());

        let crl_dps = vec![params.get_crl_dp()];
        let pki_keypair = params.cert_keypair.unwrap_or_else(|| {
            let (sk, _) = crypto.signature_key_gen(signature_scheme).unwrap();
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
        let crypto = RustCrypto::default();
        let signature_scheme = self.signature_scheme;

        let serial = u16::from_le_bytes(crypto.random_array().unwrap());

        let crl_dps = vec![params.get_crl_dp()];
        let pki_keypair = params.cert_keypair.unwrap_or_else(|| {
            let (sk, _) = crypto.signature_key_gen(signature_scheme).unwrap();
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

    pub fn cross_sign_intermediate(&self, intermediate: &X509Certificate) -> X509Certificate {
        let cross_signed_cert = self
            .pki_keypair
            .re_sign(&self.certificate, &intermediate.certificate, None)
            .unwrap();

        Self {
            certificate: cross_signed_cert,
            pki_keypair: intermediate.pki_keypair.clone(),
            cert_type: intermediate.cert_type,
            signature_scheme: intermediate.signature_scheme,
            is_federated: true,
            crl_dps: vec![],
        }
    }

    pub fn update_end_identity(&self, target: &mut X509Certificate, expiration: Option<std::time::Duration>) {
        let new_cert = self
            .pki_keypair
            .re_sign(&self.certificate, &target.certificate, expiration)
            .unwrap();
        target.certificate = new_cert;
    }

    pub fn create_and_sign_end_identity(&self, params: CertificateParams) -> X509Certificate {
        let crypto = RustCrypto::default();
        let signature_scheme = self.signature_scheme;
        let serial = u64::from_le_bytes(crypto.random_array().unwrap());

        let crl_dps = vec![params.get_crl_dp()];
        let pki_keypair = params.cert_keypair.unwrap_or_else(|| {
            let (sk, _) = crypto.signature_key_gen(signature_scheme).unwrap();
            PkiKeypair::new(signature_scheme, sk).unwrap()
        });

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
            let qualified_client_id = wire_e2e_identity::prelude::E2eiClientId::try_from_qualified(client_id)
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
