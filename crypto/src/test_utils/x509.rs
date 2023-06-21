use std::time::Duration;

use openmls_traits::types::SignatureScheme;
use time::OffsetDateTime;
use x509_cert::{
    der::{Decode, Encode},
    Certificate, PkiPath,
};

use crate::mls::credential::trust_anchor::{extract_domain_names, PerDomainTrustAnchor};

/// Params for generating the Certificate chain
#[derive(Debug, Clone)]
pub struct CertificateParams {
    pub org: String,
    pub common_name: Option<String>,
    pub domain: Option<String>,
    pub expiration: Duration,
}

impl PerDomainTrustAnchor {
    pub fn into_mls_unchecked(self) -> openmls::extensions::PerDomainTrustAnchor {
        let certificate_chain = pem::parse_many(&self.intermediate_certificate_chain)
            .unwrap()
            .into_iter()
            .map(|p| p.into_contents())
            .collect();
        openmls::extensions::PerDomainTrustAnchor::new(
            self.domain_name.into(),
            openmls::prelude::CredentialType::X509,
            certificate_chain,
        )
        .unwrap()
    }
}

impl From<PkiPath> for PerDomainTrustAnchor {
    fn from(chain: PkiPath) -> Self {
        let domains = extract_domain_names(&chain[0]).unwrap_or_default();
        let pems = chain
            .iter()
            .map(|c| pem::Pem::new("CERTIFICATE", c.to_der().unwrap()))
            .collect::<Vec<_>>();
        Self {
            domain_name: domains.get(0).cloned().unwrap_or_default(),
            intermediate_certificate_chain: pem::encode_many(&pems),
        }
    }
}

impl From<Certificate> for PerDomainTrustAnchor {
    fn from(cert: Certificate) -> Self {
        let mut domains = extract_domain_names(&cert).unwrap_or_default();
        let pem = pem::Pem::new("CERTIFICATE", cert.to_der().unwrap());
        Self {
            domain_name: domains.remove(0),
            intermediate_certificate_chain: pem::encode(&pem),
        }
    }
}

/// Create a certificate chain with a CA and a Leaf for usage with the certificate trust anchors
/// extension
pub fn create_intermediate_certificates(cert_params: CertificateParams, signature_scheme: SignatureScheme) -> PkiPath {
    let ca_params = CertificateParams {
        org: "World Domination Inc".to_string(),
        common_name: Some("World Domination".to_string()),
        domain: Some("world.com".to_string()),
        expiration: Duration::from_secs(10),
    };
    let key_pair = rcgen::KeyPair::generate(signature_scheme.rcgen_signature_alg()).unwrap();
    let ca_params = new_cert_params(key_pair, signature_scheme, ca_params, true);
    let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();
    let leaf_key = rcgen::KeyPair::generate(signature_scheme.rcgen_signature_alg()).unwrap();
    let pk = leaf_key.public_key_raw().to_vec();
    let leaf_params = new_cert_params(leaf_key, signature_scheme, cert_params, false);
    let csr = rcgen::CertificateSigningRequest {
        params: leaf_params,
        public_key: rcgen::PublicKey {
            alg: signature_scheme.rcgen_signature_alg(),
            raw: pk,
        },
    };
    let cert = csr.serialize_der_with_signer(&ca_cert).unwrap();
    let ca_cert = ca_cert.serialize_der().unwrap();

    PkiPath::from([
        Certificate::from_der(&cert).unwrap(),
        Certificate::from_der(&ca_cert).unwrap(),
    ])
}

/// Create a single certificate
pub fn create_single_certificate(
    cert_params: CertificateParams,
    signature_scheme: SignatureScheme,
    is_ca: bool,
) -> Certificate {
    let key_pair = rcgen::KeyPair::generate(signature_scheme.rcgen_signature_alg()).unwrap();
    let params = new_cert_params(key_pair, signature_scheme, cert_params, is_ca);
    let cert = rcgen::Certificate::from_params(params).unwrap();
    Certificate::from_der(&cert.serialize_der().unwrap()).unwrap()
}

fn new_cert_params(
    key_pair: rcgen::KeyPair,
    signature_scheme: SignatureScheme,
    cert_params: CertificateParams,
    is_ca: bool,
) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(vec![]);
    params.alg = signature_scheme.rcgen_signature_alg();
    params.key_pair = Some(key_pair);
    params.key_identifier_method = signature_scheme.rcgen_key_id_method();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::OrganizationName, cert_params.org);
    if let Some(common_name) = cert_params.common_name {
        dn.push(rcgen::DnType::CommonName, common_name);
    }
    if let Some(domain) = cert_params.domain {
        params.subject_alt_names = vec![rcgen::SanType::DnsName(domain)];
    }

    if is_ca {
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    }
    params.distinguished_name = dn;
    params.not_before = OffsetDateTime::now_utc() - Duration::from_secs(10);
    params.not_after = OffsetDateTime::now_utc() + cert_params.expiration;
    params
}

trait SignatureSchemeEx {
    fn rcgen_key_id_method(&self) -> rcgen::KeyIdMethod;
    fn rcgen_signature_alg(&self) -> &'static rcgen::SignatureAlgorithm;
}

#[cfg(not(target_family = "wasm"))]
impl SignatureSchemeEx for SignatureScheme {
    fn rcgen_key_id_method(&self) -> rcgen::KeyIdMethod {
        match self {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => rcgen::KeyIdMethod::Sha256,
            SignatureScheme::ECDSA_SECP384R1_SHA384 => rcgen::KeyIdMethod::Sha384,
            SignatureScheme::ED25519 => rcgen::KeyIdMethod::Sha256,
            _ => panic!("Unsupported signature scheme"),
        }
    }

    fn rcgen_signature_alg(&self) -> &'static rcgen::SignatureAlgorithm {
        match self {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            SignatureScheme::ECDSA_SECP384R1_SHA384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            SignatureScheme::ED25519 => &rcgen::PKCS_ED25519,
            _ => panic!("Unsupported signature scheme"),
        }
    }
}

#[cfg(target_family = "wasm")]
impl SignatureSchemeEx for SignatureScheme {
    fn rcgen_key_id_method(&self) -> rcgen::KeyIdMethod {
        match self {
            SignatureScheme::ED25519 => rcgen::KeyIdMethod::Sha256,
            _ => panic!("Unsupported signature scheme"),
        }
    }

    fn rcgen_signature_alg(&self) -> &'static rcgen::SignatureAlgorithm {
        match self {
            SignatureScheme::ED25519 => &rcgen::PKCS_ED25519,
            _ => panic!("Unsupported signature scheme"),
        }
    }
}
