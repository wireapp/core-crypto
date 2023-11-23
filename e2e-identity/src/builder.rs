#![allow(dead_code)]

use jwt_simple::prelude::*;
pub use time::OffsetDateTime;
use x509_cert::der::EncodePem;

use rusty_jwt_tools::prelude::*;

// re-export for convenience
use crate::RustyE2eIdentity;

/// Builds a verifiable proof of identity.
/// From the built artifact, you can use [rusty_acme::prelude::WireIdentityReader] to extract
/// back the relevant claims.
/// Builds x509 certificates for now but it could also support Verifiable Credentials in the future
#[derive(Debug, Clone)]
pub struct WireIdentityBuilder {
    pub alg: SignAlgorithm,
    pub client_id: String,
    pub handle: String,
    pub display_name: String,
    pub domain: String,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
    pub options: Option<WireIdentityBuilderOptions>,
}

#[derive(Debug, Clone)]
pub enum WireIdentityBuilderOptions {
    X509(WireIdentityBuilderX509),
}

#[derive(Debug)]
pub struct WireIdentityBuilderX509 {
    pub ca_not_after: OffsetDateTime,
    pub ca_kp: Option<Vec<u8>>,
    pub provisioner_name: String,
    pub cert_kp: Option<Vec<u8>>,
}

impl Clone for WireIdentityBuilderX509 {
    fn clone(&self) -> Self {
        Self {
            ca_not_after: self.ca_not_after,
            ca_kp: None,
            provisioner_name: self.provisioner_name.clone(),
            cert_kp: None,
        }
    }
}

impl Default for WireIdentityBuilderX509 {
    fn default() -> Self {
        Self {
            ca_kp: None,
            ca_not_after: rcgen::date_time_ymd(2032, 1, 1),
            provisioner_name: "wireapp".to_string(),
            cert_kp: None,
        }
    }
}

/// Currently limited since we build the certificate with ring which does not support NIST P-curve
/// signature algorithm and we need this helper in CoreCrypto tests which are also tested in WASM.
#[derive(Debug, Clone)]
pub enum SignAlgorithm {
    Ed25519,
}

impl SignAlgorithm {
    fn spki_alg_oid(&self) -> Vec<u64> {
        match self {
            SignAlgorithm::Ed25519 => oid_registry::OID_SIG_ED25519,
        }
        .iter()
        .unwrap()
        .collect::<Vec<u64>>()
    }
}

/// For generating x509
impl WireIdentityBuilder {
    pub fn new_rand_client(domain: Option<String>) -> (String, String) {
        let rand_str = |n: usize| {
            use rand::distributions::{Alphanumeric, DistString as _};
            Alphanumeric.sample_string(&mut rand::thread_rng(), n)
        };
        let user_id = uuid::Uuid::new_v4().to_string();
        let domain = domain.unwrap_or_else(|| format!("{}.com", rand_str(6)));
        let client_id = ClientId::try_new(user_id, rand::random::<u64>(), &domain)
            .unwrap()
            .to_qualified();
        (client_id, domain)
    }

    pub fn new_key_pair(&self) -> (rcgen::KeyPair, Vec<u8>) {
        match self.alg {
            SignAlgorithm::Ed25519 => {
                let kp = rcgen::KeyPair::generate(&rcgen::PKCS_ED25519).unwrap();
                let sign_key = Self::parse_sk(&kp);
                (kp, sign_key)
            }
        }
    }

    fn parse_sk(kp: &rcgen::KeyPair) -> Vec<u8> {
        const KEY_LEN: usize = 32;
        const PRIV_KEY_IDX: usize = 16;
        const PUB_KEY_IDX: usize = 53;

        let kp_der = kp.serialize_der();
        let sk = &kp_der[PRIV_KEY_IDX..PRIV_KEY_IDX + KEY_LEN];
        let pk = &kp_der[PUB_KEY_IDX..PUB_KEY_IDX + KEY_LEN];
        [sk, pk].concat()
    }

    fn new_cert_params(&self, key_pair: rcgen::KeyPair, is_ca: bool) -> rcgen::CertificateParams {
        let mut params = rcgen::CertificateParams::new(vec![]);
        let (alg, key_id_method) = match self.alg {
            SignAlgorithm::Ed25519 => (&rcgen::PKCS_ED25519, rcgen::KeyIdMethod::Sha256),
        };
        params.alg = alg;
        params.key_pair = Some(key_pair);
        params.key_identifier_method = key_id_method;
        if is_ca {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            if let Some(WireIdentityBuilderOptions::X509(WireIdentityBuilderX509 { provisioner_name, .. })) =
                self.options.as_ref()
            {
                let mut dn = rcgen::DistinguishedName::new();
                dn.push(rcgen::DnType::OrganizationName, provisioner_name);
                params.distinguished_name = dn;
            }
        }
        params
    }

    pub fn new_ca_certificate(&self) -> rcgen::Certificate {
        // generate an issuer who is also a root ca
        let (ca_kp, ..) = self.get_ca_kp();
        let mut ca_params = self.new_cert_params(ca_kp, true);
        if let Some(WireIdentityBuilderOptions::X509(WireIdentityBuilderX509 { ca_not_after, .. })) = self.options {
            ca_params.not_after = ca_not_after;
        }
        rcgen::Certificate::from_params(ca_params).unwrap()
    }

    fn get_ca_kp(&self) -> (rcgen::KeyPair, Vec<u8>) {
        if let Some(WireIdentityBuilderOptions::X509(WireIdentityBuilderX509 { ca_kp: Some(ca_kp), .. })) =
            self.options.as_ref()
        {
            self.parse_keypair(ca_kp)
        } else {
            self.new_key_pair()
        }
    }

    fn get_cert_kp(&self) -> (rcgen::KeyPair, Vec<u8>) {
        if let Some(WireIdentityBuilderOptions::X509(WireIdentityBuilderX509 {
            cert_kp: Some(cert_kp), ..
        })) = self.options.as_ref()
        {
            self.parse_keypair(cert_kp)
        } else {
            self.new_key_pair()
        }
    }

    fn parse_keypair(&self, kp: &[u8]) -> (rcgen::KeyPair, Vec<u8>) {
        const DER_HEADER_SK_LEN: usize = 16;
        let (kp, sk) = match self.alg {
            SignAlgorithm::Ed25519 => {
                let kp = Ed25519KeyPair::from_bytes(kp).unwrap();
                // `to_der()` is the only way to get the private key
                let sk = kp.key_pair().to_der()[DER_HEADER_SK_LEN..].to_vec();
                let kp = rcgen::KeyPair::from_der(&kp.to_der()).unwrap();
                (kp, sk)
            }
        };
        (kp, sk)
    }

    pub fn build_x509(self) -> (x509_cert::PkiPath, Vec<u8>) {
        let (cert_kp, cert_sk) = self.get_cert_kp();
        // we do it this way to avoid depending on 'x509-parser' feature from rcgen which would bring
        // x509-parser crate and would force a painful ring versions alignment
        let pk_alg = rcgen::SignatureAlgorithm::from_oid(&self.alg.spki_alg_oid()[..]).unwrap();
        let pk = rcgen::PublicKey {
            alg: pk_alg,
            raw: cert_kp.public_key_raw().to_vec(),
        };

        let mut cert_params = self.new_cert_params(cert_kp, false);
        cert_params.not_before = self.not_before;
        cert_params.not_after = self.not_after;

        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::OrganizationName, self.domain.clone());
        dn.push(rcgen::DnType::CommonName, self.display_name.clone());
        cert_params.distinguished_name = dn;

        let client_id = ClientId::try_from_qualified(&self.client_id).unwrap().to_uri();
        let handle = Handle::from(self.handle.as_str()).to_qualified(&self.domain);
        cert_params.subject_alt_names = vec![rcgen::SanType::URI(client_id), rcgen::SanType::URI(handle.to_string())];

        cert_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        cert_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];

        let csr = rcgen::CertificateSigningRequest {
            params: cert_params,
            public_key: pk,
        };
        let ca = self.new_ca_certificate();
        let cert = csr.serialize_der_with_signer(&ca).unwrap();

        // now converting into RustCrypto types for convenience
        use x509_cert::der::Decode as _;

        let cert = x509_cert::Certificate::from_der(&cert).unwrap();
        let ca = ca.serialize_der().unwrap();
        let ca = x509_cert::Certificate::from_der(&ca).unwrap();
        let chain = x509_cert::PkiPath::from([cert, ca]);

        (chain, cert_sk)
    }

    pub fn build_x509_der(self) -> (Vec<Vec<u8>>, Vec<u8>) {
        let (certificate_chain, sign_key) = self.build_x509();
        use x509_cert::der::Encode as _;
        let certificate_chain = certificate_chain
            .into_iter()
            .map(|c| c.to_der().unwrap())
            .collect::<Vec<_>>();
        (certificate_chain, sign_key)
    }

    pub fn build_x509_pem(self) -> (String, Vec<u8>) {
        let (certificate_chain, sign_key) = self.build_x509();
        let certificate_chain = certificate_chain
            .into_iter()
            .map(|c| c.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap())
            .collect::<Vec<String>>()
            .join("");
        (certificate_chain, sign_key)
    }
}

impl Default for WireIdentityBuilder {
    fn default() -> Self {
        let (firstname, lastname) = ("Alice", "Smith");
        let (client_id, domain) = WireIdentityBuilder::new_rand_client(None);
        Self {
            alg: SignAlgorithm::Ed25519,
            client_id,
            handle: Handle::from("alice_wire").to_qualified("wire.com").to_string(),
            display_name: format!("{firstname} {lastname}"),
            domain,
            not_before: rcgen::date_time_ymd(1970, 1, 1),
            not_after: rcgen::date_time_ymd(2032, 1, 1),
            options: Some(WireIdentityBuilderOptions::X509(WireIdentityBuilderX509::default())),
        }
    }
}

impl RustyE2eIdentity {
    pub fn get_key_pair(&self) -> (rcgen::KeyPair, Vec<u8>) {
        match self.sign_alg {
            JwsAlgorithm::Ed25519 => {
                const KEY_LEN: usize = 32;

                let kp = Ed25519KeyPair::from_pem(self.sign_kp.as_str()).unwrap();
                let rcgen_kp = rcgen::KeyPair::from_der(&kp.to_der()).unwrap();
                let sk = kp.key_pair().to_bytes()[KEY_LEN..].to_vec();
                (rcgen_kp, sk)
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use rusty_acme::prelude::WireIdentityReader as _;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test]
    fn should_have_expected_identity_claims() {
        let client_id = "t6wRpI8BRSeviBwwiFp5MQ:6bf3531c4811b575@wire.com";
        let handle = "alice_wire";
        let display_name = "Alice Smith";
        let domain = "wire.com";
        let builder = WireIdentityBuilder {
            alg: SignAlgorithm::Ed25519,
            client_id: client_id.to_string(),
            handle: handle.to_string(),
            display_name: display_name.to_string(),
            domain: domain.to_string(),
            ..Default::default()
        };
        let (cert_chain, ..) = builder.build_x509();
        let cert = cert_chain.get(0).unwrap();
        let identity = cert.extract_identity().unwrap();
        assert_eq!(&identity.client_id, client_id);
        assert_eq!(
            identity.handle.as_str(),
            Handle::from(handle).to_qualified(domain).as_str()
        );
        assert_eq!(&identity.display_name, display_name);
        assert_eq!(&identity.domain, domain);
    }

    #[test]
    #[wasm_bindgen_test]
    fn default_should_be_valid() {
        let (cert_chain, ..) = WireIdentityBuilder::default().build_x509();
        let cert = cert_chain.get(0).unwrap();
        assert!(cert.extract_identity().is_ok());
    }
}
