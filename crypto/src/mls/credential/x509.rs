#[cfg(test)]
use crate::test_utils::x509::X509Certificate;
#[cfg(test)]
use mls_crypto_provider::PkiKeypair;
#[cfg(test)]
use x509_cert::der::Encode;

use openmls_traits::types::SignatureScheme;
use wire_e2e_identity::prelude::{HashAlgorithm, WireIdentityReader};
use zeroize::Zeroize;

use crate::{
    e2e_identity::id::WireQualifiedClientId,
    prelude::{ClientId, CryptoError, CryptoResult},
};

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct CertificatePrivateKey {
    pub(crate) value: Vec<u8>,
    #[zeroize(skip)]
    pub(crate) signature_scheme: SignatureScheme,
}

impl CertificatePrivateKey {
    pub(crate) fn into_parts(mut self) -> (Vec<u8>, SignatureScheme) {
        (std::mem::take(&mut self.value), self.signature_scheme)
    }
}

/// Represents a x509 certificate chain supplied by the client
/// It can fetch it after an end-to-end identity process where it can get back a certificate
/// from the Authentication Service
#[derive(Debug, Clone)]
pub struct CertificateBundle {
    /// x509 certificate chain
    /// First entry is the leaf certificate and each subsequent is its issuer
    pub certificate_chain: Vec<Vec<u8>>,
    /// Leaf certificate private key
    pub private_key: CertificatePrivateKey,
}

impl CertificateBundle {
    /// Reads the client_id from the leaf certificate
    pub fn get_client_id(&self) -> CryptoResult<ClientId> {
        let leaf = self.certificate_chain.first().ok_or(CryptoError::InvalidIdentity)?;

        let hash_alg = match self.private_key.signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 | SignatureScheme::ED25519 => HashAlgorithm::SHA256,
            SignatureScheme::ECDSA_SECP384R1_SHA384 => HashAlgorithm::SHA384,
            SignatureScheme::ED448 | SignatureScheme::ECDSA_SECP521R1_SHA512 => HashAlgorithm::SHA512,
        };

        let identity = leaf
            .extract_identity(None, hash_alg)
            .map_err(|_| CryptoError::InvalidIdentity)?;
        let client_id = identity.client_id.parse::<WireQualifiedClientId>()?;
        Ok(client_id.into())
    }

    /// Reads the 'Not Before' claim from the leaf certificate
    pub fn get_created_at(&self) -> CryptoResult<u64> {
        let leaf = self.certificate_chain.first().ok_or(CryptoError::InvalidIdentity)?;
        leaf.extract_created_at().map_err(|_| CryptoError::InvalidIdentity)
    }
}

#[cfg(test)]
fn new_rand_client(domain: Option<String>) -> (String, String) {
    let rand_str = |n: usize| {
        use rand::distributions::{Alphanumeric, DistString as _};
        Alphanumeric.sample_string(&mut rand::thread_rng(), n)
    };
    let user_id = uuid::Uuid::new_v4().to_string();
    let domain = domain.unwrap_or_else(|| format!("{}.com", rand_str(6)));
    let client_id = wire_e2e_identity::prelude::E2eiClientId::try_new(user_id, rand::random::<u64>(), &domain)
        .unwrap()
        .to_qualified();
    (client_id, domain)
}

#[cfg(test)]
impl CertificateBundle {
    /// Generates a certificate that is later turned into a [openmls::prelude::CredentialBundle]
    pub fn rand(name: &ClientId, signer: &crate::test_utils::x509::X509Certificate) -> Self {
        // here in our tests client_id is generally just "alice" or "bob"
        // so we will use it to augment handle & display_name
        // and not a real client_id, instead we'll generate a random one
        let handle = format!("{name}_wire");
        let display_name = format!("{name} Smith");
        Self::new(&handle, &display_name, None, None, signer)
    }

    /// Generates a certificate that is later turned into a [openmls::prelude::CredentialBundle]
    pub fn new(
        handle: &str,
        display_name: &str,
        client_id: Option<&crate::e2e_identity::id::QualifiedE2eiClientId>,
        cert_keypair: Option<PkiKeypair>,
        signer: &crate::test_utils::x509::X509Certificate,
    ) -> Self {
        Self::new_with_expiration(handle, display_name, client_id, cert_keypair, signer, None)
    }

    pub fn new_with_expiration(
        handle: &str,
        display_name: &str,
        client_id: Option<&crate::e2e_identity::id::QualifiedE2eiClientId>,
        cert_keypair: Option<PkiKeypair>,
        signer: &crate::test_utils::x509::X509Certificate,
        expiration: Option<std::time::Duration>,
    ) -> Self {
        // here in our tests client_id is generally just "alice" or "bob"
        // so we will use it to augment handle & display_name
        // and not a real client_id, instead we'll generate a random one
        let domain = "world.com";
        let (client_id, domain) = client_id
            .map(|cid| {
                let cid = String::from_utf8(cid.to_vec()).unwrap();
                (cid, domain.to_string())
            })
            .unwrap_or_else(|| new_rand_client(Some(domain.to_string())));

        let mut cert_params = crate::test_utils::x509::CertificateParams {
            domain: domain.into(),
            common_name: Some(display_name.to_string()),
            handle: Some(handle.to_string()),
            client_id: Some(client_id.to_string()),
            cert_keypair,
            ..Default::default()
        };

        if let Some(expiration) = expiration {
            cert_params.expiration = expiration;
        }

        let cert = signer.create_and_sign_end_identity(cert_params);
        Self::from_certificate_and_issuer(&cert, signer)
    }

    pub fn new_with_default_values(
        signer: &crate::test_utils::x509::X509Certificate,
        expiration: Option<std::time::Duration>,
    ) -> Self {
        Self::new_with_expiration("alice_wire@world.com", "Alice Smith", None, None, signer, expiration)
    }

    pub fn from_self_signed_certificate(cert: &X509Certificate) -> Self {
        Self::from_certificate_and_issuer(cert, cert)
    }

    pub fn from_certificate_and_issuer(cert: &X509Certificate, issuer: &X509Certificate) -> Self {
        Self {
            certificate_chain: vec![cert.certificate.to_der().unwrap(), issuer.certificate.to_der().unwrap()],
            private_key: CertificatePrivateKey {
                value: cert.pki_keypair.signing_key_bytes(),
                signature_scheme: cert.signature_scheme,
            },
        }
    }

    pub fn rand_identifier(
        name: &str,
        signers: &[&crate::test_utils::x509::X509Certificate],
    ) -> crate::prelude::ClientIdentifier {
        crate::prelude::ClientIdentifier::X509(
            signers
                .iter()
                .map(|signer| (signer.signature_scheme, Self::rand(&name.into(), signer)))
                .collect::<std::collections::HashMap<_, _>>(),
        )
    }
}
