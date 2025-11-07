#[cfg(test)]
use std::collections::HashMap;
use std::fmt;

#[cfg(test)]
use mls_crypto_provider::PkiKeypair;
use openmls::prelude::Credential as MlsCredential;
use openmls_traits::types::SignatureScheme;
use openmls_x509_credential::CertificateKeyPair;
use wire_e2e_identity::prelude::{HashAlgorithm, WireIdentityReader};
#[cfg(test)]
use x509_cert::der::Encode;
use zeroize::Zeroize;

use super::{Error, Result};
#[cfg(test)]
use crate::test_utils::x509::X509Certificate;
use crate::{
    Ciphersuite, ClientId, Credential, CredentialType, MlsError, RecursiveError,
    e2e_identity::id::WireQualifiedClientId,
};

#[derive(core_crypto_macros::Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct CertificatePrivateKey {
    #[sensitive]
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
#[derive(Clone)]
pub struct CertificateBundle {
    /// x509 certificate chain
    /// First entry is the leaf certificate and each subsequent is its issuer
    pub certificate_chain: Vec<Vec<u8>>,
    /// Leaf certificate private key
    pub private_key: CertificatePrivateKey,
}

impl fmt::Debug for CertificateBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use base64::prelude::*;

        #[derive(derive_more::Debug)]
        #[debug("{}", BASE64_STANDARD.encode(_0))]
        // this only exists for the debug impl, which is ignored by the dead code check
        #[expect(dead_code)]
        struct CertificateDebugHelper<'a>(&'a Vec<u8>);

        let certificates = self
            .certificate_chain
            .iter()
            .map(CertificateDebugHelper)
            .collect::<Vec<_>>();
        f.debug_struct("CertificateBundle")
            .field("certificate_chain", &certificates)
            .field("private_key", &self.private_key)
            .finish()
    }
}

impl CertificateBundle {
    /// Reads the client_id from the leaf certificate
    pub fn get_client_id(&self) -> Result<ClientId> {
        let leaf = self.certificate_chain.first().ok_or(Error::InvalidIdentity)?;

        let hash_alg = match self.private_key.signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 | SignatureScheme::ED25519 => HashAlgorithm::SHA256,
            SignatureScheme::ECDSA_SECP384R1_SHA384 => HashAlgorithm::SHA384,
            SignatureScheme::ED448 | SignatureScheme::ECDSA_SECP521R1_SHA512 => HashAlgorithm::SHA512,
        };

        let identity = leaf
            .extract_identity(None, hash_alg)
            .map_err(|_| Error::InvalidIdentity)?;
        let client_id = identity
            .client_id
            .parse::<WireQualifiedClientId>()
            .map_err(RecursiveError::e2e_identity("parsing wire qualified client id"))?;
        Ok(client_id.into())
    }

    /// Reads the 'Not Before' claim from the leaf certificate
    pub fn get_created_at(&self) -> Result<u64> {
        let leaf = self.certificate_chain.first().ok_or(Error::InvalidIdentity)?;
        leaf.extract_created_at().map_err(|_| Error::InvalidIdentity)
    }
}

impl Credential {
    /// Create a new x509 credential from a certificate bundle.
    pub fn x509(ciphersuite: Ciphersuite, cert: CertificateBundle) -> Result<Self> {
        let earliest_validity = cert.get_created_at().map_err(RecursiveError::mls_credential(
            "getting credential 'not before' claim from leaf cert in Credential::x509",
        ))?;
        let (sk, ..) = cert.private_key.into_parts();
        let chain = cert.certificate_chain;

        let kp = CertificateKeyPair::new(sk, chain.clone()).map_err(MlsError::wrap("creating certificate key pair"))?;

        let credential = MlsCredential::new_x509(chain).map_err(MlsError::wrap("creating x509 credential"))?;

        let cb = Credential {
            ciphersuite,
            credential_type: CredentialType::X509,
            mls_credential: credential,
            signature_key_pair: kp.0,
            earliest_validity,
        };
        Ok(cb)
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
    // test functions are not held to the same standard as real functions
    #![allow(missing_docs)]

    /// Generates a certificate that is later turned into a [Credential]
    ///
    /// `name` is not known to be a qualified e2ei client id so we invent a new one
    pub fn rand(name: &ClientId, signer: &crate::test_utils::x509::X509Certificate) -> Self {
        // here in our tests client_id is generally just "alice" or "bob"
        // so we will use it to augment handle & display_name
        // and not a real client_id, instead we'll generate a random one
        let handle = format!("{name}_wire");
        let display_name = format!("{name} Smith");
        Self::new(&handle, &display_name, None, None, signer)
    }

    /// Generates a certificate that is later turned into a [Credential]
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

    pub fn rand_identifier_certs(
        client_id: &ClientId,
        signers: &[&crate::test_utils::x509::X509Certificate],
    ) -> HashMap<SignatureScheme, CertificateBundle> {
        signers
            .iter()
            .map(|signer| (signer.signature_scheme, Self::rand(client_id, signer)))
            .collect()
    }

    pub fn rand_identifier(
        client_id: &ClientId,
        signers: &[&crate::test_utils::x509::X509Certificate],
    ) -> crate::ClientIdentifier {
        crate::ClientIdentifier::X509(Self::rand_identifier_certs(client_id, signers))
    }
}
