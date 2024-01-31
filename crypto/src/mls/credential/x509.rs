use openmls_traits::types::SignatureScheme;
use wire_e2e_identity::prelude::WireIdentityReader;
use zeroize::Zeroize;

#[cfg(test)]
use wire_e2e_identity::prelude::{WireIdentityBuilder, WireIdentityBuilderOptions, WireIdentityBuilderX509};

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

        let identity = leaf.extract_identity().map_err(|_| CryptoError::InvalidIdentity)?;
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
impl From<crate::test_utils::x509::X509Certificate> for CertificateBundle {
    fn from(cert: crate::test_utils::x509::X509Certificate) -> Self {
        use x509_cert::der::Encode as _;

        Self {
            certificate_chain: vec![cert.certificate.to_der().unwrap()],
            private_key: CertificatePrivateKey {
                value: cert.pki_keypair.signing_key_bytes(),
                signature_scheme: cert.signature_scheme,
            },
        }
    }
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
        Self::new(&handle, &display_name, None, signer)
    }

    /// Generates a certificate that is later turned into a [openmls::prelude::CredentialBundle]
    pub fn new(
        handle: &str,
        display_name: &str,
        client_id: Option<&crate::e2e_identity::id::QualifiedE2eiClientId>,
        signer: &crate::test_utils::x509::X509Certificate,
    ) -> Self {
        // here in our tests client_id is generally just "alice" or "bob"
        // so we will use it to augment handle & display_name
        // and not a real client_id, instead we'll generate a random one
        let domain = "wire.com";
        let (client_id, domain) = client_id
            .map(|cid| {
                let cid = String::from_utf8(cid.to_vec()).unwrap();
                (cid, domain.to_string())
            })
            .unwrap_or_else(|| WireIdentityBuilder::new_rand_client(Some(domain.to_string())));

        let cert = signer.create_and_sign_end_identity(crate::test_utils::x509::CertificateParams {
            org: "Wire".to_string(),
            domain: domain.into(),
            common_name: Some(display_name.to_string()),
            handle: Some(handle.to_string()),
            client_id: Some(client_id.to_string()),
            ..Default::default()
        });

        cert.into()
    }

    // pub fn new_from_builder(builder: WireIdentityBuilder, sc: SignatureScheme) -> Self {
    //     let (certificate_chain, sign_key) = builder.build_x509_der();
    //     Self {
    //         certificate_chain,
    //         private_key: CertificatePrivateKey {
    //             value: sign_key,
    //             signature_scheme: sc,
    //         },
    //     }
    // }

    pub fn rand_identifier(
        name: &str,
        signers: &[crate::test_utils::x509::X509Certificate],
    ) -> crate::prelude::ClientIdentifier {
        crate::prelude::ClientIdentifier::X509(
            signers
                .iter()
                .map(|signer| (signer.signature_scheme, Self::rand(&name.into(), signer)))
                .collect::<std::collections::HashMap<_, _>>(),
        )
    }
}
