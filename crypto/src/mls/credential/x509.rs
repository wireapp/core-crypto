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
impl CertificateBundle {
    /// Generates a certificate that is later turned into a [openmls::prelude::CredentialBundle]
    pub fn rand(name: &ClientId, sc: SignatureScheme) -> Self {
        // here in our tests client_id is generally just "alice" or "bob"
        // so we will use it to augment handle & display_name
        // and not a real client_id, instead we'll generate a random one
        let handle = format!("{name}_wire");
        let display_name = format!("{name} Smith");
        Self::new(sc, &handle, &display_name, None, None)
    }

    /// Generates a certificate that is later turned into a [openmls::prelude::CredentialBundle]
    pub fn new(
        sc: SignatureScheme,
        handle: &str,
        display_name: &str,
        client_id: Option<&crate::e2e_identity::id::QualifiedE2eiClientId>,
        cert_kp: Option<Vec<u8>>,
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

        let builder = WireIdentityBuilder {
            handle: handle.to_string(),
            display_name: display_name.to_string(),
            client_id,
            domain,
            options: Some(WireIdentityBuilderOptions::X509(WireIdentityBuilderX509 {
                cert_kp,
                ..Default::default()
            })),
            ..Default::default()
        };
        Self::new_from_builder(builder, sc)
    }

    pub fn new_from_builder(builder: WireIdentityBuilder, sc: SignatureScheme) -> Self {
        let (certificate_chain, sign_key) = builder.build_x509_der();
        Self {
            certificate_chain,
            private_key: CertificatePrivateKey {
                value: sign_key,
                signature_scheme: sc,
            },
        }
    }

    pub fn rand_identifier(name: &str, signature_schemes: &[SignatureScheme]) -> crate::prelude::ClientIdentifier {
        crate::prelude::ClientIdentifier::X509(
            signature_schemes
                .iter()
                .map(|sc| (*sc, Self::rand(&name.into(), *sc)))
                .collect::<std::collections::HashMap<_, _>>(),
        )
    }
}
