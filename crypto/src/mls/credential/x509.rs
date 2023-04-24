use openmls_traits::types::SignatureScheme;
use wire_e2e_identity::prelude::WireIdentityReader;

use crate::prelude::{ClientId, CryptoError, CryptoResult};

use zeroize::Zeroize;

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
        let leaf = self.certificate_chain.get(0).ok_or(CryptoError::InvalidIdentity)?;
        let identity = leaf.extract_identity().map_err(|_| CryptoError::InvalidIdentity)?;
        Ok(identity.client_id.as_bytes().into())
    }
}

#[cfg(test)]
impl CertificateBundle {
    /// Generates a certificate that is later turned into a [openmls::prelude::CredentialBundle]
    pub fn rand(cs: crate::prelude::MlsCiphersuite, client_id: ClientId) -> CertificateBundle {
        // here in our tests client_id is generally just "alice" or "bob"
        // so we will use it to augment handle & display_name
        // and not a real client_id, instead we'll generate a random one
        let client_id = String::from_utf8(client_id.into()).unwrap();
        let handle = format!("{}_wire", client_id);
        let display_name = format!("{} Smith", client_id);
        let (certificate_chain, sign_key) = wire_e2e_identity::prelude::WireIdentityBuilder {
            handle,
            display_name,
            ..Default::default()
        }
        .build_x509_der();
        Self {
            certificate_chain,
            private_key: CertificatePrivateKey {
                value: sign_key,
                signature_scheme: cs.signature_algorithm(),
            },
        }
    }

    pub fn rand_identifier(
        ciphersuites: &[crate::prelude::MlsCiphersuite],
        client_id: ClientId,
    ) -> crate::prelude::ClientIdentifier {
        crate::prelude::ClientIdentifier::X509(
            ciphersuites
                .iter()
                .map(|&cs| (cs, Self::rand(cs, client_id.clone())))
                .collect::<std::collections::HashMap<_, _>>(),
        )
    }
}
