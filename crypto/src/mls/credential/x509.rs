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

    /// Reads the 'Not Before' claim from the leaf certificate
    pub fn get_created_at(&self) -> CryptoResult<u64> {
        let leaf = self.certificate_chain.get(0).ok_or(CryptoError::InvalidIdentity)?;
        leaf.extract_created_at().map_err(|_| CryptoError::InvalidIdentity)
    }
}

#[cfg(test)]
impl CertificateBundle {
    /// Generates a certificate that is later turned into a [openmls::prelude::CredentialBundle]
    pub fn rand(client_id: &ClientId, sc: openmls::prelude::SignatureScheme) -> Self {
        // here in our tests client_id is generally just "alice" or "bob"
        // so we will use it to augment handle & display_name
        // and not a real client_id, instead we'll generate a random one
        let handle = format!("{}_wire", client_id);
        let display_name = format!("{} Smith", client_id);
        Self::new(sc, &handle, &display_name, None, None)
    }

    /// Generates a certificate that is later turned into a [openmls::prelude::CredentialBundle]
    pub fn new(
        sc: openmls::prelude::SignatureScheme,
        handle: &str,
        display_name: &str,
        client_id: Option<&ClientId>,
        cert_kp: Option<Vec<u8>>,
    ) -> Self {
        // here in our tests client_id is generally just "alice" or "bob"
        // so we will use it to augment handle & display_name
        // and not a real client_id, instead we'll generate a random one
        let domain = "wire.com";
        let (client_id, domain) = client_id
            .and_then(|c| std::str::from_utf8(c.0.as_slice()).ok())
            .map(|cid| (cid.to_string(), domain.to_string()))
            .unwrap_or_else(|| {
                wire_e2e_identity::prelude::WireIdentityBuilder::new_rand_client(Some(domain.to_string()))
            });
        let builder = wire_e2e_identity::prelude::WireIdentityBuilder {
            handle: handle.to_string(),
            display_name: display_name.to_string(),
            client_id,
            domain,
            options: Some(wire_e2e_identity::prelude::WireIdentityBuilderOptions::X509(
                wire_e2e_identity::prelude::WireIdentityBuilderX509 {
                    cert_kp,
                    ..Default::default()
                },
            )),
            ..Default::default()
        };
        Self::new_from_builder(sc, builder)
    }

    pub fn new_from_builder(
        sc: openmls::prelude::SignatureScheme,
        builder: wire_e2e_identity::prelude::WireIdentityBuilder,
    ) -> Self {
        let (certificate_chain, sign_key) = builder.build_x509_der();
        Self {
            certificate_chain,
            private_key: CertificatePrivateKey {
                value: sign_key,
                signature_scheme: sc,
            },
        }
    }

    pub fn rand_identifier(
        signature_schemes: &[openmls::prelude::SignatureScheme],
        client_id: ClientId,
    ) -> crate::prelude::ClientIdentifier {
        crate::prelude::ClientIdentifier::X509(
            signature_schemes
                .iter()
                .map(|sc| (*sc, Self::rand(&client_id, *sc)))
                .collect::<std::collections::HashMap<_, _>>(),
        )
    }
}
