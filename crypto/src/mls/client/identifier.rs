use crate::prelude::{CertificateBundle, ClientId, CryptoResult};

/// Used by consumers to initializes a MLS client. Encompasses all the client types available.
/// Could be enriched later with Verifiable Presentations.
#[derive(Debug, Clone)]
pub enum ClientIdentifier {
    /// Basic keypair
    Basic(ClientId),
    /// X509 certificate
    X509(CertificateBundle),
}

impl ClientIdentifier {
    /// Extract the unique [ClientId] from an identifier. Use with parsimony as, in case of a x509
    /// certificate this leads to parsing the certificate
    pub fn get_id(&self) -> CryptoResult<std::borrow::Cow<ClientId>> {
        match self {
            ClientIdentifier::Basic(id) => Ok(std::borrow::Cow::Borrowed(id)),
            ClientIdentifier::X509(cert) => {
                let id = cert.get_client_id()?;
                Ok(std::borrow::Cow::Owned(id))
            }
        }
    }
}
