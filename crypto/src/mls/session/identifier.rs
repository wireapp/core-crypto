use std::collections::{HashMap, HashSet};

use mls_crypto_provider::MlsCryptoProvider;
use openmls_traits::types::SignatureScheme;

use super::{
    Credential,
    error::{Error, Result},
};
use crate::{CertificateBundle, ClientId, RecursiveError, Session, mls::session::id::ClientIdRef};

/// Used by consumers to initializes a MLS client. Encompasses all the client types available.
/// Could be enriched later with Verifiable Presentations.
#[derive(Debug, Clone)]
pub enum ClientIdentifier {
    /// Basic keypair
    Basic(ClientId),
    /// X509 certificate
    X509(HashMap<SignatureScheme, CertificateBundle>),
}

impl ClientIdentifier {
    /// Extract the unique [ClientId] from an identifier. Use with parsimony as, in case of a x509
    /// certificate this leads to parsing the certificate
    pub fn get_id(&self) -> Result<std::borrow::Cow<'_, ClientIdRef>> {
        match self {
            ClientIdentifier::Basic(id) => Ok(std::borrow::Cow::Borrowed(id)),
            ClientIdentifier::X509(certs) => {
                // since ClientId has uniqueness constraints, it is the same for all certificates.
                // hence no need to compute it for every certificate then verify its uniqueness
                // that's not a getter's job
                let cert = certs.values().next().ok_or(Error::NoX509CertificateBundle)?;
                let id = cert
                    .get_client_id()
                    .map_err(RecursiveError::mls_credential("getting client id"))?;
                Ok(std::borrow::Cow::Owned(id))
            }
        }
    }

    /// Generate a new Credential (Credential + KeyPair) for each ciphersuite.
    /// This method does not persist them in the keystore !
    pub fn generate_credentials(
        self,
        backend: &MlsCryptoProvider,
        signature_schemes: HashSet<SignatureScheme>,
    ) -> Result<Vec<(SignatureScheme, ClientId, Credential)>> {
        match self {
            ClientIdentifier::Basic(client_id) => signature_schemes
                .into_iter()
                .map(|signature_scheme| {
                    let credential = Credential::basic(signature_scheme, client_id.clone(), backend)
                        .map_err(RecursiveError::mls_credential("generating basic credential"))?;
                    Ok((signature_scheme, client_id.clone(), credential))
                })
                .collect(),
            ClientIdentifier::X509(certs) => certs
                .into_iter()
                .map(|(signature_scheme, certificate_bundle)| {
                    let id = certificate_bundle
                        .get_client_id()
                        .map_err(RecursiveError::mls_credential("getting client id"))?;
                    let credential = Session::new_x509_credential(certificate_bundle)?;
                    Ok((signature_scheme, id, credential))
                })
                .collect(),
        }
    }
}
