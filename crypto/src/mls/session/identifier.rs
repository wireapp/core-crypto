use std::collections::HashMap;

use openmls::prelude::CredentialType;
use openmls_traits::types::SignatureScheme;

use super::error::{Error, Result};
use crate::{CertificateBundle, ClientId, RecursiveError, mls::session::id::ClientIdRef};

/// Used by consumers to initializes a MLS client. Encompasses all the client types available.
/// Could be enriched later with Verifiable Presentations.
#[derive(Debug, Clone, derive_more::From)]
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

    /// The credential type for this identifier
    pub fn credential_type(&self) -> CredentialType {
        match self {
            ClientIdentifier::Basic(_) => CredentialType::Basic,
            ClientIdentifier::X509(_) => CredentialType::X509,
        }
    }
}
