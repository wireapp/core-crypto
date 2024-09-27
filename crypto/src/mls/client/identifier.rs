use super::CredentialBundle;
use crate::{
    prelude::CryptoError,
    prelude::{CertificateBundle, Client, ClientId, CryptoResult},
};
use mls_crypto_provider::TransactionalCryptoProvider;
use openmls_traits::types::SignatureScheme;
use std::collections::{HashMap, HashSet};

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
    pub fn get_id(&self) -> CryptoResult<std::borrow::Cow<ClientId>> {
        match self {
            ClientIdentifier::Basic(id) => Ok(std::borrow::Cow::Borrowed(id)),
            ClientIdentifier::X509(certs) => {
                // since ClientId has uniqueness constraints, it is the same for all certificates.
                // hence no need to compute it for every certificate then verify its uniqueness
                // that's not a getter's job
                let cert = certs.values().next().ok_or(CryptoError::ImplementationError)?;
                let id = cert.get_client_id()?;
                Ok(std::borrow::Cow::Owned(id))
            }
        }
    }

    /// Generate a new CredentialBundle (Credential + KeyPair) for each ciphersuite.
    /// This method does not persist them in the keystore !
    pub fn generate_credential_bundles(
        self,
        backend: &TransactionalCryptoProvider,
        signature_schemes: HashSet<SignatureScheme>,
    ) -> CryptoResult<Vec<(SignatureScheme, ClientId, CredentialBundle)>> {
        match self {
            ClientIdentifier::Basic(id) => signature_schemes.iter().try_fold(
                Vec::with_capacity(signature_schemes.len()),
                |mut acc, &sc| -> CryptoResult<_> {
                    let cb = Client::new_basic_credential_bundle(&id, sc, backend)?;
                    acc.push((sc, id.clone(), cb));
                    Ok(acc)
                },
            ),
            ClientIdentifier::X509(certs) => {
                let cap = certs.len();
                certs
                    .into_iter()
                    .try_fold(Vec::with_capacity(cap), |mut acc, (sc, cert)| -> CryptoResult<_> {
                        let id = cert.get_client_id()?;
                        let cb = Client::new_x509_credential_bundle(cert)?;
                        acc.push((sc, id, cb));
                        Ok(acc)
                    })
            }
        }
    }
}
