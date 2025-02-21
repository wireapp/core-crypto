use super::{
    CredentialBundle,
    error::{Error, Result},
};
use crate::{
    RecursiveError,
    prelude::{CertificateBundle, Client, ClientId},
};
use mls_crypto_provider::MlsCryptoProvider;
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
    pub fn get_id(&self) -> Result<std::borrow::Cow<ClientId>> {
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

    /// Generate a new CredentialBundle (Credential + KeyPair) for each ciphersuite.
    /// This method does not persist them in the keystore !
    pub fn generate_credential_bundles(
        self,
        backend: &MlsCryptoProvider,
        signature_schemes: HashSet<SignatureScheme>,
    ) -> Result<Vec<(SignatureScheme, ClientId, CredentialBundle)>> {
        match self {
            ClientIdentifier::Basic(id) => signature_schemes.iter().try_fold(
                Vec::with_capacity(signature_schemes.len()),
                |mut acc, &sc| -> Result<_> {
                    let cb = Client::new_basic_credential_bundle(&id, sc, backend)
                        .map_err(RecursiveError::mls_credential("creating new basic credential bundle"))?;
                    acc.push((sc, id.clone(), cb));
                    Ok(acc)
                },
            ),
            ClientIdentifier::X509(certs) => {
                let cap = certs.len();
                certs
                    .into_iter()
                    .try_fold(Vec::with_capacity(cap), |mut acc, (sc, cert)| -> Result<_> {
                        let id = cert
                            .get_client_id()
                            .map_err(RecursiveError::mls_credential("getting client id"))?;
                        let cb = Client::new_x509_credential_bundle(cert)
                            .map_err(RecursiveError::mls_credential("creating new x509 credential bundle"))?;
                        acc.push((sc, id, cb));
                        Ok(acc)
                    })
            }
        }
    }
}
