use super::CredentialBundle;
use crate::prelude::{CertificateBundle, Client, ClientId, CryptoResult, MlsCiphersuite};
use mls_crypto_provider::MlsCryptoProvider;
use std::collections::HashMap;

/// Used by consumers to initializes a MLS client. Encompasses all the client types available.
/// Could be enriched later with Verifiable Presentations.
#[derive(Debug, Clone)]
pub enum ClientIdentifier {
    /// Basic keypair
    Basic(ClientId),
    /// X509 certificate
    X509(HashMap<MlsCiphersuite, CertificateBundle>),
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
                let cert = certs.values().next().unwrap();
                let id = cert.get_client_id()?;
                Ok(std::borrow::Cow::Owned(id))
            }
        }
    }

    /// Generate a new CredentialBundle (Credential + KeyPair) for each ciphersuite.
    /// This method does not persist them in the keystore !
    pub fn generate_credential_bundles(
        self,
        backend: &MlsCryptoProvider,
        ciphersuites: &[MlsCiphersuite],
    ) -> CryptoResult<Vec<(MlsCiphersuite, ClientId, CredentialBundle)>> {
        match self {
            ClientIdentifier::Basic(id) => ciphersuites.iter().try_fold(
                Vec::with_capacity(ciphersuites.len()),
                |mut acc, &cs| -> CryptoResult<_> {
                    let cb = Client::new_basic_credential_bundle(&id, cs, backend)?;
                    acc.push((cs, id.clone(), cb));
                    Ok(acc)
                },
            ),
            ClientIdentifier::X509(certs) => {
                certs
                    .into_iter()
                    .try_fold(vec![], |mut acc, (cs, cert)| -> CryptoResult<_> {
                        let id = cert.get_client_id()?;
                        let cb = Client::new_x509_credential_bundle(cert)?;
                        acc.push((cs, id, cb));
                        Ok(acc)
                    })
            }
        }
    }
}
