use std::collections::HashSet;

use openmls::{
    group::MlsGroup,
    prelude::{Credential as MlsCredential, CredentialType as MlsCredentialType, X509Credential},
};
use wire_e2e_identity::validation::extract_crl_uris;

use super::{Error, Result};
use crate::RecursiveError;

#[derive(
    Debug,
    Clone,
    derive_more::From,
    derive_more::Into,
    derive_more::Deref,
    derive_more::DerefMut,
    derive_more::IntoIterator,
)]
pub(crate) struct CrlUris(HashSet<String>);

pub(crate) fn extract_crl_uris_from_credentials<'a>(
    mut credentials: impl Iterator<Item = &'a MlsCredential>,
) -> Result<CrlUris> {
    credentials.try_fold(CrlUris::new(), |mut acc, credential| {
        if credential.credential_type() == MlsCredentialType::X509 {
            acc.extend(extract_dp(credential)?);
        }

        Ok(acc)
    })
}

pub(crate) fn extract_crl_uris_from_group(group: &MlsGroup) -> Result<CrlUris> {
    let credentials = group.members().map(|member| member.credential).collect::<Vec<_>>();
    extract_crl_uris_from_credentials(credentials.iter())
}

/// The CRL distribution points of every certificate in an X509 credential's chain.
pub(crate) fn extract_dp(credential: &MlsCredential) -> Result<CrlUris> {
    X509Credential::try_from(credential.clone())
        .map_err(Error::DecodeX509Chain)?
        .certificates()
        .iter()
        .try_fold(CrlUris::new(), |mut acc, cert| -> Result<CrlUris> {
            use x509_cert::der::Decode as _;
            let cert = x509_cert::Certificate::from_der(cert.as_slice()).map_err(Error::DecodeX509)?;
            if let Some(crl_uris) =
                extract_crl_uris(&cert).map_err(RecursiveError::e2e_identity("extracting crl urls"))?
            {
                acc.extend(crl_uris);
            }
            Ok(acc)
        })
}

impl CrlUris {
    fn new() -> Self {
        HashSet::new().into()
    }
}
