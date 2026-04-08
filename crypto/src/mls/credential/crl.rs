use std::collections::HashSet;

use openmls::{
    group::MlsGroup,
    prelude::{Certificate, MlsCredentialType},
};
use wire_e2e_identity::x509_check::extract_crl_uris;

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
    mut credentials: impl Iterator<Item = &'a MlsCredentialType>,
) -> Result<CrlUris> {
    credentials.try_fold(CrlUris::new(), |mut acc, cred| {
        if let MlsCredentialType::X509(cert) = cred {
            acc.extend(extract_dp(cert)?);
        }

        Ok(acc)
    })
}

pub(crate) fn extract_crl_uris_from_group(group: &MlsGroup) -> Result<CrlUris> {
    extract_crl_uris_from_credentials(group.members_credentials().map(|c| c.mls_credential()))
}

pub(crate) fn extract_dp(cert: &Certificate) -> Result<CrlUris> {
    cert.certificates
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
