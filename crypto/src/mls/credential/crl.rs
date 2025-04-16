use super::{Error, Result};
use crate::{KeystoreError, RecursiveError, e2e_identity::NewCrlDistributionPoints};
use core_crypto_keystore::{connection::FetchFromDatabase, entities::E2eiCrl};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::{
    group::MlsGroup,
    prelude::{Certificate, MlsCredentialType, Proposal, StagedCommit},
};
use openmls_traits::OpenMlsCryptoProvider;
use std::collections::HashSet;
use wire_e2e_identity::prelude::x509::extract_crl_uris;

pub(crate) fn extract_crl_uris_from_credentials<'a>(
    mut credentials: impl Iterator<Item = &'a MlsCredentialType>,
) -> Result<HashSet<String>> {
    credentials.try_fold(HashSet::new(), |mut acc, cred| {
        if let MlsCredentialType::X509(cert) = cred {
            acc.extend(extract_dp(cert)?);
        }

        Ok(acc)
    })
}

pub(crate) fn extract_crl_uris_from_proposals(proposals: &[Proposal]) -> Result<HashSet<String>> {
    extract_crl_uris_from_credentials(
        proposals
            .iter()
            .filter_map(|p| match p {
                Proposal::Add(add) => Some(add.key_package().leaf_node()),
                Proposal::Update(update) => Some(update.leaf_node()),
                _ => None,
            })
            .map(|ln| ln.credential().mls_credential()),
    )
}

pub(crate) fn extract_crl_uris_from_update_path(commit: &StagedCommit) -> Result<HashSet<String>> {
    if let Some(update_path) = commit.get_update_path_leaf_node() {
        if let MlsCredentialType::X509(cert) = update_path.credential().mls_credential() {
            return extract_dp(cert);
        }
    }
    Ok(HashSet::new())
}

pub(crate) fn extract_crl_uris_from_group(group: &MlsGroup) -> Result<HashSet<String>> {
    extract_crl_uris_from_credentials(group.members_credentials().map(|c| c.mls_credential()))
}

pub(crate) fn extract_dp(cert: &Certificate) -> Result<HashSet<String>> {
    cert.certificates
        .iter()
        .try_fold(HashSet::new(), |mut acc, cert| -> Result<HashSet<String>> {
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

pub(crate) async fn get_new_crl_distribution_points(
    backend: &MlsCryptoProvider,
    mut crl_dps: HashSet<String>,
) -> Result<NewCrlDistributionPoints> {
    if crl_dps.is_empty() {
        return Ok(None.into());
    }

    let stored_crls = backend
        .key_store()
        .find_all::<E2eiCrl>(Default::default())
        .await
        .map_err(KeystoreError::wrap("finding all e2e crl"))?;
    let stored_crl_dps: HashSet<&str> = stored_crls.iter().map(|crl| crl.distribution_point.as_str()).collect();
    crl_dps.retain(|dp| !stored_crl_dps.contains(&dp.as_str()));

    Ok(Some(crl_dps).into())
}
