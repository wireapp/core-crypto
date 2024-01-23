use crate::{CryptoError, CryptoResult};
use core_crypto_keystore::entities::E2eiCrl;
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::{Certificate, MlsCredentialType, Proposal, StagedCommit};
use openmls_traits::OpenMlsCryptoProvider;
use wire_e2e_identity::prelude::x509::extract_crl_uris;

pub(crate) fn extract_crl_uris_from_proposals(proposals: &[Proposal]) -> CryptoResult<Vec<String>> {
    proposals
        .iter()
        .filter_map(|p| match p {
            Proposal::Add(add) => Some(add.key_package().leaf_node()),
            Proposal::Update(update) => Some(update.leaf_node()),
            _ => None,
        })
        .map(|ln| ln.credential().mls_credential())
        .filter_map(|c| match c {
            MlsCredentialType::X509(cert) => Some(cert),
            _ => None,
        })
        .try_fold(vec![], |mut acc, c| {
            acc.extend(extract_dp(c)?);
            CryptoResult::Ok(acc)
        })
}

pub(crate) fn extract_crl_uris_from_update_path(commit: &StagedCommit) -> CryptoResult<Vec<String>> {
    if let Some(update_path) = commit.get_update_path_leaf_node() {
        if let MlsCredentialType::X509(cert) = update_path.credential().mls_credential() {
            return extract_dp(cert);
        }
    }
    Ok(vec![])
}

pub(crate) fn extract_dp(cert: &Certificate) -> CryptoResult<Vec<String>> {
    Ok(cert
        .certificates
        .iter()
        .try_fold(std::collections::HashSet::new(), |mut acc, cert| {
            use x509_cert::der::Decode as _;
            let cert = x509_cert::Certificate::from_der(cert.as_slice())?;
            if let Some(crl_uris) = extract_crl_uris(&cert).map_err(|e| CryptoError::E2eiError(e.into()))? {
                acc.extend(crl_uris);
            }
            CryptoResult::Ok(acc)
        })?
        .into_iter()
        .collect())
}

pub(crate) async fn get_new_crl_distribution_points(
    backend: &MlsCryptoProvider,
    crl_dps: Vec<String>,
) -> CryptoResult<Option<Vec<String>>> {
    if !crl_dps.is_empty() {
        let stored_crls = backend.key_store().find_all::<E2eiCrl>(Default::default()).await?;
        let stored_crl_dps: Vec<&str> = stored_crls.iter().map(|crl| crl.distribution_point.as_str()).collect();

        Ok(Some(
            crl_dps
                .into_iter()
                .filter(|dp| stored_crl_dps.contains(&dp.as_str()))
                .collect(),
        ))
    } else {
        Ok(None)
    }
}
