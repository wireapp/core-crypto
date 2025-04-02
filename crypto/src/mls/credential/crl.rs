use super::{Error, Result};
use crate::{
    KeystoreError, RecursiveError, e2e_identity::NewCrlDistributionPoints, transaction_context::TransactionContext,
};
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

impl TransactionContext {
    /// When x509 new credentials are registered this extracts the new CRL Distribution Point from the end entity certificate
    /// and all the intermediates
    pub(crate) async fn extract_dp_on_init(&self, certificate_chain: &[Vec<u8>]) -> Result<NewCrlDistributionPoints> {
        use x509_cert::der::Decode as _;

        // Own intermediates are not provided by smallstep in the /federation endpoint so we got to intercept them here, at issuance
        let size = certificate_chain.len();
        let mut crl_new_distribution_points = HashSet::new();
        if size > 1 {
            for int in certificate_chain.iter().skip(1).rev() {
                let mut crl_dp = self
                    .e2ei_register_intermediate_ca_der(int)
                    .await
                    .map_err(RecursiveError::transaction("registering intermediate ca der"))?;
                if let Some(crl_dp) = crl_dp.take() {
                    crl_new_distribution_points.extend(crl_dp);
                }
            }
        }

        let ee = certificate_chain.first().ok_or(Error::InvalidCertificateChain)?;

        let ee = x509_cert::Certificate::from_der(ee).map_err(Error::DecodeX509)?;
        let mut ee_crl_dp = extract_crl_uris(&ee).map_err(RecursiveError::e2e_identity("extracting crl urls"))?;
        if let Some(crl_dp) = ee_crl_dp.take() {
            crl_new_distribution_points.extend(crl_dp);
        }

        get_new_crl_distribution_points(
            &self
                .mls_provider()
                .await
                .map_err(RecursiveError::transaction("getting mls provider"))?,
            crl_new_distribution_points,
        )
        .await
    }
}
