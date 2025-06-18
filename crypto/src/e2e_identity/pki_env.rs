use crate::KeystoreError;

use super::Result;
use core_crypto_keystore::{
    connection::FetchFromDatabase,
    entities::{E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert},
};
use std::collections::HashSet;
use wire_e2e_identity::prelude::x509::revocation::{PkiEnvironment, PkiEnvironmentParams};
use x509_cert::der::Decode;

/// New Certificate Revocation List distribution points.
#[derive(Debug, Clone, derive_more::From, derive_more::Into, derive_more::Deref, derive_more::DerefMut)]
pub struct NewCrlDistributionPoints(Option<HashSet<String>>);

impl From<NewCrlDistributionPoints> for Option<Vec<String>> {
    fn from(mut dp: NewCrlDistributionPoints) -> Self {
        dp.take().map(|d| d.into_iter().collect())
    }
}

impl IntoIterator for NewCrlDistributionPoints {
    type Item = String;

    type IntoIter = std::collections::hash_set::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        let items = self.0.unwrap_or_default();
        items.into_iter()
    }
}

pub(crate) async fn restore_pki_env(data_provider: &impl FetchFromDatabase) -> Result<Option<PkiEnvironment>> {
    let mut trust_roots = vec![];
    let Ok(ta_raw) = data_provider.find_unique::<E2eiAcmeCA>().await else {
        return Ok(None);
    };

    trust_roots.push(
        x509_cert::Certificate::from_der(&ta_raw.content).map(x509_cert::anchor::TrustAnchorChoice::Certificate)?,
    );

    let intermediates = data_provider
        .find_all::<E2eiIntermediateCert>(Default::default())
        .await
        .map_err(KeystoreError::wrap("finding intermediate certificates"))?
        .into_iter()
        .map(|inter| x509_cert::Certificate::from_der(&inter.content))
        .collect::<Result<Vec<_>, _>>()?;

    let crls = data_provider
        .find_all::<E2eiCrl>(Default::default())
        .await
        .map_err(KeystoreError::wrap("finding crls"))?
        .into_iter()
        .map(|crl| x509_cert::crl::CertificateList::from_der(&crl.content))
        .collect::<Result<Vec<_>, _>>()?;

    let params = PkiEnvironmentParams {
        trust_roots: &trust_roots,
        intermediates: &intermediates,
        crls: &crls,
        time_of_interest: None,
    };

    Ok(Some(PkiEnvironment::init(params)?))
}
