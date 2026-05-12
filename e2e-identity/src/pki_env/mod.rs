//! PKI Environment API

mod crl;
pub mod hooks;
mod mutation;

#[cfg(test)]
mod dummy;

use std::{collections::HashSet, sync::Arc};

use async_lock::Mutex;
use certval::{Error as CertvalError, PathValidationStatus};
use core_crypto_keystore::{
    connection::Database,
    entities::{E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert},
    traits::FetchFromDatabase,
};
use openmls_traits::authentication_service::{CredentialAuthenticationStatus, CredentialRef};
use x509_cert::{Certificate, anchor::TrustAnchorChoice, der::Decode as _};

use crate::{
    pki_env::hooks::PkiEnvironmentHooks,
    x509_check::{
        RustyX509CheckError, RustyX509CheckResult,
        revocation::{PkiEnvironment as RjtPkiEnvironment, PkiEnvironmentParams},
    },
};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("The trust anchor certificate couldn't be loaded from the database.")]
    NoTrustAnchor,
    #[error("Failed to fetch CRL from '{uri}': HTTP {status}")]
    CrlFetchUnsuccessful { uri: String, status: u16 },
    #[error(transparent)]
    HooksError(#[from] hooks::PkiEnvironmentHooksError),
    #[error(transparent)]
    X509Error(#[from] RustyX509CheckError),
    #[error(transparent)]
    UrlError(#[from] url::ParseError),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error(transparent)]
    X509CertDerError(#[from] x509_cert::der::Error),
    #[error(transparent)]
    KeystoreError(#[from] core_crypto_keystore::CryptoKeystoreError),
    #[error("certval error: {0}")]
    Certval(certval::Error),
}

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

async fn restore_pki_env(data_provider: &impl FetchFromDatabase) -> Result<RjtPkiEnvironment> {
    let mut trust_roots = vec![];
    if let Ok(Some(ta_raw)) = data_provider.get_unique::<E2eiAcmeCA>().await {
        trust_roots.push(
            x509_cert::Certificate::from_der(&ta_raw.content).map(x509_cert::anchor::TrustAnchorChoice::Certificate)?,
        );
    }

    let intermediates = data_provider
        .load_all::<E2eiIntermediateCert>()
        .await?
        .into_iter()
        .map(|inter| x509_cert::Certificate::from_der(&inter.content))
        .collect::<core::result::Result<Vec<_>, _>>()?;

    let crls = data_provider
        .load_all::<E2eiCrl>()
        .await?
        .into_iter()
        .map(|crl| x509_cert::crl::CertificateList::from_der(&crl.content))
        .collect::<core::result::Result<Vec<_>, _>>()?;

    let params = PkiEnvironmentParams {
        trust_roots: &trust_roots,
        intermediates: &intermediates,
        crls: &crls,
    };

    Ok(RjtPkiEnvironment::init(params)?)
}

/// The PKI environment which can be initialized independently from a CoreCrypto session.
#[derive(Debug)]
pub struct PkiEnvironment {
    /// Implemented by the clients and used by us to make external calls during e2e flow
    hooks: Arc<dyn PkiEnvironmentHooks>,
    /// The database in which X509 Credentials are stored.
    database: Database,
    rjt_pki_env: Mutex<RjtPkiEnvironment>,
}

impl PkiEnvironment {
    /// Create a new PKI Environment
    pub async fn new(hooks: Arc<dyn PkiEnvironmentHooks>, database: Database) -> Result<PkiEnvironment> {
        let rjt_pki_env = restore_pki_env(&database).await?;
        Ok(Self {
            hooks,
            database,
            rjt_pki_env: Mutex::new(rjt_pki_env),
        })
    }

    pub async fn get_trust_anchors(&self) -> Vec<Certificate> {
        self.rjt_pki_env
            .lock()
            .await
            .get_trust_anchors()
            .iter()
            .filter_map(|choice| match choice.decoded_ta {
                TrustAnchorChoice::Certificate(ref cert) => Some(cert.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn hooks(&self) -> Arc<dyn PkiEnvironmentHooks> {
        self.hooks.clone()
    }

    pub fn database(&self) -> &Database {
        &self.database
    }

    pub async fn trust_anchor(&self) -> Result<Certificate> {
        let trust_anchor = self
            .database
            .get_unique::<E2eiAcmeCA>()
            .await?
            .ok_or(Error::NoTrustAnchor)?;

        let trust_anchor = x509_cert::Certificate::from_der(&trust_anchor.content)?;
        Ok(trust_anchor)
    }

    pub async fn validate_cert(&self, cert: &x509_cert::Certificate) -> RustyX509CheckResult<()> {
        self.rjt_pki_env.lock().await.validate_cert_and_revocation(cert)
    }

    pub async fn validate_credential<'a>(&'a self, credential: CredentialRef<'a>) -> CredentialAuthenticationStatus {
        let certificates = if let CredentialRef::X509 { certificates } = credential {
            certificates
        } else {
            panic!("this function can only be called with an X509 credential");
        };

        let Some(cert) = certificates
            .first()
            .and_then(|cert_raw| x509_cert::Certificate::from_der(cert_raw).ok())
        else {
            return CredentialAuthenticationStatus::Invalid;
        };

        match self.rjt_pki_env.lock().await.validate_cert_and_revocation(&cert) {
            Err(RustyX509CheckError::CertValError(CertvalError::PathValidation(
                PathValidationStatus::CertificateRevoked
                | PathValidationStatus::CertificateRevokedEndEntity
                | PathValidationStatus::CertificateRevokedIntermediateCa,
            ))) => {
                // ? Revoked credentials are A-OK. They still degrade conversations though.
                // TODO: update this after WPB-25524
                CredentialAuthenticationStatus::Valid
            }
            Err(RustyX509CheckError::CertValError(CertvalError::PathValidation(
                PathValidationStatus::InvalidNotAfterDate,
            ))) => {
                // ? Expired credentials are A-OK. They still degrade conversations though.
                // TODO: update this after WPB-25524
                CredentialAuthenticationStatus::Valid
            }
            Err(RustyX509CheckError::CertValError(CertvalError::PathValidation(_))) => {
                CredentialAuthenticationStatus::Invalid
            }
            Err(_) => CredentialAuthenticationStatus::Unknown,
            Ok(_) => CredentialAuthenticationStatus::Valid,
        }
    }
}
