//! PKI Environment API

mod crl;
pub mod hooks;

use std::{collections::HashSet, sync::Arc};

use certval::{CertVector as _, TaSource};
use core_crypto_keystore::{
    connection::Database,
    entities::{E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert},
    traits::FetchFromDatabase,
};
use openmls_traits::authentication_service::{CredentialAuthenticationStatus, CredentialRef};
use x509_cert::{
    Certificate,
    der::{Decode as _, Encode as _},
};

use crate::{
    pki_env::hooks::PkiEnvironmentHooks,
    x509_check::{
        RustyX509CheckError,
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
        time_of_interest: None,
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
    rjt_pki_env: RjtPkiEnvironment,
}

impl PkiEnvironment {
    /// Create a new PKI Environment
    pub async fn new(hooks: Arc<dyn PkiEnvironmentHooks>, database: Database) -> Result<PkiEnvironment> {
        let rjt_pki_env = restore_pki_env(&database).await?;
        Ok(Self {
            hooks,
            database,
            rjt_pki_env,
        })
    }

    pub fn mls_pki_env_provider(&self) -> &RjtPkiEnvironment {
        &self.rjt_pki_env
    }

    pub async fn update_pki_environment_provider(&mut self) -> Result<()> {
        self.rjt_pki_env = restore_pki_env(&self.database).await?;
        Ok(())
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

    pub async fn add_trust_anchor(&mut self, name: &str, cert: Certificate) -> Result<()> {
        let mut guard = self.mls_pki_env_provider.0.write().await;
        let pki_env = guard.as_mut().expect("inner PKI environment must be set");

        let mut trust_anchors = TaSource::new();
        trust_anchors.push(certval::CertFile {
            filename: name.to_owned(),
            bytes: cert.to_der()?,
        });
        trust_anchors.initialize().map_err(Error::Certval)?;
        pki_env.add_trust_anchor_source(Box::new(trust_anchors));
        Ok(())
    }
}

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
impl openmls_traits::authentication_service::AuthenticationServiceDelegate for PkiEnvironmentProvider {
    async fn validate_credential<'a>(&'a self, credential: CredentialRef<'a>) -> CredentialAuthenticationStatus {
        match credential {
            // We assume that Basic credentials are always valid
            CredentialRef::Basic { identity: _ } => CredentialAuthenticationStatus::Valid,

            CredentialRef::X509 { certificates } => {
                self.refresh_time_of_interest().await;

                let binding = self.0.read().await;
                let Some(pki_env) = binding.as_ref() else {
                    // This implies that we have a Basic client without a PKI environment setup. Hence they cannot
                    // validate X509 credentials they see. So we consider it as always valid as we
                    // have no way to assert the validity
                    return CredentialAuthenticationStatus::Valid;
                };

                use x509_cert::der::Decode as _;
                let Some(cert) = certificates
                    .first()
                    .and_then(|cert_raw| x509_cert::Certificate::from_der(cert_raw).ok())
                else {
                    return CredentialAuthenticationStatus::Invalid;
                };

                if let Err(validation_error) = pki_env.validate_cert_and_revocation(&cert) {
                    use crate::x509_check::{
                        RustyX509CheckError,
                        reexports::certval::{Error as CertvalError, PathValidationStatus},
                    };

                    if let RustyX509CheckError::CertValError(CertvalError::PathValidation(
                        certificate_validation_error,
                    )) = validation_error
                    {
                        match certificate_validation_error {
                            PathValidationStatus::Valid
                            | PathValidationStatus::RevocationStatusNotAvailable
                            | PathValidationStatus::RevocationStatusNotDetermined => {}
                            PathValidationStatus::CertificateRevoked
                            | PathValidationStatus::CertificateRevokedEndEntity
                            | PathValidationStatus::CertificateRevokedIntermediateCa => {
                                // ? Revoked credentials are A-OK. They still degrade conversations though.
                                // return CredentialAuthenticationStatus::Revoked;
                            }
                            PathValidationStatus::InvalidNotAfterDate => {
                                // ? Expired credentials are A-OK. They still degrade conversations though.
                                // return CredentialAuthenticationStatus::Expired;
                            }
                            _ => return CredentialAuthenticationStatus::Invalid,
                        }
                    } else {
                        return CredentialAuthenticationStatus::Unknown;
                    }
                }

                CredentialAuthenticationStatus::Valid
            }
        }
    }
}
