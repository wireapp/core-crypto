//! PKI Environment API

use std::{collections::HashSet, sync::Arc};

use async_lock::{RwLock, RwLockReadGuard};
use core_crypto_keystore::{
    connection::Database,
    entities::{E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert},
    traits::FetchFromDatabase,
};
use openmls_traits::authentication_service::{CredentialAuthenticationStatus, CredentialRef};
use x509_cert::der::Decode as _;

use crate::{
    acme::prelude::x509::{
        RustyX509CheckError,
        revocation::{PkiEnvironment as RjtPkiEnvironment, PkiEnvironmentParams},
    },
    error::E2eIdentityError,
    pki_env_hooks::PkiEnvironmentHooks,
};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    IdentityError(#[from] E2eIdentityError),
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

async fn restore_pki_env(data_provider: &impl FetchFromDatabase) -> Result<Option<RjtPkiEnvironment>> {
    let mut trust_roots = vec![];
    let Ok(Some(ta_raw)) = data_provider.get_unique::<E2eiAcmeCA>().await else {
        return Ok(None);
    };

    trust_roots.push(
        x509_cert::Certificate::from_der(&ta_raw.content).map(x509_cert::anchor::TrustAnchorChoice::Certificate)?,
    );

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

    Ok(Some(RjtPkiEnvironment::init(params)?))
}

/// The PKI environment which can be initialized independently from a CoreCrypto session.
#[derive(Debug, Clone)]
pub struct PkiEnvironment {
    /// Implemented by the clients and used by us to make external calls during e2e flow
    // TODO: remove this config with further implementation of RFC CC2, as soon as hooks are actually used
    #[expect(dead_code)]
    hooks: Arc<dyn PkiEnvironmentHooks>,
    /// The database in which X509 Credentials are stored.
    database: Database,
    /// The PkiEnvironmentProvider is the provider used by the MlsCryptoProvider which has to implement
    /// openmls_traits::OpenMlsCryptoProvideropenMls. It therefore has to be shared with the MlsCryptoProvider but
    /// we consider this struct to be the place where it actually belongs to.
    mls_pki_env_provider: PkiEnvironmentProvider,
}

impl PkiEnvironment {
    /// Create a new PKI Environment
    pub async fn new(hooks: Arc<dyn PkiEnvironmentHooks>, database: Database) -> Result<PkiEnvironment> {
        let mls_pki_env_provider = restore_pki_env(&database)
            .await?
            .map(PkiEnvironmentProvider::from)
            .unwrap_or_default();
        Ok(Self {
            hooks,
            database,
            mls_pki_env_provider,
        })
    }

    /// Returns true if the inner pki environment has been restored from the database.
    pub async fn provider_is_setup(&self) -> bool {
        self.mls_pki_env_provider.is_env_setup().await
    }

    pub fn mls_pki_env_provider(&self) -> PkiEnvironmentProvider {
        self.mls_pki_env_provider.clone()
    }

    pub async fn update_pki_environment_provider(&self) -> Result<()> {
        if let Some(rjt_pki_environment) = restore_pki_env(&self.database).await? {
            self.mls_pki_env_provider.update_env(Some(rjt_pki_environment)).await;
        }
        Ok(())
    }

    pub fn database(&self) -> &Database {
        &self.database
    }
}

#[derive(Debug, Clone, Default)]
pub struct PkiEnvironmentProvider(Arc<RwLock<Option<RjtPkiEnvironment>>>);

impl From<RjtPkiEnvironment> for PkiEnvironmentProvider {
    fn from(value: RjtPkiEnvironment) -> Self {
        Self(Arc::new(Some(value).into()))
    }
}

impl PkiEnvironmentProvider {
    pub async fn refresh_time_of_interest(&self) {
        if let Some(pki) = self.0.write().await.as_mut() {
            let _ = pki.refresh_time_of_interest();
        }
    }

    pub async fn borrow(&self) -> RwLockReadGuard<'_, Option<RjtPkiEnvironment>> {
        self.0.read().await
    }

    pub async fn is_env_setup(&self) -> bool {
        self.0.read().await.is_some()
    }

    pub async fn update_env(&self, env: Option<RjtPkiEnvironment>) {
        let mut guard = self.0.write().await;
        *guard = env;
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
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
                    use crate::acme::x509_check::{
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
