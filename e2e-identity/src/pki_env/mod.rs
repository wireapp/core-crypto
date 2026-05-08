//! PKI Environment API

mod crl;
pub mod hooks;

#[cfg(test)]
mod dummy;

use std::{collections::HashSet, sync::Arc};

use async_lock::Mutex;
use certval::{CertSource, CertVector as _, CertificationPathSettings, TaSource};
use core_crypto_keystore::{
    connection::Database,
    entities::{E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert},
    traits::FetchFromDatabase,
};
use openmls_traits::authentication_service::{CredentialAuthenticationStatus, CredentialRef};
use x509_cert::{
    Certificate,
    anchor::TrustAnchorChoice,
    der::{Decode as _, Encode as _},
};

use crate::{
    pki_env::hooks::PkiEnvironmentHooks,
    x509_check::{
        RustyX509CheckError, RustyX509CheckResult, extract_crl_uris,
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

    /// Adds the certificate as a trust anchor to the PKI environment.
    ///
    /// The certificate is saved to the database, and included in the PKI environment for
    /// future validation.
    pub async fn add_trust_anchor(&self, name: &str, cert: Certificate) -> Result<()> {
        // Validate it (expiration & signature only)
        self.rjt_pki_env.lock().await.validate_trust_anchor_cert(&cert)?;

        // Save cert's DER representation to the database
        let cert_data = E2eiAcmeCA {
            content: cert.to_der()?,
        };

        self.database.save(cert_data).await?;

        let mut trust_anchors = TaSource::new();
        trust_anchors.push(certval::CertFile {
            filename: name.to_owned(),
            bytes: cert.to_der()?,
        });
        trust_anchors.initialize().map_err(Error::Certval)?;
        self.rjt_pki_env
            .lock()
            .await
            .add_trust_anchor_source(Box::new(trust_anchors));
        Ok(())
    }

    /// Adds the certificate to the PKI environment.
    ///
    /// The certificate is saved to the database, and included in the PKI environment for
    /// future validation.
    ///
    /// CRL (Certificate Revocation List) distribution points are extracted from the certificate and
    /// an attempt is made to fetch a CRL from each one.
    pub async fn add_intermediate_cert(&self, name: &str, cert: Certificate) -> Result<()> {
        // Save cert's DER representation to the database
        let (ski, aki) = RjtPkiEnvironment::extract_ski_aki_from_cert(&cert)?;
        let ski_aki_pair = format!("{ski}:{}", aki.unwrap_or_default());
        let cert_der = RjtPkiEnvironment::encode_cert_to_der(&cert)?;
        let intermediate_cert = E2eiIntermediateCert {
            content: cert_der,
            ski_aki_pair,
        };

        self.database.save(intermediate_cert).await?;

        // Get CRL distribution points and CRLs
        let dps: Vec<String> = extract_crl_uris(&cert)?.iter().flatten().cloned().collect();
        let crls = self.fetch_crls(dps.iter().map(AsRef::as_ref)).await?;

        // Save all CRLs to the database
        for (distribution_point, crl) in &crls {
            self.save_crl(distribution_point, crl).await?;
        }

        let cps = CertificationPathSettings::new();
        let mut cert_source = CertSource::new();
        cert_source.push(certval::CertFile {
            filename: name.to_owned(),
            bytes: cert.to_der()?,
        });

        cert_source.initialize(&cps).map_err(Error::Certval)?;
        self.rjt_pki_env
            .lock()
            .await
            .add_certificate_source(Box::new(cert_source));

        Ok(())
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

        if let Err(validation_error) = self.rjt_pki_env.lock().await.validate_cert_and_revocation(&cert) {
            use crate::x509_check::{
                RustyX509CheckError,
                reexports::certval::{Error as CertvalError, PathValidationStatus},
            };

            if let RustyX509CheckError::CertValError(CertvalError::PathValidation(certificate_validation_error)) =
                validation_error
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
