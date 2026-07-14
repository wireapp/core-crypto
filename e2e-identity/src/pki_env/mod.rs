//! PKI Environment API

mod crl;
pub mod hooks;

#[cfg(test)]
mod dummy;

use std::{collections::HashSet, sync::Arc};

use async_lock::Mutex;
use certval::{
    CertSource, CertVector as _, CertificationPathSettings, Error as CertvalError, PathValidationStatus, TaSource,
};
use core_crypto_keystore::{
    CryptoKeystoreError, Database,
    entities::{E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert},
    traits::{FetchFromDatabase, UniqueEntity},
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
        revocation::{PkiEnvironment as RjtPkiEnvironment, PkiEnvironmentParams, now},
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
    database: Arc<Database>,
    rjt_pki_env: Mutex<RjtPkiEnvironment>,
}

impl PkiEnvironment {
    /// Create a new PKI Environment
    pub async fn new(hooks: Arc<dyn PkiEnvironmentHooks>, database: Arc<Database>) -> Result<PkiEnvironment> {
        let rjt_pki_env = restore_pki_env(&*database).await?;
        Ok(Self {
            hooks,
            database,
            rjt_pki_env: Mutex::new(rjt_pki_env),
        })
    }

    /// Return certificates that are used as trust anchors.
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

    /// Get the hooks.
    pub fn hooks(&self) -> Arc<dyn PkiEnvironmentHooks> {
        self.hooks.clone()
    }

    /// Get the database.
    pub fn database(&self) -> &Database {
        &self.database
    }

    /// Get an Arc to the database.
    ///
    /// In general [`Self::database`] is lighter-weight and should be preferred.
    pub fn database_arc(&self) -> Arc<Database> {
        self.database.clone()
    }

    /// Wrap an operation which requires a transaction.
    ///
    /// If a transaction does not already exist, creates one.
    ///
    /// After the operation finishes, if we created a transaction, then either
    /// commit or rollback the operation according to the operation's success.
    async fn transactionally<T, E>(&self, operation: impl AsyncFnOnce() -> std::result::Result<T, E>) -> Result<T>
    where
        E: Into<Error>,
    {
        let created_transaction = match self.database.try_new_immediate_transaction().await {
            Ok(()) => true,
            Err(CryptoKeystoreError::TransactionInProgress) => false,
            Err(err) => return Err(err.into()),
        };
        let operation_outcome = operation().await;
        if created_transaction {
            if operation_outcome.is_ok() {
                self.database.commit_transaction().await?;
            } else {
                self.database.rollback_transaction().await?;
            }
        }
        operation_outcome.map_err(Into::into)
    }

    /// Adds the certificate as a trust anchor to the PKI environment.
    ///
    /// The certificate is saved to the database, and included in the PKI environment for
    /// future validation.
    ///
    /// # Caution
    ///
    /// Adding a trust anchor will replace any existing trust anchor. This limitation
    /// will be relaxed in the future.
    pub async fn add_trust_anchor(&self, cert: Certificate) -> Result<()> {
        // Validate it (expiration & signature only)
        self.rjt_pki_env.lock().await.validate_trust_anchor_cert(&cert)?;

        // Save cert's DER representation to the database
        // TODO: make this work for multiple trust anchors, see WPB-25632
        let cert_data = E2eiAcmeCA {
            content: cert.to_der()?,
        };

        self.transactionally(async || self.database.save(cert_data).await)
            .await?;

        let mut trust_anchors = TaSource::new();
        trust_anchors.push(certval::CertFile {
            filename: "".to_string(),
            bytes: cert.to_der()?,
        });
        trust_anchors.initialize().map_err(Error::Certval)?;
        self.rjt_pki_env
            .lock()
            .await
            .add_trust_anchor_source(Box::new(trust_anchors));
        Ok(())
    }

    /// Remove the trust anchor with serial number `serial_number` from the PKI environment.
    ///
    /// Note that any certificates relying on the removed trust anchor may no longer
    /// validate.
    pub async fn remove_trust_anchor(&self, serial_number: &[u8]) -> Result<()> {
        let mut guard = self.rjt_pki_env.lock().await;

        let certs: Vec<_> = guard
            .get_trust_anchors()
            .iter()
            .filter_map(|choice| match choice.decoded_ta {
                TrustAnchorChoice::Certificate(ref cert)
                    if cert.tbs_certificate.serial_number.as_bytes() != serial_number =>
                {
                    Some(cert.clone())
                }
                _ => None,
            })
            .collect();

        guard.clear_trust_anchor_sources();

        let mut trust_anchors = TaSource::new();
        for cert in certs {
            trust_anchors.push(certval::CertFile {
                filename: "".to_string(),
                bytes: cert.to_der()?,
            });
        }
        trust_anchors.initialize().map_err(Error::Certval)?;
        guard.add_trust_anchor_source(Box::new(trust_anchors));

        // TODO: make this work for multiple trust anchors, see WPB-25632
        self.transactionally(async || {
            self.database
                .remove::<E2eiAcmeCA>(&<E2eiAcmeCA as UniqueEntity>::KEY)
                .await
        })
        .await?;

        Ok(())
    }

    /// Adds the certificate to the PKI environment.
    ///
    /// The certificate is saved to the database, and included in the PKI environment for
    /// future validation.
    ///
    /// CRL (Certificate Revocation List) distribution points are extracted from the certificate and
    /// an attempt is made to fetch a CRL from each one.
    pub async fn add_intermediate_cert(&self, cert: Certificate) -> Result<()> {
        // Save cert's DER representation to the database
        let (ski, aki) = RjtPkiEnvironment::extract_ski_aki_from_cert(&cert)?;
        let ski_aki_pair = format!("{ski}:{}", aki.unwrap_or_default());
        let cert_der = RjtPkiEnvironment::encode_cert_to_der(&cert)?;
        let intermediate_cert = E2eiIntermediateCert {
            content: cert_der,
            ski_aki_pair,
        };

        self.transactionally(async || {
            self.database.save(intermediate_cert).await?;

            // Get CRL distribution points and CRLs
            let dps: Vec<String> = extract_crl_uris(&cert)?.iter().flatten().cloned().collect();
            let crls = self.fetch_crls(dps.iter().map(AsRef::as_ref)).await?;

            // Save all CRLs to the database
            for (distribution_point, crl) in &crls {
                self.save_crl(distribution_point, crl).await?;
            }

            Result::Ok(())
        })
        .await?;

        let mut cps = CertificationPathSettings::new();
        certval::set_time_of_interest(&mut cps, now()?);
        let mut cert_source = CertSource::new();
        cert_source.push(certval::CertFile {
            filename: "".to_string(),
            bytes: cert.to_der()?,
        });

        let mut guard = self.rjt_pki_env.lock().await;
        cert_source.initialize(&cps).map_err(Error::Certval)?;
        cert_source.find_all_partial_paths(&guard, &cps);
        guard.add_certificate_source(Box::new(cert_source));

        Ok(())
    }

    /// Validate an end-entity X509 certificate.
    ///
    /// Performs validation of the provided certificate in the context
    /// defined by the set of trust anchors and intermediate certificates
    /// contained in this PKI environment. Revocation check is performed
    /// and time of interest is set to the time of the call.
    pub async fn validate_cert(&self, cert: &x509_cert::Certificate) -> RustyX509CheckResult<()> {
        self.rjt_pki_env.lock().await.validate_cert_and_revocation(cert)
    }

    /// Validate an X509 credential.
    ///
    /// # Panics
    ///
    /// Panics if the provided credential is not of type X509.
    pub async fn validate_credential<'a>(&'a self, credential: CredentialRef<'a>) -> CredentialAuthenticationStatus {
        let CredentialRef::X509 { certificates } = credential else {
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

#[cfg(test)]
mod tests {
    use spki::der::DecodePem as _;

    use super::*;

    const EXAMPLE_CERT_PEM: &str = "
-----BEGIN CERTIFICATE-----
MIIBkzCCAUWgAwIBAgIUHFYIFRkm33GKIOb4xLeNtkjl3TIwBQYDK2VwMDcxFTAT
BgNVBAMMDFRlc3QgUm9vdCBDQTERMA8GA1UECgwIVGVzdCBPcmcxCzAJBgNVBAYT
AlVTMB4XDTI2MDUyODE1MzA0NFoXDTM2MDUyNTE1MzA0NFowNzEVMBMGA1UEAwwM
VGVzdCBSb290IENBMREwDwYDVQQKDAhUZXN0IE9yZzELMAkGA1UEBhMCVVMwKjAF
BgMrZXADIQDa0nMgIgBZeNM2ysNUVp80zwjZNqPJt7HYK3GX7GPp9aNjMGEwHQYD
VR0OBBYEFHA0MmaaNGOTuBvdo3zzQoKFJ3p5MB8GA1UdIwQYMBaAFHA0MmaaNGOT
uBvdo3zzQoKFJ3p5MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAUG
AytlcANBAJffPzL50OWnmEBo9mGBQfPVzKRIfFc8EaXox1D5VF9cC1r8nRa0hUq+
LOVS/gxNk618+PKA2bYq67MZQXCYGgk=
-----END CERTIFICATE-----
";

    #[tokio::test]
    async fn can_add_trust_anchor() {
        let db = Database::open_in_memory().unwrap();
        let pki_env = PkiEnvironment::with_dummy_hooks(db).await.unwrap();
        let cert = x509_cert::Certificate::from_pem(EXAMPLE_CERT_PEM).unwrap();
        assert!(pki_env.add_trust_anchor(cert).await.is_ok());
    }

    #[tokio::test]
    async fn can_remove_trust_anchor() {
        let db = Database::open_in_memory().unwrap();
        let pki_env = PkiEnvironment::with_dummy_hooks(db).await.unwrap();
        let cert = x509_cert::Certificate::from_pem(EXAMPLE_CERT_PEM).unwrap();
        pki_env.add_trust_anchor(cert.clone()).await.unwrap();

        let certs = pki_env.get_trust_anchors().await;
        assert_eq!(certs.len(), 1);

        pki_env
            .remove_trust_anchor(certs[0].tbs_certificate.serial_number.as_bytes())
            .await
            .unwrap();
        assert_eq!(pki_env.get_trust_anchors().await.len(), 0);
    }

    #[tokio::test]
    async fn can_add_intermediate_cert() {
        let db = Database::open_in_memory().unwrap();
        let pki_env = PkiEnvironment::with_dummy_hooks(db).await.unwrap();
        let cert = x509_cert::Certificate::from_pem(EXAMPLE_CERT_PEM).unwrap();
        assert!(pki_env.add_intermediate_cert(cert).await.is_ok());
    }
}
