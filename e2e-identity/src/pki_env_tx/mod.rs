//! Transaction context implementation for PKI Environments

use std::sync::Arc;

use async_lock::RwLock;
use x509_cert::Certificate;

use crate::pki_env::PkiEnvironment;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("this transaction context has been invalidated; it can be used only within the scope where it is provided")]
    Invalidated,
    #[error(transparent)]
    Keystore(#[from] core_crypto_keystore::CryptoKeystoreError),
    #[error("delegating environment operation implementation")]
    Delegated(#[from] crate::pki_env::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// This struct provides transactional support for PKI environments.
///
/// This struct provides mutable access to the database. Every operation that
/// causes data to be persisted needs to be done through this struct.
#[derive(Debug)]
pub struct PkiTransactionContext {
    inner: RwLock<TransactionContextInner>,
}

/// Due to uniffi's design, we can't force the context to be dropped after the transaction is
/// committed. To work around that we switch the value to `Invalid` when the context is finished
/// and throw errors if something is called
#[derive(Debug, Clone)]
enum TransactionContextInner {
    Valid { pki_environment: Arc<PkiEnvironment> },
    Invalid,
}

impl TransactionContextInner {
    /// Take the PkiEnvironment out of the context-inner, invalidating it
    fn take(&mut self) -> Result<Arc<PkiEnvironment>> {
        let environment = match self {
            TransactionContextInner::Valid { pki_environment } => Some(pki_environment.clone()),
            TransactionContextInner::Invalid => None,
        };
        *self = Self::Invalid;
        environment.ok_or(Error::Invalidated)
    }
}

impl PkiTransactionContext {
    pub(super) async fn new(pki_environment: Arc<PkiEnvironment>) -> Result<Self> {
        pki_environment.database().new_transaction().await?;
        Ok(Self {
            inner: TransactionContextInner::Valid { pki_environment }.into(),
        })
    }

    /// Commit the changes in this transaction, finalizing and invalidating the transaction context.
    pub async fn commit(&self) -> Result<()> {
        self.inner
            .write()
            .await
            .take()?
            .database()
            .commit_transaction()
            .await
            .map_err(Into::into)
    }

    /// Abort the changes in this transaction, finalizing and invalidating the transaction context.
    pub async fn rollback(&self) -> Result<()> {
        self.inner
            .write()
            .await
            .take()?
            .database()
            .rollback_transaction()
            .await
            .map_err(Into::into)
    }

    async fn ensure_valid(&self) -> Result<Arc<PkiEnvironment>> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { pki_environment } => Ok(pki_environment.clone()),
            TransactionContextInner::Invalid => Err(Error::Invalidated),
        }
    }

    /// Validate the CRL (trust anchors must be configured prior to this) and
    /// save it to the database.
    pub async fn save_crl(&self, crl_dp: &str, crl_der: &[u8]) -> Result<()> {
        self.ensure_valid()
            .await?
            .save_crl(crl_dp, crl_der)
            .await
            .map_err(Into::into)
    }

    /// Adds the certificate as a trust anchor to the PKI environment.
    ///
    /// The certificate is saved to the database, and included in the PKI environment for
    /// future validation.
    pub async fn add_trust_anchor(&self, name: &str, cert: Certificate) -> Result<()> {
        self.ensure_valid()
            .await?
            .add_trust_anchor(name, cert)
            .await
            .map_err(Into::into)
    }

    /// Adds the certificate to the PKI environment.
    ///
    /// The certificate is saved to the database, and included in the PKI environment for
    /// future validation.
    ///
    /// CRL (Certificate Revocation List) distribution points are extracted from the certificate and
    /// an attempt is made to fetch a CRL from each one.
    pub async fn add_intermediate_cert(&self, name: &str, cert: Certificate) -> Result<()> {
        self.ensure_valid()
            .await?
            .add_intermediate_cert(name, cert)
            .await
            .map_err(Into::into)
    }
}
