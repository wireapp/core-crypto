//! This module contains the primitives to enable transactional support on a higher level within the
//! [Session]. All mutating operations need to be done through a [TransactionContext].

use std::sync::Arc;

#[cfg(feature = "proteus")]
use async_lock::Mutex;
use async_lock::{RwLock, RwLockReadGuardArc, RwLockWriteGuardArc};
use core_crypto_keystore::{CryptoKeystoreError, connection::FetchFromDatabase, entities::ConsumerData};
pub use error::{Error, Result};
use mls_crypto_provider::{Database, MlsCryptoProvider};
use openmls_traits::OpenMlsCryptoProvider as _;

#[cfg(feature = "proteus")]
use crate::proteus::ProteusCentral;
use crate::{
    Ciphersuite, ClientId, ClientIdentifier, CoreCrypto, Credential, CredentialFindFilters, CredentialRef,
    CredentialType, KeystoreError, MlsConversation, MlsError, MlsTransport, RecursiveError, Session,
    group_store::GroupStore, mls::HasSessionAndCrypto,
};
pub mod conversation;
pub mod e2e_identity;
mod error;
pub mod key_package;
#[cfg(feature = "proteus")]
pub mod proteus;
#[cfg(test)]
pub mod test_utils;

/// This struct provides transactional support for Core Crypto.
///
/// This struct provides mutable access to the internals of Core Crypto. Every operation that
/// causes data to be persisted needs to be done through this struct. This struct will buffer all
/// operations in memory and when [TransactionContext::finish] is called, it will persist the data into
/// the keystore.
#[derive(Debug, Clone)]
pub struct TransactionContext {
    inner: Arc<RwLock<TransactionContextInner>>,
}

/// Due to uniffi's design, we can't force the context to be dropped after the transaction is
/// committed. To work around that we switch the value to `Invalid` when the context is finished
/// and throw errors if something is called
#[derive(Debug, Clone)]
enum TransactionContextInner {
    Valid {
        provider: MlsCryptoProvider,
        transport: Arc<RwLock<Option<Arc<dyn MlsTransport + 'static>>>>,
        mls_client: Session,
        mls_groups: Arc<RwLock<GroupStore<MlsConversation>>>,
        #[cfg(feature = "proteus")]
        proteus_central: Arc<Mutex<Option<ProteusCentral>>>,
    },
    Invalid,
}

impl CoreCrypto {
    /// Creates a new transaction. All operations that persist data will be
    /// buffered in memory and when [TransactionContext::finish] is called, the data will be persisted
    /// in a single database transaction.
    pub async fn new_transaction(&self) -> Result<TransactionContext> {
        TransactionContext::new(
            &self.mls,
            #[cfg(feature = "proteus")]
            self.proteus.clone(),
        )
        .await
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl HasSessionAndCrypto for TransactionContext {
    async fn session(&self) -> crate::mls::Result<Session> {
        self.session()
            .await
            .map_err(RecursiveError::transaction("getting mls client"))
            .map_err(Into::into)
    }

    async fn crypto_provider(&self) -> crate::mls::Result<MlsCryptoProvider> {
        self.mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))
            .map_err(Into::into)
    }
}

impl TransactionContext {
    async fn new(
        client: &Session,
        #[cfg(feature = "proteus")] proteus_central: Arc<Mutex<Option<ProteusCentral>>>,
    ) -> Result<Self> {
        client
            .crypto_provider
            .new_transaction()
            .await
            .map_err(MlsError::wrap("creating new transaction"))?;
        let mls_groups = Arc::new(RwLock::new(Default::default()));
        let callbacks = client.transport.clone();
        let mls_client = client.clone();
        Ok(Self {
            inner: Arc::new(
                TransactionContextInner::Valid {
                    mls_client,
                    transport: callbacks,
                    provider: client.crypto_provider.clone(),
                    mls_groups,
                    #[cfg(feature = "proteus")]
                    proteus_central,
                }
                .into(),
            ),
        })
    }

    pub(crate) async fn session(&self) -> Result<Session> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { mls_client, .. } => Ok(mls_client.clone()),
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    pub(crate) async fn mls_transport(&self) -> Result<RwLockReadGuardArc<Option<Arc<dyn MlsTransport + 'static>>>> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid {
                transport: callbacks, ..
            } => Ok(callbacks.read_arc().await),
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    #[cfg(test)]
    pub(crate) async fn set_transport_callbacks(
        &self,
        callbacks: Option<Arc<dyn MlsTransport + 'static>>,
    ) -> Result<()> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { transport: cbs, .. } => {
                *cbs.write_arc().await = callbacks;
                Ok(())
            }
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    /// Clones all references that the [MlsCryptoProvider] comprises.
    pub async fn mls_provider(&self) -> Result<MlsCryptoProvider> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { provider, .. } => Ok(provider.clone()),
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    pub(crate) async fn keystore(&self) -> Result<Database> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { provider, .. } => Ok(provider.keystore()),
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    pub(crate) async fn mls_groups(&self) -> Result<RwLockWriteGuardArc<GroupStore<MlsConversation>>> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { mls_groups, .. } => Ok(mls_groups.write_arc().await),
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    #[cfg(feature = "proteus")]
    pub(crate) async fn proteus_central(&self) -> Result<Arc<Mutex<Option<ProteusCentral>>>> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { proteus_central, .. } => Ok(proteus_central.clone()),
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    /// Commits the transaction, meaning it takes all the enqueued operations and persist them into
    /// the keystore. After that the internal state is switched to invalid, causing errors if
    /// something is called from this object.
    pub async fn finish(&self) -> Result<()> {
        let mut guard = self.inner.write().await;
        let TransactionContextInner::Valid { provider, .. } = &*guard else {
            return Err(Error::InvalidTransactionContext);
        };

        let commit_result = provider
            .keystore()
            .commit_transaction()
            .await
            .map_err(KeystoreError::wrap("commiting transaction"))
            .map_err(Into::into);

        *guard = TransactionContextInner::Invalid;
        commit_result
    }

    /// Aborts the transaction, meaning it discards all the enqueued operations.
    /// After that the internal state is switched to invalid, causing errors if
    /// something is called from this object.
    pub async fn abort(&self) -> Result<()> {
        let mut guard = self.inner.write().await;

        let TransactionContextInner::Valid { provider, .. } = &*guard else {
            return Err(Error::InvalidTransactionContext);
        };

        let result = provider
            .keystore()
            .rollback_transaction()
            .await
            .map_err(KeystoreError::wrap("rolling back transaction"))
            .map_err(Into::into);

        *guard = TransactionContextInner::Invalid;
        result
    }

    /// Initializes the MLS client of [super::CoreCrypto].
    pub async fn mls_init(&self, identifier: ClientIdentifier, ciphersuites: &[Ciphersuite]) -> Result<()> {
        let mls_client = self.session().await?;
        mls_client
            .init(
                identifier,
                &ciphersuites
                    .iter()
                    .map(|ciphersuite| ciphersuite.signature_algorithm())
                    .collect::<Vec<_>>(),
            )
            .await
            .map_err(RecursiveError::mls_client("initializing mls client"))?;

        if mls_client.is_e2ei_capable().await {
            let client_id = mls_client
                .id()
                .await
                .map_err(RecursiveError::mls_client("getting client id"))?;
            log::trace!(client_id:% = client_id; "Initializing PKI environment");
            self.init_pki_env().await?;
        }

        Ok(())
    }

    /// Returns the client's public key.
    pub async fn client_public_key(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
    ) -> Result<Vec<u8>> {
        let cb = self
            .session()
            .await?
            .find_most_recent_credential(ciphersuite.signature_algorithm(), credential_type)
            .await
            .map_err(RecursiveError::mls_client("finding most recent credential"))?;
        Ok(cb.signature_key_pair.to_public_vec())
    }

    /// see [Session::id]
    pub async fn client_id(&self) -> Result<ClientId> {
        self.session()
            .await?
            .id()
            .await
            .map_err(RecursiveError::mls_client("getting client id"))
            .map_err(Into::into)
    }

    /// Generates a random byte array of the specified size
    pub async fn random_bytes(&self, len: usize) -> Result<Vec<u8>> {
        use openmls_traits::random::OpenMlsRand as _;
        self.mls_provider()
            .await?
            .rand()
            .random_vec(len)
            .map_err(MlsError::wrap("generating random vector"))
            .map_err(Into::into)
    }

    /// Set arbitrary data to be retrieved by [TransactionContext::get_data].
    /// This is meant to be used as a check point at the end of a transaction.
    /// The data should be limited to a reasonable size.
    pub async fn set_data(&self, data: Vec<u8>) -> Result<()> {
        self.keystore()
            .await?
            .save(ConsumerData::from(data))
            .await
            .map_err(KeystoreError::wrap("saving consumer data"))?;
        Ok(())
    }

    /// Get the data that has previously been set by [TransactionContext::set_data].
    /// This is meant to be used as a check point at the end of a transaction.
    pub async fn get_data(&self) -> Result<Option<Vec<u8>>> {
        match self.keystore().await?.find_unique::<ConsumerData>().await {
            Ok(data) => Ok(Some(data.into())),
            Err(CryptoKeystoreError::NotFound(..)) => Ok(None),
            Err(err) => Err(KeystoreError::wrap("finding unique consumer data")(err).into()),
        }
    }

    /// Add a credential to the identities of this session.
    ///
    /// As a side effect, stores the credential in the keystore.
    pub async fn add_credential(&self, credential: Credential) -> Result<CredentialRef> {
        self.session()
            .await?
            .add_credential(credential)
            .await
            .map_err(RecursiveError::mls_client("adding credential to session"))
            .map_err(Into::into)
    }

    /// Remove a credential from the identities of this session.
    ///
    /// As a side effect, delete the credential from the keystore.
    ///
    /// Removes both the credential itself and also any key packages which were generated from it.
    pub async fn remove_credential(&self, credential_ref: &CredentialRef) -> Result<()> {
        self.session()
            .await?
            .remove_credential(credential_ref)
            .await
            .map_err(RecursiveError::mls_client("removing credential from session"))
            .map_err(Into::into)
    }

    /// Find credentials matching the find filters among the identities of this session
    ///
    /// Note that finding credentials with no filters set is equivalent to [`Self::get_credentials`].
    pub async fn find_credentials(&self, find_filters: CredentialFindFilters<'_>) -> Result<Vec<CredentialRef>> {
        self.session()
            .await?
            .find_credentials(find_filters)
            .await
            .map_err(RecursiveError::mls_client("finding credentials by filter"))
            .map_err(Into::into)
    }

    /// Get all credentials from the identities of this session.
    ///
    /// To get specific credentials, it can be more efficient to use [`Self::find_credentials`].
    pub async fn get_credentials(&self) -> Result<Vec<CredentialRef>> {
        self.session()
            .await?
            .get_credentials()
            .await
            .map_err(RecursiveError::mls_client("getting all credentials"))
            .map_err(Into::into)
    }
}
