//! This module contains the primitives to enable transactional support on a higher level within the
//! [Client]. All mutating operations need to be done through a [TransactionContext].

use crate::mls::HasClientAndProvider;
#[cfg(feature = "proteus")]
use crate::proteus::ProteusCentral;
use crate::{
    CoreCrypto, KeystoreError, MlsError, MlsTransport, RecursiveError,
    group_store::GroupStore,
    prelude::{Client, MlsConversation},
};
use async_lock::{Mutex, RwLock, RwLockReadGuardArc, RwLockWriteGuardArc};
use core_crypto_keystore::{CryptoKeystoreError, connection::FetchFromDatabase, entities::ConsumerData};
pub use error::{Error, Result};
use mls_crypto_provider::{CryptoKeystore, MlsCryptoProvider};
use std::{ops::Deref, sync::Arc};
pub mod e2e_identity;

/// This struct provides transactional support for Core Crypto.
///
/// This is struct provides mutable access to the internals of Core Crypto. Every operation that
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
        mls_client: Client,
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
impl HasClientAndProvider for TransactionContext {
    async fn client(&self) -> crate::mls::Result<Client> {
        self.mls_client()
            .await
            .map_err(RecursiveError::transaction("getting mls client"))
            .map_err(Into::into)
    }

    async fn mls_provider(&self) -> crate::mls::Result<MlsCryptoProvider> {
        self.mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))
            .map_err(Into::into)
    }
}

impl TransactionContext {
    async fn new(
        client: &Client,
        #[cfg(feature = "proteus")] proteus_central: Arc<Mutex<Option<ProteusCentral>>>,
    ) -> Result<Self> {
        client
            .mls_backend
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
                    provider: client.mls_backend.clone(),
                    mls_groups,
                    #[cfg(feature = "proteus")]
                    proteus_central,
                }
                .into(),
            ),
        })
    }

    pub(crate) async fn mls_client(&self) -> Result<Client> {
        match self.inner.read().await.deref() {
            TransactionContextInner::Valid { mls_client, .. } => Ok(mls_client.clone()),
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    pub(crate) async fn mls_transport(&self) -> Result<RwLockReadGuardArc<Option<Arc<dyn MlsTransport + 'static>>>> {
        match self.inner.read().await.deref() {
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
        match self.inner.read().await.deref() {
            TransactionContextInner::Valid { transport: cbs, .. } => {
                *cbs.write_arc().await = callbacks;
                Ok(())
            }
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    /// Clones all references that the [MlsCryptoProvider] comprises.
    pub async fn mls_provider(&self) -> Result<MlsCryptoProvider> {
        match self.inner.read().await.deref() {
            TransactionContextInner::Valid { provider, .. } => Ok(provider.clone()),
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    pub(crate) async fn keystore(&self) -> Result<CryptoKeystore> {
        match self.inner.read().await.deref() {
            TransactionContextInner::Valid { provider, .. } => Ok(provider.keystore()),
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    pub(crate) async fn mls_groups(&self) -> Result<RwLockWriteGuardArc<GroupStore<MlsConversation>>> {
        match self.inner.read().await.deref() {
            TransactionContextInner::Valid { mls_groups, .. } => Ok(mls_groups.write_arc().await),
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    #[cfg(feature = "proteus")]
    pub(crate) async fn proteus_central(&self) -> Result<Arc<Mutex<Option<ProteusCentral>>>> {
        match self.inner.read().await.deref() {
            TransactionContextInner::Valid { proteus_central, .. } => Ok(proteus_central.clone()),
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    /// Commits the transaction, meaning it takes all the enqueued operations and persist them into
    /// the keystore. After that the internal state is switched to invalid, causing errors if
    /// something is called from this object.
    pub async fn finish(&self) -> Result<()> {
        let mut guard = self.inner.write().await;
        let TransactionContextInner::Valid { provider, .. } = guard.deref() else {
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

        let TransactionContextInner::Valid { provider, .. } = guard.deref() else {
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
}
