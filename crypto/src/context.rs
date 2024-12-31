//! This module contains the primitives to enable transactional support on a higher level within the
//! [MlsCentral]. All mutating operations need to be done through a [CentralContext].

use crate::mls::MlsCentral;
#[cfg(feature = "proteus")]
use crate::proteus::ProteusCentral;
use crate::{
    group_store::GroupStore,
    prelude::{Client, MlsConversation},
    CoreCrypto, CryptoError, CryptoResult, MlsTransport,
};
use async_lock::{Mutex, RwLock, RwLockReadGuardArc, RwLockWriteGuardArc};
use core_crypto_keystore::connection::FetchFromDatabase;
use core_crypto_keystore::entities::ConsumerData;
use core_crypto_keystore::CryptoKeystoreError;
use mls_crypto_provider::{CryptoKeystore, MlsCryptoProvider};
use std::{ops::Deref, sync::Arc};

/// This struct provides transactional support for Core Crypto.
///
/// This is struct provides mutable access to the internals of Core Crypto. Every operation that
/// causes data to be persisted needs to be done through this struct. This struct will buffer all
/// operations in memory and when [CentralContext::finish] is called, it will persist the data into
/// the keystore.
#[derive(Debug, Clone)]
pub struct CentralContext {
    state: Arc<RwLock<ContextState>>,
}

/// Due to uniffi's design, we can't force the context to be dropped after the transaction is
/// committed. To work around that we switch the value to `Invalid` when the context is finished
/// and throw errors if something is called
#[derive(Debug, Clone)]
enum ContextState {
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
    /// buffered in memory and when [CentralContext::finish] is called, the data will be persisted
    /// in a single database transaction.
    pub async fn new_transaction(&self) -> CryptoResult<CentralContext> {
        CentralContext::new(
            &self.mls,
            #[cfg(feature = "proteus")]
            self.proteus.clone(),
        )
        .await
    }
}

impl CentralContext {
    async fn new(
        mls_central: &MlsCentral,
        #[cfg(feature = "proteus")] proteus_central: Arc<Mutex<Option<ProteusCentral>>>,
    ) -> CryptoResult<Self> {
        mls_central.mls_backend.new_transaction().await?;
        let mls_groups = Arc::new(RwLock::new(Default::default()));
        let callbacks = mls_central.transport.clone();
        let mls_client = mls_central.mls_client.clone();
        Ok(Self {
            state: Arc::new(
                ContextState::Valid {
                    mls_client,
                    transport: callbacks,
                    provider: mls_central.mls_backend.clone(),
                    mls_groups,
                    #[cfg(feature = "proteus")]
                    proteus_central,
                }
                .into(),
            ),
        })
    }

    pub(crate) async fn mls_client(&self) -> CryptoResult<Client> {
        match self.state.read().await.deref() {
            ContextState::Valid { mls_client, .. } => Ok(mls_client.clone()),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub(crate) async fn mls_transport(
        &self,
    ) -> CryptoResult<RwLockReadGuardArc<Option<Arc<dyn MlsTransport + 'static>>>> {
        match self.state.read().await.deref() {
            ContextState::Valid {
                transport: callbacks, ..
            } => Ok(callbacks.read_arc().await),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    #[cfg(test)]
    pub(crate) async fn set_transport_callbacks(
        &self,
        callbacks: Option<Arc<dyn MlsTransport + 'static>>,
    ) -> CryptoResult<()> {
        match self.state.read().await.deref() {
            ContextState::Valid { transport: cbs, .. } => {
                *cbs.write_arc().await = callbacks;
                Ok(())
            }
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    /// Clones all references that the [MlsCryptoProvider] comprises.
    pub async fn mls_provider(&self) -> CryptoResult<MlsCryptoProvider> {
        match self.state.read().await.deref() {
            ContextState::Valid { provider, .. } => Ok(provider.clone()),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub(crate) async fn keystore(&self) -> CryptoResult<CryptoKeystore> {
        match self.state.read().await.deref() {
            ContextState::Valid { provider, .. } => Ok(provider.keystore()),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub(crate) async fn mls_groups(&self) -> CryptoResult<RwLockWriteGuardArc<GroupStore<MlsConversation>>> {
        match self.state.read().await.deref() {
            ContextState::Valid { mls_groups, .. } => Ok(mls_groups.write_arc().await),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    #[cfg(feature = "proteus")]
    pub(crate) async fn proteus_central(&self) -> CryptoResult<Arc<Mutex<Option<ProteusCentral>>>> {
        match self.state.read().await.deref() {
            ContextState::Valid { proteus_central, .. } => Ok(proteus_central.clone()),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    /// Commits the transaction, meaning it takes all the enqueued operations and persist them into
    /// the keystore. After that the internal state is switched to invalid, causing errors if
    /// something is called from this object.
    pub async fn finish(&self) -> CryptoResult<()> {
        let mut guard = self.state.write().await;
        let commit_result = match guard.deref() {
            ContextState::Valid { provider, .. } => provider.keystore().commit_transaction().await,
            ContextState::Invalid => return Err(CryptoError::InvalidContext),
        };
        *guard = ContextState::Invalid;
        commit_result.map_err(Into::into)
    }

    /// Aborts the transaction, meaning it discards all the enqueued operations.
    /// After that the internal state is switched to invalid, causing errors if
    /// something is called from this object.
    pub async fn abort(&self) -> CryptoResult<()> {
        let mut guard = self.state.write().await;
        let rollback_result = match guard.deref() {
            ContextState::Valid { provider, .. } => provider.keystore().rollback_transaction().await,
            ContextState::Invalid => return Err(CryptoError::InvalidContext),
        };
        *guard = ContextState::Invalid;
        rollback_result.map_err(Into::into)
    }

    /// Set arbitrary data to be retrieved by [CentralContext::get_data].
    /// This is meant to be used as a check point at the end of a transaction.
    /// The data should be limited to a reasonable size.
    pub async fn set_data(&self, data: Vec<u8>) -> CryptoResult<()> {
        self.keystore().await?.save(ConsumerData::from(data)).await?;
        Ok(())
    }

    /// Get the data that has previously been set by [CentralContext::set_data].
    /// This is meant to be used as a check point at the end of a transaction.
    pub async fn get_data(&self) -> CryptoResult<Option<Vec<u8>>> {
        match self.keystore().await?.find_unique::<ConsumerData>().await {
            Ok(data) => Ok(Some(data.into())),
            Err(CryptoKeystoreError::NotFound(..)) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }
}
