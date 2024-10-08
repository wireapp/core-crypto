//! This module contains the primitives to enable transactional support on a higher level within the
//! [MlsCentral]. All mutating operations need to be done through a [CentralContext].

use std::{ops::Deref, sync::Arc};

use async_lock::{RwLock, RwLockReadGuardArc, RwLockWriteGuardArc};
use mls_crypto_provider::TransactionalCryptoProvider;

use crate::{
    group_store::GroupStore,
    prelude::{Client, MlsConversation},
    CoreCryptoCallbacks, CryptoError, CryptoResult,
};

use super::MlsCentral;

/// This struct provides transactional support for Core Crypto.
///
/// This is struct provides mutable access to the internals of Core Crypto. Every operation that
/// causes data to be persisted needs to be done through this struct. This struct will buffer all
/// operations in memory and when [CentraContext::finish] is called, it will persist the data into
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
        provider: TransactionalCryptoProvider,
        callbacks: Arc<RwLock<Option<std::sync::Arc<dyn CoreCryptoCallbacks + 'static>>>>,
        mls_client: Arc<RwLock<Option<Client>>>,
        mls_groups: Arc<RwLock<GroupStore<MlsConversation>>>,
    },
    Invalid,
}

impl MlsCentral {
    /// Creates a new transaction within the MlsCentral. All operations that persist data will be
    /// buffered in memory and when [CentralContext::finish] is called, the data will be persisted
    /// in a single database transaction.
    pub async fn new_transaction(&self) -> CryptoResult<CentralContext> {
        CentralContext::new(self).await
    }
}

impl CentralContext {
    async fn new(central: &MlsCentral) -> CryptoResult<Self> {
        central.mls_backend.new_transaction().await?;
        let mls_groups = Arc::new(RwLock::new(Default::default()));
        let callbacks = central.callbacks.clone();
        let mls_client = central.mls_client.clone();
        Ok(Self {
            state: Arc::new(
                ContextState::Valid {
                    mls_client,
                    callbacks,
                    provider: central.mls_backend.clone(),
                    mls_groups,
                }
                .into(),
            ),
        })
    }

    pub(crate) async fn mls_client(&self) -> CryptoResult<RwLockReadGuardArc<Option<Client>>> {
        match self.state.read().await.deref() {
            ContextState::Valid { mls_client, .. } => Ok(mls_client.read_arc().await),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub(crate) async fn mls_client_mut(&self) -> CryptoResult<RwLockWriteGuardArc<Option<Client>>> {
        match self.state.read().await.deref() {
            ContextState::Valid { mls_client, .. } => Ok(mls_client.write_arc().await),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub(crate) async fn callbacks(
        &self,
    ) -> CryptoResult<RwLockReadGuardArc<Option<Arc<dyn CoreCryptoCallbacks + 'static>>>> {
        match self.state.read().await.deref() {
            ContextState::Valid { callbacks, .. } => Ok(callbacks.read_arc().await),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    #[cfg(test)]
    pub(crate) async fn set_callbacks(
        &self,
        callbacks: Option<Arc<dyn CoreCryptoCallbacks + 'static>>,
    ) -> CryptoResult<()> {
        match self.state.read().await.deref() {
            ContextState::Valid { callbacks: cbs, .. } => {
                *cbs.write_arc().await = callbacks;
                Ok(())
            }
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    /// Creates a read guard on the internal mls provider for the current transaction
    pub async fn mls_provider(&self) -> CryptoResult<TransactionalCryptoProvider> {
        match self.state.read().await.deref() {
            ContextState::Valid { provider, .. } => Ok(provider.clone()),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub(crate) async fn mls_groups(&self) -> CryptoResult<RwLockWriteGuardArc<GroupStore<MlsConversation>>> {
        match self.state.read().await.deref() {
            ContextState::Valid { mls_groups, .. } => Ok(mls_groups.write_arc().await),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    /// Commits the transaction, meaning it takes all the enqueued operations and persist them into
    /// the keystore. After that the internal state is switched to invalid, causing errors if
    /// something is called from this object.
    pub async fn finish(&self) -> CryptoResult<()> {
        let mut guard = self.state.write().await;
        match guard.deref() {
            ContextState::Valid { provider, .. } => {
                provider.keystore().commit_transaction().await?;
            }
            ContextState::Invalid => return Err(CryptoError::InvalidContext),
        }
        *guard = ContextState::Invalid;
        Ok(())
    }
}
