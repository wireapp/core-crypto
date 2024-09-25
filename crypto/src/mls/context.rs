use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use async_lock::{RwLock, RwLockReadGuardArc, RwLockWriteGuardArc};
use core_crypto_keystore::KeystoreTransaction;
use mls_crypto_provider::TransactionalCryptoProvider;

use crate::{
    group_store::GroupStore,
    prelude::{Client, MlsConversation},
    CoreCryptoCallbacks, CryptoError, CryptoResult,
};

use super::MlsCentral;

#[derive(Debug, Clone)]
pub struct CentralContext {
    state: Arc<RwLock<ContextState>>,
}

#[derive(Debug, Clone)]
enum ContextState {
    Valid {
        transaction: TransactionalCryptoProvider,
        callbacks: Arc<RwLock<Option<std::sync::Arc<dyn CoreCryptoCallbacks + 'static>>>>,
        mls_client: Arc<RwLock<Option<Client>>>,
        mls_groups: Arc<RwLock<GroupStore<MlsConversation>>>,
    },
    Invalid,
}

impl CentralContext {
    pub fn new(central: MlsCentral) -> Self {
        let transaction = central.mls_backend.new_transaction();
        let mls_groups = Arc::new(RwLock::new(Default::default()));
        let callbacks = central.callbacks.clone();
        let mls_client = central.mls_client.clone();
        Self {
            state: Arc::new(
                ContextState::Valid {
                    mls_client,
                    callbacks,
                    transaction,
                    mls_groups,
                }
                .into(),
            ),
        }
    }

    pub(crate) async fn mls_client(&self) -> CryptoResult<RwLockReadGuardArc<Option<Client>>> {
        match self.state.read().await.deref() {
            ContextState::Valid {
                mls_client,
                callbacks: _,
                transaction: _,
                mls_groups: _,
            } => Ok(mls_client.read_arc().await),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub(crate) async fn mls_client_mut(&self) -> CryptoResult<RwLockWriteGuardArc<Option<Client>>> {
        match self.state.read().await.deref() {
            ContextState::Valid {
                mls_client,
                callbacks: _,
                transaction: _,
                mls_groups: _,
            } => Ok(mls_client.write_arc().await),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub(crate) async fn callbacks(
        &self,
    ) -> CryptoResult<RwLockReadGuardArc<Option<std::sync::Arc<dyn CoreCryptoCallbacks + 'static>>>> {
        match self.state.read().await.deref() {
            ContextState::Valid {
                mls_client: _,
                callbacks,
                transaction: _,
                mls_groups: _,
            } => Ok(callbacks.read_arc().await),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub(crate) async fn mls_provider(&self) -> CryptoResult<TransactionalCryptoProvider> {
        match self.state.read().await.deref() {
            ContextState::Valid {
                mls_client: _,
                callbacks: _,
                transaction,
                mls_groups: _,
            } => Ok(transaction.clone()),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub(crate) async fn transaction(&self) -> CryptoResult<KeystoreTransaction> {
        match self.state.read().await.deref() {
            ContextState::Valid {
                mls_client: _,
                callbacks: _,
                transaction,
                mls_groups: _,
            } => Ok(transaction.transaction()),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub(crate) async fn mls_groups(&self) -> CryptoResult<RwLockReadGuardArc<GroupStore<MlsConversation>>> {
        match self.state.read().await.deref() {
            ContextState::Valid {
                mls_client: _,
                callbacks: _,
                transaction: _,
                mls_groups,
            } => Ok(mls_groups.read_arc().await),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub(crate) async fn mls_groups_mut(&self) -> CryptoResult<RwLockWriteGuardArc<GroupStore<MlsConversation>>> {
        match self.state.read().await.deref() {
            ContextState::Valid {
                mls_client: _,
                callbacks: _,
                transaction: _,
                mls_groups,
            } => Ok(mls_groups.write_arc().await),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub async fn finish(&self) -> CryptoResult<()> {
        let mut guard = self.state.write().await;
        match guard.deref() {
            ContextState::Valid {
                mls_client: _,
                callbacks: _,
                transaction,
                mls_groups: _,
            } => {
                transaction.transaction().commit().await?;
            }
            ContextState::Invalid => return Err(CryptoError::InvalidContext),
        }
        *guard = ContextState::Invalid;
        Ok(())
    }
}