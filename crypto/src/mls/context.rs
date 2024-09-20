use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use async_lock::RwLock;
use core_crypto_keystore::KeystoreTransaction;

use crate::{group_store::GroupStore, prelude::MlsConversation, CryptoError, CryptoResult};

use super::MlsCentral;

#[derive(Debug, Clone)]
pub struct CentralContext {
    state: Arc<RwLock<ContextState>>,
}

#[derive(Debug, Clone)]
enum ContextState {
    Valid {
        central: MlsCentral,
        transaction: KeystoreTransaction,
        mls_groups: Arc<RwLock<GroupStore<MlsConversation>>>,
    },
    Invalid,
}

impl CentralContext {
    pub fn new(central: MlsCentral) -> Self {
        let transaction = central.mls_backend.keystore().new_transaction();
        let mls_groups = Arc::new(Default::default().into());
        Self {
            state: Arc::new(
                ContextState::Valid {
                    central,
                    transaction,
                    mls_groups,
                }
                .into(),
            ),
        }
    }

    async fn central(&self) -> CryptoResult<&MlsCentral> {
        match self.state.read().await.deref() {
            ContextState::Valid {
                central,
                transaction,
                mls_groups,
            } => Ok(central),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub(crate) async fn transaction(&self) -> CryptoResult<&KeystoreTransaction> {
        match self.state.read().await.deref() {
            ContextState::Valid {
                central,
                transaction,
                mls_groups,
            } => Ok(transaction),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub(crate) async fn mls_groups(&self) -> CryptoResult<&GroupStore<MlsConversation>> {
        match self.state.read().await.deref() {
            ContextState::Valid {
                central,
                transaction,
                mls_groups,
            } => Ok(mls_groups),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub(crate) async fn mls_groups_mut(&self) -> CryptoResult<&mut GroupStore<MlsConversation>> {
        match self.state.write().await.deref_mut() {
            ContextState::Valid {
                central,
                transaction,
                mls_groups,
            } => Ok(mls_groups),
            ContextState::Invalid => Err(CryptoError::InvalidContext),
        }
    }

    pub async fn finish(&self) -> CryptoResult<()> {
        let guard = self.state.write().await;
        match guard.deref() {
            ContextState::Valid {
                central,
                transaction,
                mls_groups,
            } => {
                transaction.commit().await?;
            }
            ContextState::Invalid => return Err(CryptoError::InvalidContext),
        }
        *guard = ContextState::Invalid;
        Ok(())
    }
}
