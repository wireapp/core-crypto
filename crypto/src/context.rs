//! This module contains the primitives to enable transactional support on a higher level within the
//! [MlsCentral]. All mutating operations need to be done through a [CentralContext].

use crate::mls::MlsCentral;
#[cfg(feature = "proteus")]
use crate::proteus::ProteusCentral;
use crate::{
    group_store::GroupStore,
    prelude::{Client, MlsConversation},
    CoreCrypto, Error, MlsTransport, Result,
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
    pub async fn new_transaction(&self) -> Result<CentralContext> {
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
    ) -> Result<Self> {
        mls_central
            .mls_backend
            .new_transaction()
            .await
            .map_err(Error::mls_operation("creating new transaction"))?;
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

    pub(crate) async fn mls_client(&self) -> Result<Client> {
        match self.state.read().await.deref() {
            ContextState::Valid { mls_client, .. } => Ok(mls_client.clone()),
            ContextState::Invalid => Err(Error::InvalidContext),
        }
    }

    // This is going to be needed soon.
    #[expect(dead_code)]
    pub(crate) async fn transport(&self) -> Result<RwLockReadGuardArc<Option<Arc<dyn MlsTransport + 'static>>>> {
        match self.state.read().await.deref() {
            ContextState::Valid {
                transport: callbacks, ..
            } => Ok(callbacks.read_arc().await),
            ContextState::Invalid => Err(Error::InvalidContext),
        }
    }

    // This is going to be needed soon.
    #[expect(dead_code)]
    #[cfg(test)]
    pub(crate) async fn set_transport_callbacks(
        &self,
        callbacks: Option<Arc<dyn MlsTransport + 'static>>,
    ) -> Result<()> {
        match self.state.read().await.deref() {
            ContextState::Valid { transport: cbs, .. } => {
                *cbs.write_arc().await = callbacks;
                Ok(())
            }
            ContextState::Invalid => Err(Error::InvalidContext),
        }
    }

    /// Clones all references that the [MlsCryptoProvider] comprises.
    pub async fn mls_provider(&self) -> Result<MlsCryptoProvider> {
        match self.state.read().await.deref() {
            ContextState::Valid { provider, .. } => Ok(provider.clone()),
            ContextState::Invalid => Err(Error::InvalidContext),
        }
    }

    pub(crate) async fn keystore(&self) -> Result<CryptoKeystore> {
        match self.state.read().await.deref() {
            ContextState::Valid { provider, .. } => Ok(provider.keystore()),
            ContextState::Invalid => Err(Error::InvalidContext),
        }
    }

    pub(crate) async fn mls_groups(&self) -> Result<RwLockWriteGuardArc<GroupStore<MlsConversation>>> {
        match self.state.read().await.deref() {
            ContextState::Valid { mls_groups, .. } => Ok(mls_groups.write_arc().await),
            ContextState::Invalid => Err(Error::InvalidContext),
        }
    }

    #[cfg(feature = "proteus")]
    pub(crate) async fn proteus_central(&self) -> Result<Arc<Mutex<Option<ProteusCentral>>>> {
        match self.state.read().await.deref() {
            ContextState::Valid { proteus_central, .. } => Ok(proteus_central.clone()),
            ContextState::Invalid => Err(Error::InvalidContext),
        }
    }

    /// Commits the transaction, meaning it takes all the enqueued operations and persist them into
    /// the keystore. After that the internal state is switched to invalid, causing errors if
    /// something is called from this object.
    pub async fn finish(&self) -> Result<()> {
        let mut guard = self.state.write().await;
        let ContextState::Valid { provider, .. } = guard.deref() else {
            return Err(Error::InvalidContext);
        };

        let commit_result = provider
            .keystore()
            .commit_transaction()
            .await
            .map_err(Error::keystore("commiting transaction"));

        *guard = ContextState::Invalid;
        commit_result
    }

    /// Aborts the transaction, meaning it discards all the enqueued operations.
    /// After that the internal state is switched to invalid, causing errors if
    /// something is called from this object.
    pub async fn abort(&self) -> Result<()> {
        let mut guard = self.state.write().await;

        let ContextState::Valid { provider, .. } = guard.deref() else {
            return Err(Error::InvalidContext);
        };

        let result = provider
            .keystore()
            .rollback_transaction()
            .await
            .map_err(Error::keystore("rolling back transaction"));

        *guard = ContextState::Invalid;
        result
    }

    /// Set arbitrary data to be retrieved by [CentralContext::get_data].
    /// This is meant to be used as a check point at the end of a transaction.
    /// The data should be limited to a reasonable size.
    pub async fn set_data(&self, data: Vec<u8>) -> Result<()> {
        self.keystore()
            .await?
            .save(ConsumerData::from(data))
            .await
            .map_err(Error::keystore("saving consumer data"))?;
        Ok(())
    }

    /// Get the data that has previously been set by [CentralContext::set_data].
    /// This is meant to be used as a check point at the end of a transaction.
    pub async fn get_data(&self) -> Result<Option<Vec<u8>>> {
        match self.keystore().await?.find_unique::<ConsumerData>().await {
            Ok(data) => Ok(Some(data.into())),
            Err(CryptoKeystoreError::NotFound(..)) => Ok(None),
            Err(err) => Err(Error::keystore("finding unique consumer data")(err)),
        }
    }
}
