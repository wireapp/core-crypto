//! This module contains the primitives to enable transactional support on a higher level within the
//! [Session]. All mutating operations need to be done through a [TransactionContext].

use std::sync::Arc;

use async_lock::{Mutex, MutexGuardArc, RwLock};
use core_crypto_keystore::{CryptoKeystoreError, entities::ConsumerData, traits::FetchFromDatabase as _};
pub use error::{Error, Result};
use openmls_traits::OpenMlsCryptoProvider as _;
use wire_e2e_identity::pki_env::PkiEnvironment;

use crate::{
    ClientId, ConversationId, CoreCrypto, CredentialFindFilters, CredentialRef, KeystoreError, MlsError, MlsTransport,
    RecursiveError, Session,
    mls::{self, HasSessionAndCrypto, conversation_cache::MlsConversationCache},
    mls_provider::{Database, MlsCryptoProvider},
};
pub mod conversation;
mod credential;
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
        core_crypto: Arc<CoreCrypto>,
        pending_epoch_changes: Arc<Mutex<Vec<(ConversationId, u64)>>>,
    },
    Invalid,
}

impl CoreCrypto {
    /// Creates a new transaction. All operations that persist data will be
    /// buffered in memory and when [TransactionContext::finish] is called, the data will be persisted
    /// in a single database transaction.
    pub async fn new_transaction(self: &Arc<Self>) -> Result<TransactionContext> {
        TransactionContext::new(self.clone()).await
    }
}

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
impl HasSessionAndCrypto for TransactionContext {
    async fn session(&self) -> crate::mls::Result<Session<Database>> {
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
    async fn new(core_crypto: Arc<CoreCrypto>) -> Result<Self> {
        core_crypto
            .database
            .new_transaction()
            .await
            .map_err(MlsError::wrap("creating new transaction"))?;
        Ok(Self {
            inner: Arc::new(
                TransactionContextInner::Valid {
                    core_crypto,
                    pending_epoch_changes: Default::default(),
                }
                .into(),
            ),
        })
    }

    pub(crate) async fn session(&self) -> Result<Session<Database>> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { core_crypto, .. } => core_crypto.mls.read().await.as_ref().cloned().ok_or(
                RecursiveError::mls_client("Getting mls session from transaction context")(
                    mls::session::Error::MlsNotInitialized,
                )
                .into(),
            ),
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    #[cfg(test)]
    pub(crate) async fn set_session_if_exists(&self, new_session: Session<Database>) {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { core_crypto, .. } => {
                let mut guard = core_crypto.mls.write().await;

                if guard.as_ref().is_some() {
                    *guard = Some(new_session)
                }
            }
            TransactionContextInner::Invalid => {}
        }
    }

    pub(crate) async fn mls_transport(&self) -> Result<Arc<dyn MlsTransport + 'static>> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { core_crypto, .. } => core_crypto
                .mls
                .read()
                .await
                .as_ref()
                .map(|s| s.transport.clone())
                .ok_or(
                    RecursiveError::mls_client("Getting mls session from transaction context")(
                        mls::session::Error::MlsNotInitialized,
                    )
                    .into(),
                ),

            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    /// Clones all references that the [MlsCryptoProvider] comprises.
    pub async fn mls_provider(&self) -> Result<MlsCryptoProvider> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { core_crypto, .. } => core_crypto
                .mls
                .read()
                .await
                .as_ref()
                .map(|s| s.crypto_provider.clone())
                .ok_or(
                    RecursiveError::mls_client("Getting mls session from transaction context")(
                        mls::session::Error::MlsNotInitialized,
                    )
                    .into(),
                ),
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    pub(crate) async fn database(&self) -> Result<Database> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { core_crypto, .. } => Ok(core_crypto.database.clone()),
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    pub(crate) async fn pki_environment(&self) -> Result<Arc<PkiEnvironment>> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { core_crypto, .. } => core_crypto
                .pki_environment
                .read()
                .await
                .as_ref()
                .map(Clone::clone)
                .ok_or(
                    RecursiveError::transaction("getting PKI environment from transaction context")(
                        e2e_identity::Error::PkiEnvironmentUnset,
                    )
                    .into(),
                ),
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    pub(crate) async fn mls_groups(&self) -> Result<MutexGuardArc<MlsConversationCache>> {
        let guard = self.inner.read().await;
        let TransactionContextInner::Valid { core_crypto, .. } = &*guard else {
            return Err(Error::InvalidTransactionContext);
        };
        let cache = core_crypto
            .mls
            .read()
            .await
            .as_ref()
            .map(|session| session.conversation_cache.clone())
            .ok_or_else(|| {
                RecursiveError::mls_client("getting mls session from transaction context")(
                    mls::session::Error::MlsNotInitialized,
                )
            })?;

        Ok(cache.lock_arc().await)
    }

    pub(crate) async fn queue_epoch_changed(&self, conversation_id: ConversationId, epoch: u64) -> Result<()> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid {
                pending_epoch_changes, ..
            } => {
                pending_epoch_changes.lock().await.push((conversation_id, epoch));
                Ok(())
            }
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    /// Commits the transaction, meaning it takes all the enqueued operations and persist them into
    /// the keystore. After that the internal state is switched to invalid, causing errors if
    /// something is called from this object.
    pub async fn finish(&self) -> Result<()> {
        let mut guard = self.inner.write().await;
        let TransactionContextInner::Valid {
            core_crypto,
            pending_epoch_changes,
            ..
        } = &*guard
        else {
            return Err(Error::InvalidTransactionContext);
        };

        let commit_result = core_crypto
            .database
            .commit_transaction()
            .await
            .map_err(KeystoreError::wrap("commiting transaction"))
            .map_err(Into::into);

        if let Some(session) = core_crypto.mls.read().await.as_ref() {
            if commit_result.is_ok() {
                // We need owned values, so we could just clone the conversation ids, but we don't need the events
                // anymore, so draining the vector works, too.
                let mut epoch_changes = pending_epoch_changes.lock().await;
                for (conversation_id, epoch) in epoch_changes.drain(..) {
                    session.notify_epoch_changed(conversation_id, epoch).await;
                }
            } else {
                // Commit failed: the keystore is back to its pre-transaction state, but the in-memory
                // conversation cache may have absorbed mutations that never made it to disk. Clear them
                // so subsequent reads load fresh state from the keystore.
                session.conversation_cache.lock().await.clear();
            }
        }

        *guard = TransactionContextInner::Invalid;
        commit_result
    }

    /// Aborts the transaction, meaning it discards all the enqueued operations.
    /// After that the internal state is switched to invalid, causing errors if
    /// something is called from this object.
    pub async fn abort(&self) -> Result<()> {
        let mut guard = self.inner.write().await;

        let TransactionContextInner::Valid { core_crypto, .. } = &*guard else {
            return Err(Error::InvalidTransactionContext);
        };

        // Drop any in-memory conversation state mutated during this transaction; it never reached
        // the keystore and would otherwise diverge from disk after rollback.
        if let Some(session) = core_crypto.mls.read().await.as_ref() {
            session.conversation_cache.lock().await.clear();
        }

        let result = core_crypto
            .database
            .rollback_transaction()
            .await
            .map_err(KeystoreError::wrap("rolling back transaction"))
            .map_err(Into::into);

        *guard = TransactionContextInner::Invalid;
        result
    }

    /// Initializes the MLS client of [super::CoreCrypto].
    pub async fn mls_init(&self, session_id: ClientId, transport: Arc<dyn MlsTransport>) -> Result<()> {
        let database = self.database().await?;
        let pki_env = self.pki_environment().await.ok();
        let crypto_provider = MlsCryptoProvider::new_with_pki_env(database.clone(), pki_env);
        let session = Session::new(session_id.clone(), crypto_provider, database, transport);
        self.set_mls_session(session).await?;

        Ok(())
    }

    /// Set the `mls_session` Arc (also sets it on the transaction's CoreCrypto instance)
    pub(crate) async fn set_mls_session(&self, session: Session<Database>) -> Result<()> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { core_crypto, .. } => {
                let mut guard = core_crypto.mls.write().await;
                *guard = Some(session);
                Ok(())
            }
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    /// see [Session::id]
    pub async fn client_id(&self) -> Result<ClientId> {
        let session = self.session().await?;
        Ok(session.id())
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
        self.database()
            .await?
            .save(ConsumerData::from(data))
            .await
            .map_err(KeystoreError::wrap("saving consumer data"))?;
        Ok(())
    }

    /// Get the data that has previously been set by [TransactionContext::set_data].
    /// This is meant to be used as a check point at the end of a transaction.
    pub async fn get_data(&self) -> Result<Option<Vec<u8>>> {
        match self.database().await?.get_unique::<ConsumerData>().await {
            Ok(maybe_data) => Ok(maybe_data.map(Into::into)),
            Err(CryptoKeystoreError::NotFound(..)) => Ok(None),
            Err(err) => Err(KeystoreError::wrap("finding unique consumer data")(err).into()),
        }
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
