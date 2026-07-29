//! This module contains the primitives to enable transactional support on a higher level within the
//! [Session]. All mutating operations need to be done through a [TransactionContext].

use std::sync::Arc;

use async_lock::{Mutex, MutexGuardArc, RwLock};
use core_crypto_keystore::{CryptoKeystoreError, UniqueArc, entities::ConsumerData, traits::FetchFromDatabase as _};
pub use error::{Error, Result};
use openmls_traits::OpenMlsCryptoProvider as _;
use wire_e2e_identity::pki_env::PkiEnvironment;

use crate::{
    ClientId, ConversationId, CoreCrypto, KeystoreError, MlsTransport, OpenMlsError, RecursiveError, Session,
    mls::{self, conversation_cache::ConversationCache},
    mls_provider::{CryptoProvider, Database},
};
pub mod conversation;
mod credential;
pub mod e2e_identity;
mod error;
mod inner_guard;
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
///
/// Due to uniffi's design, we can't force the context to be dropped after the transaction is
/// committed. To work around that keep everything important in `TransactionContextInner`;
/// see `inner` and `take_inner`.
#[derive(Debug, Clone)]
pub struct TransactionContext {
    inner: Arc<RwLock<Option<TransactionContextInner>>>,
}

#[derive(derive_more::Debug)]
pub(crate) struct TransactionContextInner {
    core_crypto: Arc<CoreCrypto>,
    pending_epoch_changes: Arc<Mutex<Vec<(ConversationId, u64)>>>,
    #[debug(skip)]
    transaction: UniqueArc<core_crypto_keystore::Transaction>,
}

impl CoreCrypto {
    /// Creates a new transaction. All operations that persist data will be
    /// buffered in memory and when [TransactionContext::finish] is called, the data will be persisted
    /// in a single database transaction.
    pub async fn new_transaction(self: &Arc<Self>) -> Result<TransactionContext> {
        TransactionContext::new(self.clone()).await
    }
}

impl TransactionContext {
    async fn new(core_crypto: Arc<CoreCrypto>) -> Result<Self> {
        let transaction = core_crypto
            .database
            .new_transaction()
            .await
            .map_err(OpenMlsError::wrap("creating new transaction"))?;
        Ok(Self {
            inner: Arc::new(RwLock::new(Some(TransactionContextInner {
                core_crypto,
                pending_epoch_changes: Default::default(),
                transaction,
            }))),
        })
    }

    pub(crate) async fn session(&self) -> Result<Session> {
        let inner = self.inner().await?;
        inner.core_crypto.mls.read().await.as_ref().cloned().ok_or(
            RecursiveError::mls_client("Getting mls session from transaction context")(
                mls::session::Error::MlsNotInitialized,
            )
            .into(),
        )
    }

    #[cfg(test)]
    pub(crate) async fn set_session_if_exists(&self, new_session: Session) {
        let Ok(inner) = self.inner().await else {
            return;
        };
        let mut guard = inner.core_crypto.mls.write().await;
        if guard.as_ref().is_some() {
            *guard = Some(new_session)
        }
    }

    pub(crate) async fn mls_transport(&self) -> Result<Arc<dyn MlsTransport + 'static>> {
        let inner = self.inner().await?;
        inner
            .core_crypto
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
            )
    }

    /// Clones the [CryptoProvider].
    pub async fn crypto_provider(&self) -> Result<CryptoProvider> {
        let inner = self.inner().await?;
        inner
            .core_crypto
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
            )
    }

    pub(crate) async fn database(&self) -> Result<Arc<Database>> {
        let inner = self.inner().await?;
        Ok(inner.core_crypto.database.clone())
    }

    pub(crate) async fn pki_environment(&self) -> Result<Arc<PkiEnvironment>> {
        let inner = self.inner().await?;
        inner
            .core_crypto
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
            )
    }

    pub(crate) async fn mls_groups(&self) -> Result<MutexGuardArc<ConversationCache>> {
        let inner = self.inner().await?;
        let cache = inner
            .core_crypto
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
        let inner = self.inner().await?;
        inner.pending_epoch_changes.lock().await.push((conversation_id, epoch));
        Ok(())
    }

    /// Commits the transaction, meaning it takes all the enqueued operations and persist them into
    /// the keystore. After that the internal state is switched to invalid, causing errors if
    /// something is called from this object.
    pub async fn finish(&self) -> Result<()> {
        let TransactionContextInner {
            core_crypto,
            pending_epoch_changes,
            transaction: tx,
        } = self.take_inner().await?;

        let commit_result = tx
            .commit()
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

        commit_result
    }

    /// Aborts the transaction, meaning it discards all the enqueued operations.
    /// After that the internal state is switched to invalid, causing errors if
    /// something is called from this object.
    pub async fn abort(&self) -> Result<()> {
        let inner = self.take_inner().await?;

        // Drop any in-memory conversation state mutated during this transaction; it never reached
        // the keystore and would otherwise diverge from disk after rollback.
        if let Some(session) = inner.core_crypto.mls.read().await.as_ref() {
            session.conversation_cache.lock().await.clear();
        }

        Ok(())
    }

    /// Initializes the MLS client of [super::CoreCrypto].
    pub async fn mls_init(&self, session_id: ClientId, transport: Arc<dyn MlsTransport>) -> Result<()> {
        let database = self.database().await?;
        let pki_env = self.pki_environment().await.ok();
        let crypto_provider = CryptoProvider::new_with_pki_env(database.clone(), pki_env);
        let session = Session::new(session_id.clone(), crypto_provider, database.into(), transport);
        self.set_mls_session(session).await?;

        Ok(())
    }

    /// Set the `mls_session` Arc (also sets it on the transaction's CoreCrypto instance)
    pub(crate) async fn set_mls_session(&self, session: Session) -> Result<()> {
        let inner = self.inner().await?;
        let mut guard = inner.core_crypto.mls.write().await;
        *guard = Some(session);
        Ok(())
    }

    /// see [Session::id]
    pub async fn client_id(&self) -> Result<ClientId> {
        let session = self.session().await?;
        Ok(session.id())
    }

    /// Generates a random byte array of the specified size
    pub async fn random_bytes(&self, len: usize) -> Result<Vec<u8>> {
        use openmls_traits::random::OpenMlsRand as _;
        self.crypto_provider()
            .await?
            .rand()
            .random_vec(len)
            .map_err(OpenMlsError::wrap("generating random vector"))
            .map_err(Into::into)
    }

    /// Set arbitrary data to be retrieved by [TransactionContext::get_data].
    /// This is meant to be used as a check point at the end of a transaction.
    /// The data should be limited to a reasonable size.
    pub async fn set_data(&self, data: Vec<u8>) -> Result<()> {
        let inner = self.inner().await?;
        inner
            .transaction
            .save(ConsumerData::from(data))
            .await
            .map_err(KeystoreError::wrap("saving consumer data"))?;
        Ok(())
    }

    /// Get the data that has previously been set by [TransactionContext::set_data].
    /// This is meant to be used as a check point at the end of a transaction.
    pub async fn get_data(&self) -> Result<Option<Vec<u8>>> {
        let inner = self.inner().await?;
        match inner.transaction.get_unique::<ConsumerData>().await {
            Ok(maybe_data) => Ok(maybe_data.map(Into::into)),
            Err(CryptoKeystoreError::NotFound(..)) => Ok(None),
            Err(err) => Err(KeystoreError::wrap("finding unique consumer data")(err).into()),
        }
    }
}

impl TransactionContextInner {
    pub(crate) fn transaction(&self) -> &core_crypto_keystore::Transaction {
        &self.transaction
    }
}
