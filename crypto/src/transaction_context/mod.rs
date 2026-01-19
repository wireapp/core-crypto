//! This module contains the primitives to enable transactional support on a higher level within the
//! [Session]. All mutating operations need to be done through a [TransactionContext].

use std::sync::Arc;

#[cfg(feature = "proteus")]
use async_lock::Mutex;
use async_lock::{RwLock, RwLockWriteGuardArc};
use core_crypto_keystore::{CryptoKeystoreError, entities::ConsumerData, traits::FetchFromDatabase as _};
pub use error::{Error, Result};
use mls_crypto_provider::{Database, MlsCryptoProvider};
use openmls_traits::OpenMlsCryptoProvider as _;

#[cfg(feature = "proteus")]
use crate::proteus::ProteusCentral;
use crate::{
    ClientId, ClientIdentifier, CoreCrypto, Credential, CredentialFindFilters, CredentialRef, KeystoreError,
    MlsConversation, MlsError, MlsTransport, RecursiveError, Session,
    group_store::GroupStore,
    mls::{self, HasSessionAndCrypto},
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
        keystore: Database,
        mls_session: Arc<RwLock<Option<Session>>>,
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
            self.database.clone(),
            self.mls.clone(),
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
        keystore: Database,
        mls_session: Arc<RwLock<Option<Session>>>,
        #[cfg(feature = "proteus")] proteus_central: Arc<Mutex<Option<ProteusCentral>>>,
    ) -> Result<Self> {
        keystore
            .new_transaction()
            .await
            .map_err(MlsError::wrap("creating new transaction"))?;
        let mls_groups = Arc::new(RwLock::new(Default::default()));
        Ok(Self {
            inner: Arc::new(
                TransactionContextInner::Valid {
                    keystore,
                    mls_session: mls_session.clone(),
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
            TransactionContextInner::Valid { mls_session, .. } => {
                if let Some(session) = mls_session.read().await.as_ref() {
                    return Ok(session.clone());
                }
                Err(mls::session::Error::MlsNotInitialized)
                    .map_err(RecursiveError::mls_client(
                        "Getting mls session from transaction context",
                    ))
                    .map_err(Into::into)
            }
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    #[cfg(test)]
    pub(crate) async fn set_session_if_exists(&self, new_session: Session) {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { mls_session, .. } => {
                let mut guard = mls_session.write().await;

                if guard.as_ref().is_some() {
                    *guard = Some(new_session)
                }
            }
            TransactionContextInner::Invalid => {}
        }
    }

    pub(crate) async fn mls_transport(&self) -> Result<Arc<dyn MlsTransport + 'static>> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { mls_session, .. } => {
                if let Some(session) = mls_session.read().await.as_ref() {
                    let transport = session.transport.clone();
                    return Ok(transport);
                }
                Err(mls::session::Error::MlsNotInitialized)
                    .map_err(RecursiveError::mls_client(
                        "Getting mls session from transaction context",
                    ))
                    .map_err(Into::into)
            }

            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    /// Clones all references that the [MlsCryptoProvider] comprises.
    pub async fn mls_provider(&self) -> Result<MlsCryptoProvider> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { mls_session, .. } => {
                if let Some(session) = mls_session.read().await.as_ref() {
                    return Ok(session.crypto_provider.clone());
                }
                Err(mls::session::Error::MlsNotInitialized)
                    .map_err(RecursiveError::mls_client(
                        "Getting mls session from transaction context",
                    ))
                    .map_err(Into::into)
            }
            TransactionContextInner::Invalid => Err(Error::InvalidTransactionContext),
        }
    }

    pub(crate) async fn keystore(&self) -> Result<Database> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { keystore, .. } => Ok(keystore.clone()),
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
        let TransactionContextInner::Valid { keystore, .. } = &*guard else {
            return Err(Error::InvalidTransactionContext);
        };

        let commit_result = keystore
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

        let TransactionContextInner::Valid { keystore, .. } = &*guard else {
            return Err(Error::InvalidTransactionContext);
        };

        let result = keystore
            .rollback_transaction()
            .await
            .map_err(KeystoreError::wrap("rolling back transaction"))
            .map_err(Into::into);

        *guard = TransactionContextInner::Invalid;
        result
    }

    /// Initializes the MLS client of [super::CoreCrypto].
    pub async fn mls_init(&self, identifier: ClientIdentifier, transport: Arc<dyn MlsTransport>) -> Result<()> {
        let database = self.keystore().await?;
        let client_id = identifier
            .get_id()
            .map_err(RecursiveError::mls_client("getting client id"))?
            .into_owned();

        let mls_backend = MlsCryptoProvider::new(database);
        let session = Session::new(client_id.clone(), mls_backend, transport);

        if matches!(identifier, ClientIdentifier::X509(..)) {
            log::trace!(client_id:% = client_id; "Initializing PKI environment");
            self.init_pki_env().await?;
        }

        self.set_mls_session(session).await?;

        Ok(())
    }

    /// Set the `mls_session` Arc (also sets it on the transaction's CoreCrypto instance)
    pub(crate) async fn set_mls_session(&self, session: Session) -> Result<()> {
        match &*self.inner.read().await {
            TransactionContextInner::Valid { mls_session, .. } => {
                let mut guard = mls_session.write().await;
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
        match self.keystore().await?.get_unique::<ConsumerData>().await {
            Ok(maybe_data) => Ok(maybe_data.map(Into::into)),
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
