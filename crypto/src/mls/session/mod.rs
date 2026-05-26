mod credential;
pub(crate) mod e2e_identity;
mod epoch_observer;
mod error;
mod history_observer;
pub(crate) mod id;
pub(crate) mod identifier;
pub(crate) mod key_package;
pub(crate) mod user_id;

use std::sync::Arc;

use async_lock::{Mutex, RwLock};
pub use epoch_observer::EpochObserver;
pub(crate) use error::{Error, Result};
pub use history_observer::HistoryObserver;
use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    ClientId, HistorySecret, ImmutableDatabase, LeafError, MlsError, MlsTransport, RecursiveError,
    mls::{
        self, HasSessionAndCrypto,
        conversation::{ConversationIdRef, ImmutableConversation},
        conversation_cache::MlsConversationCache,
    },
    mls_provider::{EntropySeed, MlsCryptoProvider},
};

/// A MLS Session enables a user device to communicate via the MLS protocol.
///
/// This closely maps to the `Client` term in [RFC 9720], but we avoid that term to avoid ambiguity;
/// `Client` is very overloaded with distinct meanings.
///
/// There is one `Session` per user per device. A session can contain many MLS groups/conversations.
///
/// It is cheap to clone a `Session` because everything heavy is wrapped inside an [Arc].
///
/// [RFC 9720]: https://www.rfc-editor.org/rfc/rfc9420.html
#[derive(Clone, derive_more::Debug)]
pub struct Session {
    id: ClientId,
    pub(crate) crypto_provider: MlsCryptoProvider,
    pub(crate) transport: Arc<dyn MlsTransport + 'static>,
    database: ImmutableDatabase,
    #[debug("EpochObserver")]
    pub(crate) epoch_observer: Arc<RwLock<Option<Arc<dyn EpochObserver + 'static>>>>,
    #[debug("HistoryObserver")]
    pub(crate) history_observer: Arc<RwLock<Option<Arc<dyn HistoryObserver + 'static>>>>,
    /// LRU cache of live MLS conversations.
    ///
    /// Shared across transactions for cache reuse;
    /// cleared on transaction rollback to avoid serving stale state.
    pub(crate) conversation_cache: Arc<Mutex<MlsConversationCache>>,
}

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
impl HasSessionAndCrypto for Session {
    async fn session(&self) -> mls::Result<Session> {
        Ok(self.clone())
    }

    async fn crypto_provider(&self) -> mls::Result<MlsCryptoProvider> {
        Ok(self.crypto_provider.clone())
    }
}

impl Session {
    /// Create a new `Session`
    pub fn new(
        id: ClientId,
        crypto_provider: MlsCryptoProvider,
        database: ImmutableDatabase,
        transport: Arc<dyn MlsTransport>,
    ) -> Self {
        Self {
            id,
            crypto_provider,
            transport,
            database,
            epoch_observer: Arc::new(RwLock::new(None)),
            history_observer: Arc::new(RwLock::new(None)),
            conversation_cache: Arc::new(Mutex::new(MlsConversationCache::new())),
        }
    }

    /// Get an immutable view of an `MlsConversation`.
    ///
    /// Because it operates on the raw conversation type, this may be faster than
    /// [crate::transaction_context::TransactionContext::conversation] for transient and immutable
    /// purposes. For long-lived or mutable purposes, prefer the other method.
    pub async fn get_raw_conversation(&self, id: &ConversationIdRef) -> Result<ImmutableConversation> {
        ImmutableConversation::load(self.clone(), id)
            .await
            .map_err(RecursiveError::mls_conversation("getting raw conversation by id"))?
            .ok_or_else(|| LeafError::ConversationNotFound(id.to_owned()))
            .map_err(Into::into)
    }

    /// Checks if a given conversation id exists locally
    pub async fn conversation_exists(&self, id: &ConversationIdRef) -> Result<bool> {
        match self.get_raw_conversation(id).await {
            Ok(_) => Ok(true),
            Err(Error::Leaf(LeafError::ConversationNotFound(_))) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Generates a random byte array of the specified size
    pub fn random_bytes(&self, len: usize) -> crate::mls::Result<Vec<u8>> {
        use openmls_traits::random::OpenMlsRand as _;
        self.crypto_provider
            .rand()
            .random_vec(len)
            .map_err(MlsError::wrap("generating random vector"))
            .map_err(Into::into)
    }

    /// Waits for running transactions to finish, then closes the connection with the local KeyStore.
    ///
    /// # Errors
    /// KeyStore errors, such as IO, and if there is more than one strong reference
    /// to the connection.
    pub async fn close(&self) -> crate::mls::Result<()> {
        self.crypto_provider
            .close()
            .await
            .map_err(MlsError::wrap("closing connection with keystore"))
            .map_err(Into::into)
    }

    /// Get read-only access to the database.
    pub fn database(&self) -> &ImmutableDatabase {
        &self.database
    }

    /// see [crate::mls_provider::MlsCryptoProvider::reseed]
    pub async fn reseed(&self, seed: Option<EntropySeed>) -> crate::mls::Result<()> {
        self.crypto_provider
            .reseed(seed)
            .map_err(MlsError::wrap("reseeding mls backend"))
            .map_err(Into::into)
    }

    /// Restore from an external [`HistorySecret`].
    pub(crate) async fn restore_from_history_secret(&self, history_secret: HistorySecret) -> Result<()> {
        // store the key package
        history_secret
            .key_package
            .store(&self.crypto_provider)
            .await
            .map_err(MlsError::wrap("storing key package encapsulation"))?;

        Ok(())
    }

    /// Retrieves the client's client id. This is free-form and not inspected.
    pub fn id(&self) -> ClientId {
        self.id.clone()
    }
}

#[cfg(test)]
mod tests {
    use core_crypto_keystore::{entities::*, traits::FetchFromDatabase};

    use super::*;
    use crate::{KeystoreError, mls_provider::MlsCryptoProvider, transaction_context::test_utils::EntitiesCount};

    impl Session {
        // test functions are not held to the same documentation standard as proper functions
        #![allow(missing_docs)]

        pub async fn find_keypackages(&self, backend: &MlsCryptoProvider) -> Result<Vec<openmls::prelude::KeyPackage>> {
            use core_crypto_keystore::CryptoKeystoreMls as _;
            let kps = backend
                .key_store()
                .mls_fetch_key_packages::<openmls::prelude::KeyPackage>(u32::MAX)
                .await
                .map_err(KeystoreError::wrap("fetching mls keypackages"))?;
            Ok(kps)
        }

        /// Count the entities
        pub async fn count_entities(&self) -> EntitiesCount {
            let keystore = &self.database;
            let credential = keystore.count::<StoredCredential>().await.unwrap();
            let encryption_keypair = keystore.count::<StoredEncryptionKeyPair>().await.unwrap();
            let epoch_encryption_keypair = keystore.count::<StoredEpochEncryptionKeypair>().await.unwrap();
            let enrollment = keystore.count::<StoredE2eiEnrollment>().await.unwrap();
            let group = keystore.count::<PersistedMlsGroup>().await.unwrap();
            let hpke_private_key = keystore.count::<StoredHpkePrivateKey>().await.unwrap();
            let key_package = keystore.count::<StoredKeypackage>().await.unwrap();
            let pending_group = keystore.count::<PersistedMlsPendingGroup>().await.unwrap();
            let pending_messages = keystore.count::<MlsPendingMessage>().await.unwrap();
            let psk_bundle = keystore.count::<StoredPskBundle>().await.unwrap();
            EntitiesCount {
                credential,
                encryption_keypair,
                epoch_encryption_keypair,
                enrollment,
                group,
                hpke_private_key,
                key_package,
                pending_group,
                pending_messages,
                psk_bundle,
            }
        }
    }
}
