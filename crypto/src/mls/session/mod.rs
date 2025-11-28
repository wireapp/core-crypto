mod credential;
pub(crate) mod e2e_identity;
mod epoch_observer;
mod error;
mod history_observer;
pub(crate) mod id;
pub(crate) mod identifier;
pub(crate) mod identities;
pub(crate) mod key_package;
pub(crate) mod user_id;

use std::sync::Arc;

use async_lock::RwLock;
use core_crypto_keystore::Database;
pub use epoch_observer::EpochObserver;
pub(crate) use error::{Error, Result};
pub use history_observer::HistoryObserver;
use identities::Identities;
use mls_crypto_provider::{EntropySeed, MlsCryptoProvider};
use openmls_traits::{OpenMlsCryptoProvider, types::SignatureScheme};

use crate::{
    Ciphersuite, ClientId, ClientIdentifier, CoreCrypto, CredentialFindFilters, CredentialRef, CredentialType,
    HistorySecret, LeafError, MlsError, MlsTransport, RecursiveError,
    group_store::GroupStore,
    mls::{
        self, HasSessionAndCrypto,
        conversation::{ConversationIdRef, ImmutableConversation},
    },
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
    pub(crate) inner: Arc<RwLock<Option<SessionInner>>>,
    pub(crate) crypto_provider: MlsCryptoProvider,
    pub(crate) transport: Arc<RwLock<Option<Arc<dyn MlsTransport + 'static>>>>,
    #[debug("EpochObserver")]
    pub(crate) epoch_observer: Arc<RwLock<Option<Arc<dyn EpochObserver + 'static>>>>,
    #[debug("HistoryObserver")]
    pub(crate) history_observer: Arc<RwLock<Option<Arc<dyn HistoryObserver + 'static>>>>,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl HasSessionAndCrypto for Session {
    async fn session(&self) -> mls::Result<Session> {
        Ok(self.clone())
    }

    async fn crypto_provider(&self) -> mls::Result<MlsCryptoProvider> {
        Ok(self.crypto_provider.clone())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SessionInner {
    id: ClientId,
    pub(crate) identities: Identities,
}

impl Session {
    /// Creates a new [Session]. Does not initialize MLS or Proteus.
    ///
    /// ## Errors
    ///
    /// Failures in the initialization of the KeyStore can cause errors, such as IO, the same kind
    /// of errors can happen when the groups are being restored from the KeyStore or even during
    /// the client initialization (to fetch the identity signature).
    pub async fn try_new(database: &Database) -> crate::mls::Result<Self> {
        // cloning a database is relatively cheap; it's all arcs inside
        let database = database.to_owned();
        // Init backend (crypto + rand + keystore)
        let mls_backend = MlsCryptoProvider::new(database);

        // We create the core crypto instance first to enable creating a transaction from it and
        // doing all subsequent actions inside a single transaction, though it forces us to clone
        // a few Arcs and locks.
        let session = Self {
            crypto_provider: mls_backend,
            inner: Default::default(),
            transport: Arc::new(None.into()),
            epoch_observer: Arc::new(None.into()),
            history_observer: Arc::new(None.into()),
        };

        let cc = CoreCrypto::from(session);
        let context = cc
            .new_transaction()
            .await
            .map_err(RecursiveError::transaction("starting new transaction"))?;

        context
            .init_pki_env()
            .await
            .map_err(RecursiveError::transaction("initializing pki environment"))?;
        context
            .finish()
            .await
            .map_err(RecursiveError::transaction("finishing transaction"))?;

        Ok(cc.mls)
    }

    /// Provide the implementation of functions to communicate with the delivery service
    /// (see [MlsTransport]).
    pub async fn provide_transport(&self, transport: Arc<dyn MlsTransport>) {
        self.transport.write().await.replace(transport);
    }

    /// Initializes the client.
    ///
    /// Loads any cryptographic material already present in the keystore, but does not create any.
    /// If no credentials are present in the keystore, then one _must_ be created and added to the
    /// session before it can be used.
    pub async fn init(&self, identifier: ClientIdentifier, signature_schemes: &[SignatureScheme]) -> Result<()> {
        self.ensure_unready().await?;
        let client_id = identifier.get_id()?.into_owned();

        // we want to find all credentials matching this identifier, having a valid signature scheme.
        // the `CredentialRef::find` API doesn't allow us to easily find those credentials having
        // one of a set of signature schemes, meaning we have two paths here:
        // we could either search unbound by signature schemes and then filter for valid ones here,
        // or we could iterate over the list of signature schemes and build up a set of credential refs.
        // as there are only a few signature schemes possible and the cost of a find operation is non-trivial,
        // we choose the first option.
        // we might revisit this choice after WPB-20844 and WPB-21819.
        let mut credential_refs = CredentialRef::find(
            &self.crypto_provider.keystore(),
            CredentialFindFilters::builder().client_id(&client_id).build(),
        )
        .await
        .map_err(RecursiveError::mls_credential_ref(
            "loading matching credential refs while initializing a client",
        ))?;
        credential_refs.retain(|credential_ref| signature_schemes.contains(&credential_ref.signature_scheme()));

        let mut identities = Identities::new(credential_refs.len());
        let credentials_cache = CredentialRef::load_stored_credentials(&self.crypto_provider.keystore())
            .await
            .map_err(RecursiveError::mls_credential_ref(
                "loading credential ref cache while initializing session",
            ))?;

        for credential_ref in credential_refs {
            for credential_result in
                credential_ref
                    .load_from_cache(&credentials_cache)
                    .map_err(RecursiveError::mls_credential_ref(
                        "loading credential list in session init",
                    ))?
            {
                let credential = credential_result
                    .map_err(RecursiveError::mls_credential_ref("loading credential in session init"))?;

                match identities.push_credential(credential).await {
                    Err(Error::CredentialConflict) => {
                        // this is what we get for not having real primary keys in our DB
                        // no harm done though; no need to propagate this error
                    }
                    Ok(_) => {}
                    Err(err) => {
                        return Err(RecursiveError::MlsClient {
                            context: "adding credential to identities in init",
                            source: Box::new(err),
                        }
                        .into());
                    }
                }
            }
        }

        self.replace_inner(SessionInner {
            id: client_id,
            identities,
        })
        .await;

        Ok(())
    }

    /// Resets the client to an uninitialized state.
    #[cfg(test)]
    pub(crate) async fn reset(&self) {
        let mut inner_lock = self.inner.write().await;
        *inner_lock = None;
    }

    pub(crate) async fn is_ready(&self) -> bool {
        let inner_lock = self.inner.read().await;
        inner_lock.is_some()
    }

    async fn ensure_unready(&self) -> Result<()> {
        if self.is_ready().await {
            Err(Error::UnexpectedlyReady)
        } else {
            Ok(())
        }
    }

    async fn replace_inner(&self, new_inner: SessionInner) {
        let mut inner_lock = self.inner.write().await;
        *inner_lock = Some(new_inner);
    }

    /// Get an immutable view of an `MlsConversation`.
    ///
    /// Because it operates on the raw conversation type, this may be faster than
    /// [crate::transaction_context::TransactionContext::conversation]. for transient and immutable
    /// purposes. For long-lived or mutable purposes, prefer the other method.
    pub async fn get_raw_conversation(&self, id: &ConversationIdRef) -> Result<ImmutableConversation> {
        let raw_conversation = GroupStore::fetch_from_keystore(id, &self.crypto_provider.keystore(), None)
            .await
            .map_err(RecursiveError::root("getting conversation by id"))?
            .ok_or_else(|| LeafError::ConversationNotFound(id.to_owned()))?;
        Ok(ImmutableConversation::new(raw_conversation, self.clone()))
    }

    /// Returns the client's most recent public signature key as a buffer.
    /// Used to upload a public key to the server in order to verify client's messages signature.
    ///
    /// # Arguments
    /// * `ciphersuite` - a callback to be called to perform authorization
    /// * `credential_type` - of the credential to look for
    pub async fn public_key(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
    ) -> crate::mls::Result<Vec<u8>> {
        let cb = self
            .find_most_recent_credential(ciphersuite.signature_algorithm(), credential_type)
            .await
            .map_err(RecursiveError::mls_client("finding most recent credential"))?;
        Ok(cb.signature_key_pair.to_public_vec())
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

    /// see [mls_crypto_provider::MlsCryptoProvider::reseed]
    pub async fn reseed(&self, seed: Option<EntropySeed>) -> crate::mls::Result<()> {
        self.crypto_provider
            .reseed(seed)
            .map_err(MlsError::wrap("reseeding mls backend"))
            .map_err(Into::into)
    }

    /// Restore from an external [`HistorySecret`].
    pub(crate) async fn restore_from_history_secret(&self, history_secret: HistorySecret) -> Result<()> {
        self.ensure_unready().await?;

        // store the client id (with some other stuff)
        self.replace_inner(SessionInner {
            id: history_secret.client_id.clone(),
            identities: Identities::new(0),
        })
        .await;

        // store the key package
        history_secret
            .key_package
            .store(&self.crypto_provider)
            .await
            .map_err(MlsError::wrap("storing key package encapsulation"))?;

        Ok(())
    }

    /// Retrieves the client's client id. This is free-form and not inspected.
    pub async fn id(&self) -> Result<ClientId> {
        match &*self.inner.read().await {
            None => Err(Error::MlsNotInitialized),
            Some(SessionInner { id, .. }) => Ok(id.clone()),
        }
    }

    /// Returns whether this client is E2EI capable
    pub async fn is_e2ei_capable(&self) -> bool {
        match &*self.inner.read().await {
            None => false,
            Some(SessionInner { identities, .. }) => identities
                .iter()
                .any(|cred| cred.credential_type() == CredentialType::X509),
        }
    }
}

#[cfg(test)]
mod tests {
    use core_crypto_keystore::{connection::FetchFromDatabase as _, entities::*};
    use mls_crypto_provider::MlsCryptoProvider;

    use super::*;
    use crate::{
        CertificateBundle, Credential, KeystoreError, test_utils::*, transaction_context::test_utils::EntitiesCount,
    };

    impl Session {
        // test functions are not held to the same documentation standard as proper functions
        #![allow(missing_docs)]

        /// Replace any existing credentials, identities, client_id, and similar with newly generated ones.
        pub async fn random_generate(
            &self,
            case: &crate::test_utils::TestContext,
            signer: Option<&crate::test_utils::x509::X509Certificate>,
        ) -> Result<()> {
            self.reset().await;
            let user_uuid = uuid::Uuid::new_v4();
            let rnd_id = rand::random::<usize>();
            let client_id = format!("{}:{rnd_id:x}@members.wire.com", user_uuid.hyphenated());
            let client_id = ClientId(client_id.into_bytes());

            let credential;
            let identifier;
            match case.credential_type {
                CredentialType::Basic => {
                    identifier = ClientIdentifier::Basic(client_id.clone());
                    credential = Credential::basic(case.ciphersuite(), client_id, &self.crypto_provider).unwrap();
                }
                CredentialType::X509 => {
                    let signer = signer.expect("Missing intermediate CA").to_owned();
                    let cert = CertificateBundle::rand(&client_id, &signer);
                    identifier = ClientIdentifier::X509([(case.signature_scheme(), cert.clone())].into());
                    credential = Credential::x509(case.ciphersuite(), cert).unwrap();
                }
            };

            self.init(identifier, &[case.signature_scheme()]).await.unwrap();

            self.add_credential(credential).await.unwrap();

            Ok(())
        }

        pub async fn find_keypackages(&self, backend: &MlsCryptoProvider) -> Result<Vec<openmls::prelude::KeyPackage>> {
            use core_crypto_keystore::CryptoKeystoreMls as _;
            let kps = backend
                .key_store()
                .mls_fetch_keypackages::<openmls::prelude::KeyPackage>(u32::MAX)
                .await
                .map_err(KeystoreError::wrap("fetching mls keypackages"))?;
            Ok(kps)
        }

        /// Count the entities
        pub async fn count_entities(&self) -> EntitiesCount {
            let keystore = self.crypto_provider.keystore();
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

    #[apply(all_cred_cipher)]
    async fn can_generate_session(mut case: TestContext) {
        let [alice] = case.sessions().await;
        let key_store = case.create_in_memory_database().await;
        let backend = MlsCryptoProvider::new(key_store);
        let x509_test_chain = if case.is_x509() {
            let x509_test_chain = crate::test_utils::x509::X509TestChain::init_empty(case.signature_scheme());
            x509_test_chain.register_with_provider(&backend).await;
            Some(x509_test_chain)
        } else {
            None
        };
        backend.new_transaction().await.unwrap();
        let session = alice.session().await;
        session
            .random_generate(
                &case,
                x509_test_chain.as_ref().map(|chain| chain.find_local_intermediate_ca()),
            )
            .await
            .unwrap();
    }
}
