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
pub use epoch_observer::EpochObserver;
pub(crate) use error::{Error, Result};
pub use history_observer::HistoryObserver;
use identities::Identities;
use mls_crypto_provider::{EntropySeed, MlsCryptoProvider};
use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    Ciphersuite, ClientId, CredentialType, HistorySecret, LeafError, MlsError, MlsTransport, RecursiveError,
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
    id: ClientId,
    identities: Arc<RwLock<Identities>>,
    pub(crate) crypto_provider: MlsCryptoProvider,
    pub(crate) transport: Arc<dyn MlsTransport + 'static>,
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

impl Session {
    /// Create a new `Session`
    pub fn new(
        id: ClientId,
        identities: Identities,
        crypto_provider: MlsCryptoProvider,
        transport: Arc<dyn MlsTransport>,
    ) -> Self {
        Self {
            id,
            identities: Arc::new(RwLock::new(identities)),
            crypto_provider,
            transport,
            epoch_observer: Arc::new(RwLock::new(None)),
            history_observer: Arc::new(RwLock::new(None)),
        }
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

    /// Returns whether this client is E2EI capable
    pub async fn is_e2ei_capable(&self) -> bool {
        self.identities
            .read()
            .await
            .iter()
            .any(|cred| cred.credential_type() == CredentialType::X509)
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

        pub async fn identities(&self) -> Identities {
            self.identities.read().await.clone()
        }

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
