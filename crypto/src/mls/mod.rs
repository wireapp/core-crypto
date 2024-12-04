use std::sync::Arc;

use async_lock::RwLock;
use log::trace;

use crate::{
    prelude::{
        identifier::ClientIdentifier, key_package::INITIAL_KEYING_MATERIAL_COUNT, Client, ClientId, ConversationId,
        MlsCentralConfiguration, MlsCiphersuite, MlsConversation, MlsConversationConfiguration, MlsCredentialType,
        MlsTransport,
    },
    CoreCrypto,
};
use mls_crypto_provider::{EntropySeed, MlsCryptoProvider, MlsCryptoProviderConfiguration};
use openmls_traits::OpenMlsCryptoProvider;

use crate::context::CentralContext;

pub(crate) mod buffer_external_commit;
pub(crate) mod ciphersuite;
pub(crate) mod client;
pub mod conversation;
pub(crate) mod credential;
mod error;
pub(crate) mod external_commit;
pub(crate) mod external_proposal;
pub(crate) mod proposal;

pub use error::{Error, Result};

// Prevents direct instantiation of [MlsCentralConfiguration]
pub(crate) mod config {
    use ciphersuite::MlsCiphersuite;
    use mls_crypto_provider::EntropySeed;

    use super::*;

    /// Configuration parameters for `MlsCentral`
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct MlsCentralConfiguration {
        /// Location where the SQLite/IndexedDB database will be stored
        pub store_path: String,
        /// Identity key to be used to instantiate the [MlsCryptoProvider]
        pub identity_key: String,
        /// Identifier for the client to be used by [MlsCentral]
        pub client_id: Option<ClientId>,
        /// Entropy pool seed for the internal PRNG
        pub external_entropy: Option<EntropySeed>,
        /// All supported ciphersuites
        pub ciphersuites: Vec<ciphersuite::MlsCiphersuite>,
        /// Number of [openmls::prelude::KeyPackage] to create when creating a MLS client. Default to [INITIAL_KEYING_MATERIAL_COUNT]
        pub nb_init_key_packages: Option<usize>,
    }

    impl MlsCentralConfiguration {
        /// Creates a new instance of the configuration.
        ///
        /// # Arguments
        /// * `store_path` - location where the SQLite/IndexedDB database will be stored
        /// * `identity_key` - identity key to be used to instantiate the [MlsCryptoProvider]
        /// * `client_id` - identifier for the client to be used by [MlsCentral]
        /// * `ciphersuites` - Ciphersuites supported by this device
        /// * `entropy` - External source of entropy for platforms where default source insufficient
        ///
        /// # Errors
        /// Any empty string parameter will result in a [CryptoError::MalformedIdentifier] error.
        ///
        /// # Examples
        ///
        /// This should fail:
        /// ```
        /// use core_crypto::{prelude::MlsCentralConfiguration, CryptoError};
        ///
        /// let result = MlsCentralConfiguration::try_new(String::new(), String::new(), Some(b"".to_vec().into()), vec![], None, Some(100));
        /// assert!(matches!(result.unwrap_err(), CryptoError::MalformedIdentifier(_)));
        /// ```
        ///
        /// This should work:
        /// ```
        /// use core_crypto::prelude::{MlsCentralConfiguration, CryptoError, MlsCiphersuite};
        ///
        /// let result = MlsCentralConfiguration::try_new(
        ///     "/tmp/crypto".to_string(),
        ///     "MY_IDENTITY_KEY".to_string(),
        ///     Some(b"MY_CLIENT_ID".to_vec().into()),
        ///     vec![MlsCiphersuite::default()],
        ///     None,
        ///     Some(100),
        /// );
        /// assert!(result.is_ok());
        /// ```
        pub fn try_new(
            store_path: String,
            identity_key: String,
            client_id: Option<ClientId>,
            ciphersuites: Vec<MlsCiphersuite>,
            entropy: Option<Vec<u8>>,
            nb_init_key_packages: Option<usize>,
        ) -> Result<Self> {
            // TODO: probably more complex rules to enforce. Tracking issue: WPB-9598
            if store_path.trim().is_empty() {
                return Err(Error::MalformedIdentifier("store_path"));
            }
            // TODO: probably more complex rules to enforce. Tracking issue: WPB-9598
            if identity_key.trim().is_empty() {
                return Err(Error::MalformedIdentifier("identity_key"));
            }
            // TODO: probably more complex rules to enforce. Tracking issue: WPB-9598
            if let Some(client_id) = client_id.as_ref() {
                if client_id.is_empty() {
                    return Err(Error::MalformedIdentifier("client_id"));
                }
            }
            let external_entropy = entropy
                .as_deref()
                .map(|seed| &seed[..EntropySeed::EXPECTED_LEN])
                .map(EntropySeed::try_from_slice)
                .transpose()
                .map_err(Error::mls_operation("gathering external entropy"))?;
            Ok(Self {
                store_path,
                identity_key,
                client_id,
                ciphersuites,
                external_entropy,
                nb_init_key_packages,
            })
        }

        /// Sets the entropy seed
        pub fn set_entropy(&mut self, entropy: EntropySeed) {
            self.external_entropy = Some(entropy);
        }

        #[cfg(test)]
        #[allow(dead_code)]
        /// Creates temporary file to prevent test collisions which would happen with hardcoded file path
        /// Intended to be used only in tests.
        pub(crate) fn tmp_store_path(tmp_dir: &tempfile::TempDir) -> String {
            let path = tmp_dir.path().join("store.edb");
            std::fs::File::create(&path).unwrap();
            path.to_str().unwrap().to_string()
        }
    }
}

/// The entry point for the MLS CoreCrypto library. This struct provides all functionality to create
/// and manage groups, make proposals and commits.
#[derive(Debug, Clone)]
pub struct MlsCentral {
    pub(crate) mls_client: Client,
    pub(crate) mls_backend: MlsCryptoProvider,
    // this should be moved to the context
    pub(crate) transport: Arc<RwLock<Option<Arc<dyn MlsTransport + 'static>>>>,
}

impl MlsCentral {
    /// Tries to initialize the MLS Central object.
    /// Takes a store path (i.e. Disk location of the embedded database, should be consistent between messaging sessions)
    /// And a root identity key (i.e. enclaved encryption key for this device)
    ///
    /// # Arguments
    /// * `configuration` - the configuration for the `MlsCentral`
    ///
    /// # Errors
    /// Failures in the initialization of the KeyStore can cause errors, such as IO, the same kind
    /// of errors can happen when the groups are being restored from the KeyStore or even during
    /// the client initialization (to fetch the identity signature). Other than that, `MlsError`
    /// can be caused by group deserialization or during the initialization of the credentials:
    /// * for x509 Credentials if the cetificate chain length is lower than 2
    /// * for Basic Credentials if the signature key cannot be generated either by not supported
    ///   scheme or the key generation fails
    pub async fn try_new(configuration: MlsCentralConfiguration) -> Result<Self> {
        // Init backend (crypto + rand + keystore)
        let mls_backend = MlsCryptoProvider::try_new_with_configuration(MlsCryptoProviderConfiguration {
            db_path: &configuration.store_path,
            identity_key: &configuration.identity_key,
            in_memory: false,
            entropy_seed: configuration.external_entropy.clone(),
        })
        .await
        .map_err(Error::mls_operation("trying to initialize mls crypto provider object"))?;
        Self::new_with_backend(mls_backend, configuration).await
    }

    /// Same as the [MlsCentral::try_new] but instead, it uses an in memory KeyStore. Although required, the `store_path` parameter from the `MlsCentralConfiguration` won't be used here.
    pub async fn try_new_in_memory(configuration: MlsCentralConfiguration) -> Result<Self> {
        let mls_backend = MlsCryptoProvider::try_new_with_configuration(MlsCryptoProviderConfiguration {
            db_path: &configuration.store_path,
            identity_key: &configuration.identity_key,
            in_memory: true,
            entropy_seed: configuration.external_entropy.clone(),
        })
        .await
        .map_err(Error::mls_operation(
            "trying to initialize mls crypto provider object (in memory)",
        ))?;
        Self::new_with_backend(mls_backend, configuration).await
    }

    async fn new_with_backend(mls_backend: MlsCryptoProvider, configuration: MlsCentralConfiguration) -> Result<Self> {
        let mls_client = Client::default();

        // We create the core crypto instance first to enable creating a transaction from it and
        // doing all subsequent actions inside a single transaction, though it forces us to clone
        // a few Arcs and locks.
        let central = Self {
            mls_backend: mls_backend.clone(),
            mls_client: mls_client.clone(),
            transport: Arc::new(None.into()),
        };

        let cc = CoreCrypto::from(central);
        let context = cc
            .new_transaction()
            .await
            .map_err(Error::root("starting new transaction"))?;
        if let Some(id) = configuration.client_id {
            mls_client
                .init(
                    ClientIdentifier::Basic(id),
                    configuration.ciphersuites.as_slice(),
                    &mls_backend,
                    configuration
                        .nb_init_key_packages
                        .unwrap_or(INITIAL_KEYING_MATERIAL_COUNT),
                )
                .await
                .map_err(Error::mls_operation("initializing mls client"))?
        }
        let central = cc.mls;
        context
            .init_pki_env()
            .await
            .map_err(Error::e2e("initializing pki environment"))?;
        context.finish().await.map_err(Error::root("finishing transaction"))?;
        Ok(central)
    }

    /// Provide the implementation of functions to communicate with the delivery service
    /// (see [MlsTransport]).
    pub async fn provide_transport(&self, transport: Arc<dyn MlsTransport>) {
        self.transport.write().await.replace(transport);
    }

    /// Returns the client's most recent public signature key as a buffer.
    /// Used to upload a public key to the server in order to verify client's messages signature.
    ///
    /// # Arguments
    /// * `ciphersuite` - a callback to be called to perform authorization
    /// * `credential_type` - of the credential to look for
    pub async fn client_public_key(
        &self,
        ciphersuite: MlsCiphersuite,
        credential_type: MlsCredentialType,
    ) -> Result<Vec<u8>> {
        let cb = self
            .mls_client
            .find_most_recent_credential_bundle(ciphersuite.signature_algorithm(), credential_type)
            .await
            .map_err(Error::client("finding most recent credential bundle"))?;
        Ok(cb.signature_key.to_public_vec())
    }

    /// Returns the client's id as a buffer
    pub async fn client_id(&self) -> Result<ClientId> {
        self.mls_client
            .id()
            .await
            .map_err(Error::mls_operation("getting client id"))
    }

    /// Checks if a given conversation id exists locally
    pub async fn conversation_exists(&self, id: &ConversationId) -> Result<bool> {
        let result = self.get_conversation(id).await;
        Ok(!matches!(result, Err(conversation::Error::ConversationNotFound(_))))
    }

    /// Returns the epoch of a given conversation
    ///
    /// # Errors
    /// If the conversation can't be found
    #[cfg_attr(test, crate::idempotent)]
    pub async fn conversation_epoch(&self, id: &ConversationId) -> Result<u64> {
        Ok(self
            .get_conversation(id)
            .await
            .map_err(Error::mls_operation("getting conversation"))?
            .group
            .epoch()
            .as_u64())
    }

    /// Returns the ciphersuite of a given conversation
    ///
    /// # Errors
    /// If the conversation can't be found
    #[cfg_attr(test, crate::idempotent)]
    pub async fn conversation_ciphersuite(&self, id: &ConversationId) -> Result<MlsCiphersuite> {
        Ok(self
            .get_conversation(id)
            .await
            .map_err(Error::mls_operation("getting conversation"))?
            .ciphersuite())
    }

    /// Generates a random byte array of the specified size
    pub fn random_bytes(&self, len: usize) -> Result<Vec<u8>> {
        use openmls_traits::random::OpenMlsRand as _;
        self.mls_backend
            .rand()
            .random_vec(len)
            .map_err(Error::mls_operation("generating random vector"))
    }

    /// Closes the connection with the local KeyStore
    ///
    /// # Errors
    /// KeyStore errors, such as IO
    pub async fn close(self) -> Result<()> {
        self.mls_backend
            .close()
            .await
            .map_err(Error::mls_operation("closing connection with keystore"))
    }

    /// see [mls_crypto_provider::MlsCryptoProvider::reseed]
    pub async fn reseed(&self, seed: Option<EntropySeed>) -> Result<()> {
        self.mls_backend
            .reseed(seed)
            .map_err(Error::mls_operation("reseeding mls backend"))
    }
}

impl CentralContext {
    /// Initializes the MLS client if [super::CoreCrypto] has previously been initialized with
    /// `CoreCrypto::deferred_init` instead of `CoreCrypto::new`.
    /// This should stay as long as proteus is supported. Then it should be removed.
    pub async fn mls_init(
        &self,
        identifier: ClientIdentifier,
        ciphersuites: Vec<MlsCiphersuite>,
        nb_init_key_packages: Option<usize>,
    ) -> Result<()> {
        let nb_key_package = nb_init_key_packages.unwrap_or(INITIAL_KEYING_MATERIAL_COUNT);
        let mls_client = self.mls_client().await.map_err(Error::root("getting mls client"))?;
        mls_client
            .init(
                identifier,
                &ciphersuites,
                &self.mls_provider().await.map_err(Error::root("getting mls provider"))?,
                nb_key_package,
            )
            .await
            .map_err(Error::mls_operation("initializing mls client"))?;

        if mls_client.is_e2ei_capable().await {
            let client_id = mls_client
                .id()
                .await
                .map_err(Error::mls_operation("getting client id"))?;
            trace!(client_id:% = client_id; "Initializing PKI environment");
            self.init_pki_env().await.map_err(Error::e2e("initializing pki env"))?;
        }

        Ok(())
    }

    /// Generates MLS KeyPairs/CredentialBundle with a temporary, random client ID.
    /// This method is designed to be used in conjunction with [CentralContext::mls_init_with_client_id] and represents the first step in this process.
    ///
    /// This returns the TLS-serialized identity keys (i.e. the signature keypair's public key)
    #[cfg_attr(test, crate::dispotent)]
    pub async fn mls_generate_keypairs(&self, ciphersuites: Vec<MlsCiphersuite>) -> Result<Vec<ClientId>> {
        self.mls_client()
            .await
            .map_err(Error::root("getting mls client"))?
            .generate_raw_keypairs(
                &ciphersuites,
                &self.mls_provider().await.map_err(Error::root("getting mls provider"))?,
            )
            .await
            .map_err(Error::mls_operation("generating raw keypairs"))
    }

    /// Updates the current temporary Client ID with the newly provided one. This is the second step in the externally-generated clients process
    ///
    /// Important: This is designed to be called after [CentralContext::mls_generate_keypairs]
    #[cfg_attr(test, crate::dispotent)]
    pub async fn mls_init_with_client_id(
        &self,
        client_id: ClientId,
        tmp_client_ids: Vec<ClientId>,
        ciphersuites: Vec<MlsCiphersuite>,
    ) -> Result<()> {
        self.mls_client()
            .await
            .map_err(Error::root("getting mls client"))?
            .init_with_external_client_id(
                client_id,
                tmp_client_ids,
                &ciphersuites,
                &self.mls_provider().await.map_err(Error::root("getting mls provider"))?,
            )
            .await
            .map_err(Error::mls_operation("initializing mls client with external client id"))
    }

    /// see [MlsCentral::client_public_key]
    pub async fn client_public_key(
        &self,
        ciphersuite: MlsCiphersuite,
        credential_type: MlsCredentialType,
    ) -> Result<Vec<u8>> {
        let cb = self
            .mls_client()
            .await
            .map_err(Error::root("getting mls client"))?
            .find_most_recent_credential_bundle(ciphersuite.signature_algorithm(), credential_type)
            .await
            .map_err(Error::mls_operation("finding most recent credential bundle"))?;
        Ok(cb.signature_key.to_public_vec())
    }

    /// see [MlsCentral::client_id]
    pub async fn client_id(&self) -> Result<ClientId> {
        self.mls_client()
            .await
            .map_err(Error::root("getting mls client"))?
            .id()
            .await
            .map_err(Error::mls_operation("getting client id"))
    }

    /// Create a new empty conversation
    ///
    /// # Arguments
    /// * `id` - identifier of the group/conversation (must be unique otherwise the existing group
    ///   will be overridden)
    /// * `creator_credential_type` - kind of credential the creator wants to create the group with
    /// * `config` - configuration of the group/conversation
    ///
    /// # Errors
    /// Errors can happen from the KeyStore or from OpenMls for ex if no [openmls::key_packages::KeyPackage] can
    /// be found in the KeyStore
    #[cfg_attr(test, crate::dispotent)]
    pub async fn new_conversation(
        &self,
        id: &ConversationId,
        creator_credential_type: MlsCredentialType,
        config: MlsConversationConfiguration,
    ) -> Result<()> {
        if self.conversation_exists(id).await? || self.pending_group_exists(id).await? {
            return Err(Error::ConversationAlreadyExists(id.clone()));
        }
        let conversation = MlsConversation::create(
            id.clone(),
            &self.mls_client().await.map_err(Error::root("getting mls client"))?,
            creator_credential_type,
            config,
            &self.mls_provider().await.map_err(Error::root("getting mls provider"))?,
        )
        .await
        .map_err(Error::conversation("creating conversation"))?;

        self.mls_groups()
            .await
            .map_err(Error::root("getting mls groups"))?
            .insert(id.clone(), conversation);

        Ok(())
    }

    /// Checks if a given conversation id exists locally
    pub async fn conversation_exists(&self, id: &ConversationId) -> Result<bool> {
        Ok(self
            .mls_groups()
            .await
            .map_err(Error::root("getting mls groups"))?
            .get_fetch(
                id,
                &self
                    .mls_provider()
                    .await
                    .map_err(Error::root("getting mls provider"))?
                    .keystore(),
                None,
            )
            .await
            .ok()
            .flatten()
            .is_some())
    }

    /// Returns the epoch of a given conversation
    ///
    /// # Errors
    /// If the conversation can't be found
    #[cfg_attr(test, crate::idempotent)]
    pub async fn conversation_epoch(&self, id: &ConversationId) -> Result<u64> {
        Ok(self
            .get_conversation(id)
            .await
            .map_err(Error::conversation("getting conversation by id"))?
            .read()
            .await
            .group
            .epoch()
            .as_u64())
    }

    /// Returns the ciphersuite of a given conversation
    ///
    /// # Errors
    /// If the conversation can't be found
    #[cfg_attr(test, crate::idempotent)]
    pub async fn conversation_ciphersuite(&self, id: &ConversationId) -> Result<MlsCiphersuite> {
        Ok(self
            .get_conversation(id)
            .await
            .map_err(Error::conversation("getting conversation by id"))?
            .read()
            .await
            .ciphersuite())
    }

    /// Generates a random byte array of the specified size
    pub async fn random_bytes(&self, len: usize) -> Result<Vec<u8>> {
        use openmls_traits::random::OpenMlsRand as _;
        self.mls_provider()
            .await
            .map_err(Error::root("getting mls provider"))?
            .rand()
            .random_vec(len)
            .map_err(Error::mls_operation("generating random vector"))
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use crate::prelude::{CertificateBundle, ClientIdentifier, MlsCredentialType, INITIAL_KEYING_MATERIAL_COUNT};
    use crate::{
        mls::{MlsCentral, MlsCentralConfiguration},
        test_utils::{x509::X509TestChain, *},
        CoreCrypto,
    };

    wasm_bindgen_test_configure!(run_in_browser);

    mod conversation_epoch {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn can_get_newly_created_conversation_epoch(case: TestCase) {
            run_test_with_central(case.clone(), move |[central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    let epoch = central.context.conversation_epoch(&id).await.unwrap();
                    assert_eq!(epoch, 0);
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn can_get_conversation_epoch(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();
                    let epoch = alice_central.context.conversation_epoch(&id).await.unwrap();
                    assert_eq!(epoch, 1);
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn conversation_not_found(case: TestCase) {
            run_test_with_central(case.clone(), move |[central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    let err = central.context.conversation_epoch(&id).await.unwrap_err();
                    assert!(matches!(err, CryptoError::ConversationNotFound(conv_id) if conv_id == id));
                })
            })
            .await;
        }
    }

    mod invariants {
        use crate::prelude::MlsCiphersuite;

        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn can_create_from_valid_configuration(case: TestCase) {
            run_tests(move |[tmp_dir_argument]| {
                Box::pin(async move {
                    let configuration = MlsCentralConfiguration::try_new(
                        tmp_dir_argument,
                        "test".to_string(),
                        Some("alice".into()),
                        vec![case.ciphersuite()],
                        None,
                        Some(INITIAL_KEYING_MATERIAL_COUNT),
                    )
                    .unwrap();

                    let central = MlsCentral::try_new(configuration).await;
                    assert!(central.is_ok())
                })
            })
            .await
        }

        #[test]
        #[wasm_bindgen_test]
        fn store_path_should_not_be_empty_nor_blank() {
            let ciphersuites = vec![MlsCiphersuite::default()];
            let configuration = MlsCentralConfiguration::try_new(
                " ".to_string(),
                "test".to_string(),
                Some("alice".into()),
                ciphersuites,
                None,
                Some(INITIAL_KEYING_MATERIAL_COUNT),
            );
            assert!(matches!(
                configuration.unwrap_err(),
                CryptoError::MalformedIdentifier("store_path")
            ));
        }

        #[cfg_attr(not(target_family = "wasm"), async_std::test)]
        #[wasm_bindgen_test]
        async fn identity_key_should_not_be_empty_nor_blank() {
            run_tests(|[tmp_dir_argument]| {
                Box::pin(async move {
                    let ciphersuites = vec![MlsCiphersuite::default()];
                    let configuration = MlsCentralConfiguration::try_new(
                        tmp_dir_argument,
                        " ".to_string(),
                        Some("alice".into()),
                        ciphersuites,
                        None,
                        Some(INITIAL_KEYING_MATERIAL_COUNT),
                    );
                    assert!(matches!(
                        configuration.unwrap_err(),
                        CryptoError::MalformedIdentifier("identity_key")
                    ));
                })
            })
            .await
        }

        #[cfg_attr(not(target_family = "wasm"), async_std::test)]
        #[wasm_bindgen_test]
        async fn client_id_should_not_be_empty() {
            run_tests(|[tmp_dir_argument]| {
                Box::pin(async move {
                    let ciphersuites = vec![MlsCiphersuite::default()];
                    let configuration = MlsCentralConfiguration::try_new(
                        tmp_dir_argument,
                        "test".to_string(),
                        Some("".into()),
                        ciphersuites,
                        None,
                        Some(INITIAL_KEYING_MATERIAL_COUNT),
                    );
                    assert!(matches!(
                        configuration.unwrap_err(),
                        CryptoError::MalformedIdentifier("client_id")
                    ));
                })
            })
            .await
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn create_conversation_should_fail_when_already_exists(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
            Box::pin(async move {
                let id = conversation_id();

                let create = alice_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await;
                assert!(create.is_ok());

                // creating a conversation should first verify that the conversation does not already exist ; only then create it
                let repeat_create = alice_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await;
                assert!(matches!(repeat_create.unwrap_err(), CryptoError::ConversationAlreadyExists(i) if i == id));
            })
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_fetch_client_public_key(case: TestCase) {
        run_tests(move |[tmp_dir_argument]| {
            Box::pin(async move {
                let configuration = MlsCentralConfiguration::try_new(
                    tmp_dir_argument,
                    "test".to_string(),
                    Some("potato".into()),
                    vec![case.ciphersuite()],
                    None,
                    Some(INITIAL_KEYING_MATERIAL_COUNT),
                )
                .unwrap();

                let result = MlsCentral::try_new(configuration.clone()).await;
                assert!(result.is_ok());
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_2_phase_init_central(case: TestCase) {
        run_tests(move |[tmp_dir_argument]| {
            Box::pin(async move {
                let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());
                let configuration = MlsCentralConfiguration::try_new(
                    tmp_dir_argument,
                    "test".to_string(),
                    None,
                    vec![case.ciphersuite()],
                    None,
                    Some(INITIAL_KEYING_MATERIAL_COUNT),
                )
                .unwrap();
                // phase 1: init without mls_client
                let central = MlsCentral::try_new(configuration).await.unwrap();
                let cc = CoreCrypto::from(central);
                let context = cc.new_transaction().await.unwrap();
                x509_test_chain.register_with_central(&context).await;

                assert!(!context.mls_client().await.unwrap().is_ready().await);
                // phase 2: init mls_client
                let client_id = "alice";
                let identifier = match case.credential_type {
                    MlsCredentialType::Basic => ClientIdentifier::Basic(client_id.into()),
                    MlsCredentialType::X509 => {
                        CertificateBundle::rand_identifier(client_id, &[x509_test_chain.find_local_intermediate_ca()])
                    }
                };
                context
                    .mls_init(
                        identifier,
                        vec![case.ciphersuite()],
                        Some(INITIAL_KEYING_MATERIAL_COUNT),
                    )
                    .await
                    .unwrap();
                assert!(context.mls_client().await.unwrap().is_ready().await);
                // expect mls_client to work
                assert_eq!(
                    context
                        .get_or_create_client_keypackages(case.ciphersuite(), case.credential_type, 2)
                        .await
                        .unwrap()
                        .len(),
                    2
                );
            })
        })
        .await
    }
}
