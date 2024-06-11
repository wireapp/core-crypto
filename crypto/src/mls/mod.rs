use tracing::{trace, Instrument};

use mls_crypto_provider::{MlsCryptoProvider, MlsCryptoProviderConfiguration};
use openmls_traits::OpenMlsCryptoProvider;

use crate::prelude::{
    identifier::ClientIdentifier, key_package::INITIAL_KEYING_MATERIAL_COUNT, Client, ClientId, ConversationId,
    CoreCryptoCallbacks, CryptoError, CryptoResult, MlsCentralConfiguration, MlsCiphersuite, MlsConversation,
    MlsConversationConfiguration, MlsCredentialType, MlsError,
};

pub(crate) mod buffer_external_commit;
pub(crate) mod ciphersuite;
pub(crate) mod client;
pub(crate) mod conversation;
pub(crate) mod credential;
pub(crate) mod external_commit;
pub(crate) mod external_proposal;
pub(crate) mod proposal;
pub(crate) mod restore;

// Prevents direct instantiation of [MlsCentralConfiguration]
pub(crate) mod config {
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
        #[cfg_attr(not(test), tracing::instrument(skip_all, fields(store_path, ciphersuites = ?ciphersuites, client_id = client_id.as_ref().map(|id| base64::Engine::encode::<&[u8]>(&base64::prelude::BASE64_STANDARD, id))), err))]
        pub fn try_new(
            store_path: String,
            identity_key: String,
            client_id: Option<ClientId>,
            ciphersuites: Vec<MlsCiphersuite>,
            entropy: Option<Vec<u8>>,
            nb_init_key_packages: Option<usize>,
        ) -> CryptoResult<Self> {
            // TODO: probably more complex rules to enforce. Tracking issue: WPB-9598
            if store_path.trim().is_empty() {
                return Err(CryptoError::MalformedIdentifier("store_path"));
            }
            // TODO: probably more complex rules to enforce. Tracking issue: WPB-9598
            if identity_key.trim().is_empty() {
                return Err(CryptoError::MalformedIdentifier("identity_key"));
            }
            // TODO: probably more complex rules to enforce. Tracking issue: WPB-9598
            if let Some(client_id) = client_id.as_ref() {
                if client_id.is_empty() {
                    return Err(CryptoError::MalformedIdentifier("client_id"));
                }
            }
            let external_entropy = entropy
                .as_deref()
                .map(|seed| &seed[..EntropySeed::EXPECTED_LEN])
                .map(EntropySeed::try_from_slice)
                .transpose()?;
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
#[derive(Debug)]
pub struct MlsCentral {
    pub(crate) mls_client: Option<Client>,
    pub(crate) mls_backend: MlsCryptoProvider,
    pub(crate) mls_groups: crate::group_store::GroupStore<MlsConversation>,
    pub(crate) callbacks: Option<std::sync::Arc<dyn CoreCryptoCallbacks + 'static>>,
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
    /// scheme or the key generation fails
    #[cfg_attr(not(test), tracing::instrument(skip_all, err))]
    pub async fn try_new(configuration: MlsCentralConfiguration) -> CryptoResult<Self> {
        // Init backend (crypto + rand + keystore)
        let mls_backend = MlsCryptoProvider::try_new_with_configuration(MlsCryptoProviderConfiguration {
            db_path: &configuration.store_path,
            identity_key: &configuration.identity_key,
            in_memory: false,
            entropy_seed: configuration.external_entropy,
        })
        .in_current_span()
        .await?;
        let mls_client = if let Some(id) = configuration.client_id {
            // Init client identity (load or create)
            Some(
                Client::init(
                    ClientIdentifier::Basic(id),
                    configuration.ciphersuites.as_slice(),
                    &mls_backend,
                    configuration
                        .nb_init_key_packages
                        .unwrap_or(INITIAL_KEYING_MATERIAL_COUNT),
                )
                .await?,
            )
        } else {
            None
        };

        trace!("Trying to restore groups");
        // Restore persisted groups if there are any
        let mls_groups = Self::restore_groups(&mls_backend).await?;

        let central = Self {
            mls_backend,
            mls_client,
            mls_groups,
            callbacks: None,
        };

        central.init_pki_env().in_current_span().await?;

        Ok(central)
    }

    /// Same as the [MlsCentral::try_new] but instead, it uses an in memory KeyStore. Although required, the `store_path` parameter from the `MlsCentralConfiguration` won't be used here.
    #[cfg_attr(not(test), tracing::instrument(skip_all, err))]
    pub async fn try_new_in_memory(configuration: MlsCentralConfiguration) -> CryptoResult<Self> {
        let mls_backend = MlsCryptoProvider::try_new_with_configuration(MlsCryptoProviderConfiguration {
            db_path: &configuration.store_path,
            identity_key: &configuration.identity_key,
            in_memory: true,
            entropy_seed: configuration.external_entropy,
        })
        .in_current_span()
        .await?;
        let mls_client = if let Some(id) = configuration.client_id {
            Some(
                Client::init(
                    ClientIdentifier::Basic(id),
                    configuration.ciphersuites.as_slice(),
                    &mls_backend,
                    configuration
                        .nb_init_key_packages
                        .unwrap_or(INITIAL_KEYING_MATERIAL_COUNT),
                )
                .await?,
            )
        } else {
            None
        };
        let mls_groups = Self::restore_groups(&mls_backend).await?;

        let central = Self {
            mls_backend,
            mls_client,
            mls_groups,
            callbacks: None,
        };

        central.init_pki_env().in_current_span().await?;

        Ok(central)
    }

    /// Initializes the MLS client if [super::CoreCrypto] has previously been initialized with
    /// `CoreCrypto::deferred_init` instead of `CoreCrypto::new`.
    /// This should stay as long as proteus is supported. Then it should be removed.
    #[cfg_attr(not(test), tracing::instrument(err, skip(self, identifier), fields(ciphersuites = ?ciphersuites)))]
    pub async fn mls_init(
        &mut self,
        identifier: ClientIdentifier,
        ciphersuites: Vec<MlsCiphersuite>,
        nb_init_key_packages: Option<usize>,
    ) -> CryptoResult<()> {
        if self.mls_client.is_some() {
            // prevents wrong usage of the method instead of silently hiding the mistake
            return Err(CryptoError::ConsumerError);
        }
        let nb_key_package = nb_init_key_packages.unwrap_or(INITIAL_KEYING_MATERIAL_COUNT);
        let mls_client = Client::init(identifier, &ciphersuites, &self.mls_backend, nb_key_package).await?;

        if mls_client.is_e2ei_capable() {
            trace!(client_id = %mls_client.id(),"Initializing PKI environment");
            self.init_pki_env().in_current_span().await?;
        }

        self.mls_client.replace(mls_client);

        Ok(())
    }

    /// Generates MLS KeyPairs/CredentialBundle with a temporary, random client ID.
    /// This method is designed to be used in conjunction with [MlsCentral::mls_init_with_client_id] and represents the first step in this process.
    ///
    /// This returns the TLS-serialized identity keys (i.e. the signature keypair's public key)
    #[cfg_attr(test, crate::dispotent)]
    pub async fn mls_generate_keypairs(&self, ciphersuites: Vec<MlsCiphersuite>) -> CryptoResult<Vec<ClientId>> {
        if self.mls_client.is_some() {
            // prevents wrong usage of the method instead of silently hiding the mistake
            return Err(CryptoError::ConsumerError);
        }

        Client::generate_raw_keypairs(&ciphersuites, &self.mls_backend).await
    }

    /// Updates the current temporary Client ID with the newly provided one. This is the second step in the externally-generated clients process
    ///
    /// Important: This is designed to be called after [MlsCentral::mls_generate_keypairs]
    #[cfg_attr(test, crate::dispotent)]
    #[cfg_attr(not(test), tracing::instrument(err, skip(self), fields(ciphersuites = ?ciphersuites, client_id = ?client_id, tmp_client_ids = ?tmp_client_ids)))]
    pub async fn mls_init_with_client_id(
        &mut self,
        client_id: ClientId,
        tmp_client_ids: Vec<ClientId>,
        ciphersuites: Vec<MlsCiphersuite>,
    ) -> CryptoResult<()> {
        if self.mls_client.is_some() {
            // prevents wrong usage of the method instead of silently hiding the mistake
            return Err(CryptoError::ConsumerError);
        }

        let mls_client =
            Client::init_with_external_client_id(client_id, tmp_client_ids, &ciphersuites, &self.mls_backend).await?;

        self.mls_client = Some(mls_client);
        Ok(())
    }

    /// Sets the consumer callbacks (i.e authorization callbacks for CoreCrypto to perform authorization calls when needed)
    ///
    /// # Arguments
    /// * `callbacks` - a callback to be called to perform authorization
    pub fn callbacks(&mut self, callbacks: std::sync::Arc<dyn CoreCryptoCallbacks>) {
        self.callbacks.replace(callbacks);
    }

    /// Returns the client's most recent public signature key as a buffer.
    /// Used to upload a public key to the server in order to verify client's messages signature.
    ///
    /// # Arguments
    /// * `ciphersuite` - a callback to be called to perform authorization
    /// * `credential_type` - of the credential to look for
    pub fn client_public_key(
        &self,
        ciphersuite: MlsCiphersuite,
        credential_type: MlsCredentialType,
    ) -> CryptoResult<Vec<u8>> {
        let mls_client = self.mls_client()?;
        let cb = mls_client
            .find_most_recent_credential_bundle(ciphersuite.signature_algorithm(), credential_type)
            .ok_or(CryptoError::ClientSignatureNotFound)?;
        Ok(cb.signature_key.to_public_vec())
    }

    /// Returns the client's id as a buffer
    pub fn client_id(&self) -> CryptoResult<ClientId> {
        Ok(self.mls_client()?.id().clone())
    }

    /// Create a new empty conversation
    ///
    /// # Arguments
    /// * `id` - identifier of the group/conversation (must be unique otherwise the existing group
    /// will be overridden)
    /// * `creator_credential_type` - kind of credential the creator wants to create the group with
    /// * `config` - configuration of the group/conversation
    ///
    /// # Errors
    /// Errors can happen from the KeyStore or from OpenMls for ex if no [openmls::key_packages::KeyPackage] can
    /// be found in the KeyStore
    #[cfg_attr(test, crate::dispotent)]
    #[cfg_attr(not(test), tracing::instrument(err, skip(self, config), fields(id = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, id))))]
    pub async fn new_conversation(
        &mut self,
        id: &ConversationId,
        creator_credential_type: MlsCredentialType,
        config: MlsConversationConfiguration,
    ) -> CryptoResult<()> {
        if self.conversation_exists(id).await || self.pending_group_exists(id).await {
            return Err(CryptoError::ConversationAlreadyExists(id.clone()));
        }

        let mls_client = self.mls_client.as_mut().ok_or(CryptoError::MlsNotInitialized)?;
        let conversation = MlsConversation::create(
            id.clone(),
            mls_client,
            creator_credential_type,
            config,
            &self.mls_backend,
        )
        .in_current_span()
        .await?;

        self.mls_groups.insert(id.clone(), conversation);

        Ok(())
    }

    /// Checks if a given conversation id exists locally
    pub async fn conversation_exists(&mut self, id: &ConversationId) -> bool {
        self.mls_groups
            .get_fetch(id, self.mls_backend.borrow_keystore_mut(), None)
            .await
            .ok()
            .flatten()
            .is_some()
    }

    /// Returns the epoch of a given conversation
    ///
    /// # Errors
    /// If the conversation can't be found
    #[cfg_attr(test, crate::idempotent)]
    pub async fn conversation_epoch(&mut self, id: &ConversationId) -> CryptoResult<u64> {
        Ok(self.get_conversation(id).await?.read().await.group.epoch().as_u64())
    }

    /// Returns the ciphersuite of a given conversation
    ///
    /// # Errors
    /// If the conversation can't be found
    #[cfg_attr(test, crate::idempotent)]
    pub async fn conversation_ciphersuite(&mut self, id: &ConversationId) -> CryptoResult<MlsCiphersuite> {
        Ok(self.get_conversation(id).await?.read().await.ciphersuite())
    }

    /// Closes the connection with the local KeyStore
    ///
    /// # Errors
    /// KeyStore errors, such as IO
    pub async fn close(self) -> CryptoResult<()> {
        self.mls_backend.close().await?;
        Ok(())
    }

    /// Destroys everything we have, in-memory and on disk.
    ///
    /// # Errors
    /// KeyStore errors, such as IO
    pub async fn wipe(self) -> CryptoResult<()> {
        self.mls_backend.destroy_and_reset().await?;
        Ok(())
    }

    /// Generates a random byte array of the specified size
    pub fn random_bytes(&self, len: usize) -> CryptoResult<Vec<u8>> {
        use openmls_traits::random::OpenMlsRand as _;
        Ok(self.mls_backend.rand().random_vec(len)?)
    }

    /// Returns a reference for the internal Crypto Provider
    pub fn provider(&self) -> &MlsCryptoProvider {
        &self.mls_backend
    }

    /// Returns a mutable reference for the internal Crypto Provider
    pub fn provider_mut(&mut self) -> &mut MlsCryptoProvider {
        &mut self.mls_backend
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::prelude::{CertificateBundle, ClientIdentifier, MlsCredentialType, INITIAL_KEYING_MATERIAL_COUNT};
    use crate::{
        mls::{CryptoError, MlsCentral, MlsCentralConfiguration},
        test_utils::{x509::X509TestChain, *},
    };

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod conversation_epoch {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_get_newly_created_conversation_epoch(case: TestCase) {
            run_test_with_central(case.clone(), move |[mut central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    central
                        .mls_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    let epoch = central.mls_central.conversation_epoch(&id).await.unwrap();
                    assert_eq!(epoch, 0);
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_get_conversation_epoch(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .mls_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .mls_central
                            .invite_all(&case, &id, [&mut bob_central.mls_central])
                            .await
                            .unwrap();
                        let epoch = alice_central.mls_central.conversation_epoch(&id).await.unwrap();
                        assert_eq!(epoch, 1);
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn conversation_not_found(case: TestCase) {
            run_test_with_central(case.clone(), move |[mut central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    let err = central.mls_central.conversation_epoch(&id).await.unwrap_err();
                    assert!(matches!(err, CryptoError::ConversationNotFound(conv_id) if conv_id == id));
                })
            })
            .await;
        }
    }

    pub mod invariants {
        use crate::prelude::MlsCiphersuite;

        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_create_from_valid_configuration(case: TestCase) {
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
        pub fn store_path_should_not_be_empty_nor_blank() {
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
        pub async fn identity_key_should_not_be_empty_nor_blank() {
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
        pub async fn client_id_should_not_be_empty() {
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
    pub async fn create_conversation_should_fail_when_already_exists(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
            Box::pin(async move {
                let id = conversation_id();

                let create = alice_central
                    .mls_central
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await;
                assert!(create.is_ok());

                // creating a conversation should first verify that the conversation does not already exist ; only then create it
                let repeat_create = alice_central
                    .mls_central
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await;
                assert!(matches!(repeat_create.unwrap_err(), CryptoError::ConversationAlreadyExists(i) if i == id));
            })
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn can_fetch_client_public_key(case: TestCase) {
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
    pub async fn can_2_phase_init_central(case: TestCase) {
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
                let mut central = MlsCentral::try_new(configuration).await.unwrap();
                x509_test_chain.register_with_central(&central).await;

                assert!(central.mls_client.is_none());
                // phase 2: init mls_client
                let client_id = "alice";
                let identifier = match case.credential_type {
                    MlsCredentialType::Basic => ClientIdentifier::Basic(client_id.into()),
                    MlsCredentialType::X509 => {
                        CertificateBundle::rand_identifier(client_id, &[x509_test_chain.find_local_intermediate_ca()])
                    }
                };
                central
                    .mls_init(
                        identifier,
                        vec![case.ciphersuite()],
                        Some(INITIAL_KEYING_MATERIAL_COUNT),
                    )
                    .await
                    .unwrap();
                assert!(central.mls_client.is_some());
                // expect mls_client to work
                assert_eq!(
                    central
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
