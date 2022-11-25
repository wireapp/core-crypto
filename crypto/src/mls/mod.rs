use crate::{CoreCryptoCallbacks, CryptoError, CryptoResult, MlsError};
use std::collections::HashMap;

use openmls::{
    messages::Welcome,
    prelude::{Ciphersuite, KeyPackageBundle},
};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{Deserialize, Serialize};

use crate::prelude::config::{MlsConversationConfiguration, MlsCustomConfiguration};
use client::{Client, ClientId};
use config::MlsCentralConfiguration;
use conversation::{ConversationId, MlsConversation};
use credential::CertificateBundle;
use mls_crypto_provider::{MlsCryptoProvider, MlsCryptoProviderConfiguration};

pub(crate) mod client;
pub(crate) mod conversation;
pub(crate) mod credential;
pub(crate) mod external_commit;
pub(crate) mod external_proposal;
pub(crate) mod member;
pub(crate) mod proposal;

#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::Deref)]
#[repr(transparent)]
/// A wrapper for the OpenMLS Ciphersuite, so that we are able to provide a default value.
pub struct MlsCiphersuite(Ciphersuite);

impl Default for MlsCiphersuite {
    fn default() -> Self {
        Self(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
    }
}

impl From<Ciphersuite> for MlsCiphersuite {
    fn from(value: Ciphersuite) -> Self {
        Self(value)
    }
}

impl From<MlsCiphersuite> for Ciphersuite {
    fn from(ciphersuite: MlsCiphersuite) -> Self {
        ciphersuite.0
    }
}

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
        /// TODO: pending wire-server API supports selecting a ciphersuite only the first item of this array will be used.
        pub ciphersuites: Vec<MlsCiphersuite>,
    }

    impl MlsCentralConfiguration {
        /// Creates a new instance of the configuration.
        ///
        /// # Arguments
        /// * `store_path` - location where the SQLite/IndexedDB database will be stored
        /// * `identity_key` - identity key to be used to instantiate the [MlsCryptoProvider]
        /// * `client_id` - identifier for the client to be used by [MlsCentral]
        /// * `ciphersuites` - Ciphersuites supported by this device
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
        /// let result = MlsCentralConfiguration::try_new(String::new(), String::new(), Some(b"".to_vec().into()), vec![]);
        /// assert!(matches!(result.unwrap_err(), CryptoError::MalformedIdentifier(_)));
        /// ```
        ///
        /// This should work:
        /// ```
        /// use core_crypto::{prelude::MlsCentralConfiguration, CryptoError};
        /// use core_crypto::mls::MlsCiphersuite;
        ///
        /// let result = MlsCentralConfiguration::try_new(
        ///     "/tmp/crypto".to_string(),
        ///     "MY_IDENTITY_KEY".to_string(),
        ///     Some(b"MY_CLIENT_ID".to_vec().into()),
        ///     vec![MlsCiphersuite::default()],
        /// );
        /// assert!(result.is_ok());
        /// ```
        pub fn try_new(
            store_path: String,
            identity_key: String,
            client_id: Option<ClientId>,
            ciphersuites: Vec<MlsCiphersuite>,
        ) -> CryptoResult<Self> {
            // TODO: probably more complex rules to enforce
            if store_path.trim().is_empty() {
                return Err(CryptoError::MalformedIdentifier(store_path));
            }
            // TODO: probably more complex rules to enforce
            if identity_key.trim().is_empty() {
                return Err(CryptoError::MalformedIdentifier(identity_key));
            }
            // TODO: probably more complex rules to enforce
            if let Some(client_id) = client_id.as_ref() {
                if client_id.is_empty() {
                    return Err(CryptoError::MalformedIdentifier(String::new()));
                }
            }
            Ok(Self {
                store_path,
                identity_key,
                client_id,
                external_entropy: None,
                ciphersuites,
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
    pub(crate) mls_groups: HashMap<ConversationId, MlsConversation>,
    pub(crate) callbacks: Option<Box<dyn CoreCryptoCallbacks + 'static>>,
}

impl MlsCentral {
    /// Tries to initialize the MLS Central object.
    /// Takes a store path (i.e. Disk location of the embedded database, should be consistent between messaging sessions)
    /// And a root identity key (i.e. enclaved encryption key for this device)
    ///
    /// # Arguments
    /// * `configuration` - the configuration for the `MlsCentral`
    /// * `certificate_bundle` - an optional `CertificateBundle`. It will be used to generate the `CredentialBundle`. If `None`is passed, credentials of type a Basic will be created, otherwise a x509.
    ///
    /// # Errors
    /// Failures in the initialization of the KeyStore can cause errors, such as IO, the same kind
    /// of errors can happen when the groups are being restored from the KeyStore or even during
    /// the client initialization (to fetch the identity signature). Other than that, `MlsError`
    /// can be caused by group deserialization or during the initialization of the credentials:
    /// * for x509 Credentials if the cetificate chain length is lower than 2
    /// * for Basic Credentials if the signature key cannot be generated either by not supported
    /// scheme or the key generation fails
    pub async fn try_new(
        configuration: MlsCentralConfiguration,
        certificate_bundle: Option<CertificateBundle>,
    ) -> CryptoResult<Self> {
        // Init backend (crypto + rand + keystore)
        let mls_backend = MlsCryptoProvider::try_new_with_configuration(MlsCryptoProviderConfiguration {
            db_path: &configuration.store_path,
            identity_key: &configuration.identity_key,
            in_memory: false,
            entropy_seed: configuration.external_entropy,
        })
        .await?;
        let mls_client = if let Some(client_id) = configuration.client_id {
            // Init client identity (load or create)
            Some(
                Client::init(
                    client_id,
                    certificate_bundle,
                    configuration.ciphersuites.as_slice(),
                    &mls_backend,
                )
                .await?,
            )
        } else {
            None
        };

        // Restore persisted groups if there are any
        let mls_groups = Self::restore_groups(&mls_backend).await?;

        Ok(Self {
            mls_backend,
            mls_client,
            mls_groups,
            callbacks: None,
        })
    }

    /// Same as the [crate::MlsCentral::try_new] but instead, it uses an in memory KeyStore. Although required, the `store_path` parameter from the `MlsCentralConfiguration` won't be used here.
    pub async fn try_new_in_memory(
        configuration: MlsCentralConfiguration,
        certificate_bundle: Option<CertificateBundle>,
    ) -> CryptoResult<Self> {
        let mls_backend = MlsCryptoProvider::try_new_with_configuration(MlsCryptoProviderConfiguration {
            db_path: &configuration.store_path,
            identity_key: &configuration.identity_key,
            in_memory: true,
            entropy_seed: configuration.external_entropy,
        })
        .await?;
        let mls_client = if let Some(client_id) = configuration.client_id {
            Some(
                Client::init(
                    client_id,
                    certificate_bundle,
                    configuration.ciphersuites.as_slice(),
                    &mls_backend,
                )
                .await?,
            )
        } else {
            None
        };
        let mls_groups = Self::restore_groups(&mls_backend).await?;

        Ok(Self {
            mls_backend,
            mls_client,
            mls_groups,
            callbacks: None,
        })
    }

    /// Initializes the MLS client if [CoreCrypto] has previously been initialized with
    /// [CoreCrypto::deferred_init] instead of [CoreCrypto::new].
    /// This should stay as long as proteus is supported. Then it should be removed.
    pub async fn mls_init(
        &mut self,
        client_id: ClientId,
        ciphersuites: Vec<MlsCiphersuite>,
        certificate_bundle: Option<CertificateBundle>,
    ) -> CryptoResult<()> {
        if self.mls_client.is_some() {
            // prevents wrong usage of the method instead of silently hiding the mistake
            return Err(CryptoError::ImplementationError);
        }
        let mls_client = Client::init(
            client_id,
            certificate_bundle,
            ciphersuites.as_slice(),
            &self.mls_backend,
        )
        .await?;
        self.mls_client = Some(mls_client);
        Ok(())
    }

    /// Restore existing groups from the KeyStore.
    async fn restore_groups(backend: &MlsCryptoProvider) -> CryptoResult<HashMap<ConversationId, MlsConversation>> {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        let states = backend.key_store().mls_groups_restore().await?;
        if states.is_empty() {
            return Ok(HashMap::new());
        }

        let groups = states.into_iter().try_fold(
            HashMap::new(),
            |mut acc, (group_id, state)| -> CryptoResult<HashMap<ConversationId, MlsConversation>> {
                let conversation = MlsConversation::from_serialized_state(state)?;
                acc.insert(group_id, conversation);
                Ok(acc)
            },
        )?;
        Ok(groups)
    }

    /// Sets the consumer callbacks (i.e authorization callbacks for CoreCrypto to perform authorization calls when needed)
    ///
    /// # Arguments
    /// * `callbacks` - a callback to be called to perform authorization
    pub fn callbacks(&mut self, callbacks: Box<dyn CoreCryptoCallbacks>) {
        self.callbacks = Some(callbacks);
    }

    /// Returns the client's public key as a buffer
    pub fn client_public_key(&self) -> CryptoResult<Vec<u8>> {
        Ok(self
            .mls_client
            .as_ref()
            .ok_or(CryptoError::MlsNotInitialized)?
            .public_key()
            .to_vec())
    }

    /// Returns the client's id as a buffer
    pub fn client_id(&self) -> CryptoResult<ClientId> {
        Ok(self
            .mls_client
            .as_ref()
            .ok_or(CryptoError::MlsNotInitialized)?
            .id()
            .clone())
    }

    /// Returns `amount_requested` OpenMLS [`KeyPackageBundle`]s.
    /// Will always return the requested amount as it will generate the necessary (lacking) amount on-the-fly
    ///
    /// Note: Keypackage pruning is performed as a first step
    ///
    /// # Arguments
    /// * `amount_requested` - number of KeyPackages to request and fill the `KeyPackageBundle`
    ///
    /// # Return type
    /// A vector of `KeyPackageBundle`
    ///
    /// # Errors
    /// Errors can happen when accessing the KeyStore
    pub async fn client_keypackages(&self, amount_requested: usize) -> CryptoResult<Vec<KeyPackageBundle>> {
        self.mls_client
            .as_ref()
            .ok_or(CryptoError::MlsNotInitialized)?
            .request_keying_material(amount_requested, &self.mls_backend)
            .await
    }

    /// Returns the count of valid, non-expired, unclaimed keypackages in store
    pub async fn client_valid_keypackages_count(&self) -> CryptoResult<usize> {
        self.mls_client
            .as_ref()
            .ok_or(CryptoError::MlsNotInitialized)?
            .valid_keypackages_count(&self.mls_backend)
            .await
    }

    /// Create a new empty conversation
    ///
    /// # Arguments
    /// * `id` - identifier of the group/conversation (must be unique otherwise the existing group
    /// will be overridden)
    /// * `config` - configuration of the group/conversation
    ///
    /// # Errors
    /// Errors can happen from the KeyStore or from OpenMls for ex if no [KeyPackageBundle] can
    /// be found in the KeyStore
    pub async fn new_conversation(
        &mut self,
        id: ConversationId,
        config: MlsConversationConfiguration,
    ) -> CryptoResult<()> {
        let mls_client = self.mls_client.as_mut().ok_or(CryptoError::MlsNotInitialized)?;
        let conversation = MlsConversation::create(id.clone(), mls_client, config, &self.mls_backend).await?;

        self.mls_groups.insert(id, conversation);

        Ok(())
    }

    /// Checks if a given conversation id exists locally
    pub fn conversation_exists(&self, id: &ConversationId) -> bool {
        self.mls_groups.contains_key(id)
    }

    /// Returns the epoch of a given conversation
    ///
    /// # Errors
    /// If the conversation can't be found
    pub fn conversation_epoch(&self, id: &ConversationId) -> CryptoResult<u64> {
        Ok(self
            .mls_groups
            .get(id)
            .ok_or_else(|| CryptoError::ConversationNotFound(id.to_owned()))?
            .group
            .epoch()
            .as_u64())
    }

    /// Create a conversation from a received MLS Welcome message
    ///
    /// # Arguments
    /// * `welcome` - a `Welcome` message received as a result of a commit adding new members to a group
    /// * `configuration` - configuration of the group/conversation
    ///
    /// # Return type
    /// This function will return the conversation/group id
    ///
    /// # Errors
    /// Errors can be originating from the KeyStore of from OpenMls:
    /// * if no [KeyPackageBundle] can be read from the KeyStore
    /// * if the message can't be decrypted
    pub async fn process_welcome_message(
        &mut self,
        welcome: Welcome,
        custom_cfg: MlsCustomConfiguration,
    ) -> CryptoResult<ConversationId> {
        let configuration = MlsConversationConfiguration {
            custom: custom_cfg,
            ..Default::default()
        };
        let conversation = MlsConversation::from_welcome_message(welcome, configuration, &self.mls_backend).await?;
        let conversation_id = conversation.id().clone();
        self.mls_groups.insert(conversation_id.clone(), conversation);

        Ok(conversation_id)
    }

    /// Create a conversation from a TLS serialized MLS Welcome message. The `MlsConversationConfiguration` used in this function will be the default implementation.
    ///
    /// # Arguments
    /// * `welcome` - a TLS serialized welcome message
    /// * `configuration` - configuration of the MLS conversation fetched from the Delivery Service
    ///
    /// # Return type
    /// This function will return the conversation/group id
    ///
    /// # Errors
    /// see [MlsCentral::process_welcome_message]
    pub async fn process_raw_welcome_message(
        &mut self,
        welcome: Vec<u8>,
        custom_cfg: MlsCustomConfiguration,
    ) -> CryptoResult<ConversationId> {
        let mut cursor = std::io::Cursor::new(welcome);
        let welcome = Welcome::tls_deserialize(&mut cursor).map_err(MlsError::from)?;
        self.process_welcome_message(welcome, custom_cfg).await
    }

    /// Exports a TLS-serialized view of the current group state corresponding to the provided conversation ID.
    ///
    /// # Arguments
    /// * `conversation` - the group/conversation id
    /// * `message` - the encrypted message as a byte array
    ///
    /// # Return type
    /// A TLS serialized byte array of the `PublicGroupState`
    ///
    /// # Errors
    /// If the conversation can't be found, an error will be returned. Other errors are originating
    /// from OpenMls and serialization
    pub async fn export_public_group_state(&self, conversation_id: &ConversationId) -> CryptoResult<Vec<u8>> {
        let conversation = self.get_conversation(conversation_id)?;
        let state = conversation
            .group
            .export_public_group_state(&self.mls_backend)
            .await
            .map_err(MlsError::from)?;

        Ok(state.tls_serialize_detached().map_err(MlsError::from)?)
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
    use openmls_traits::types::SignatureScheme;
    use wasm_bindgen_test::*;

    use crate::{
        mls::{CryptoError, MlsCentral, MlsCentralConfiguration},
        test_utils::*,
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
                    central.new_conversation(id.clone(), case.cfg.clone()).await.unwrap();
                    let epoch = central.conversation_epoch(&id).unwrap();
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
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();
                        let epoch = alice_central.conversation_epoch(&id).unwrap();
                        assert_eq!(epoch, 1);
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn conversation_not_found(case: TestCase) {
            run_test_with_central(case.clone(), move |[central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    let err = central.conversation_epoch(&id).unwrap_err();
                    assert!(matches!(err, CryptoError::ConversationNotFound(conv_id) if conv_id == id));
                })
            })
            .await;
        }
    }

    pub mod invariants {
        use super::*;
        use crate::prelude::MlsCiphersuite;

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
                    )
                    .unwrap();

                    let central = MlsCentral::try_new(configuration, case.credential()).await;
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
            );
            assert!(matches!(configuration.unwrap_err(), CryptoError::MalformedIdentifier(v) if v == " "));
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
                    );
                    assert!(matches!(configuration.unwrap_err(), CryptoError::MalformedIdentifier(v) if v == " "));
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
                    );
                    assert!(matches!(configuration.unwrap_err(), CryptoError::MalformedIdentifier(v) if v.is_empty()));
                })
            })
            .await
        }
    }

    pub mod persistence {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_persist_group_state(case: TestCase) {
            run_tests(move |[tmp_dir_argument]| {
                Box::pin(async move {
                    let configuration = MlsCentralConfiguration::try_new(
                        tmp_dir_argument,
                        "test".to_string(),
                        Some("potato".into()),
                        vec![case.ciphersuite()],
                    )
                    .unwrap();

                    let mut central = MlsCentral::try_new(configuration.clone(), case.credential())
                        .await
                        .unwrap();
                    let id = conversation_id();
                    let _ = central.new_conversation(id.clone(), case.cfg.clone()).await;

                    central.close().await.unwrap();
                    let mut central = MlsCentral::try_new(configuration, case.credential()).await.unwrap();
                    let _ = central.encrypt_message(&id, b"Test").await.unwrap();

                    central.mls_backend.destroy_and_reset().await.unwrap();
                })
            })
            .await
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn can_fetch_client_public_key(case: TestCase) {
        // TODO we only support ed25519 signatures for certificates currently
        if case.ciphersuite().0.signature_algorithm() == SignatureScheme::ED25519 {
            run_tests(move |[tmp_dir_argument]| {
                Box::pin(async move {
                    let configuration = MlsCentralConfiguration::try_new(
                        tmp_dir_argument,
                        "test".to_string(),
                        Some("potato".into()),
                        vec![case.ciphersuite()],
                    )
                    .unwrap();

                    let result = MlsCentral::try_new(configuration.clone(), case.credential()).await;
                    assert!(result.is_ok());
                })
            })
            .await
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn can_2_phase_init_central(case: TestCase) {
        run_tests(move |[tmp_dir_argument]| {
            Box::pin(async move {
                let configuration = MlsCentralConfiguration::try_new(
                    tmp_dir_argument,
                    "test".to_string(),
                    None,
                    vec![case.ciphersuite()],
                )
                .unwrap();
                // phase 1: init without mls_client
                let mut central = MlsCentral::try_new(configuration, case.credential()).await.unwrap();
                assert!(central.mls_client.is_none());
                // phase 2: init mls_client
                let client_id = "alice".into();
                central
                    .mls_init(client_id, vec![case.ciphersuite()], case.credential())
                    .await
                    .unwrap();
                assert!(central.mls_client.is_some());
                // expect mls_client to work
                assert_eq!(central.client_keypackages(2).await.unwrap().len(), 2);
            })
        })
        .await
    }
}
