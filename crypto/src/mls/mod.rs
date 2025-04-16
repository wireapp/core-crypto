use crate::{
    MlsError,
    prelude::{ClientId, MlsConversation, Session},
};
use core_crypto_keystore::DatabaseKey;
use mls_crypto_provider::MlsCryptoProvider;

pub(crate) mod ciphersuite;
pub mod conversation;
pub(crate) mod credential;
mod error;
pub(crate) mod proposal;
pub(crate) mod session;

pub use error::{Error, Result};
pub use session::EpochObserver;

/// Prevents direct instantiation of [MlsClientConfiguration]
pub(crate) mod config {
    use ciphersuite::MlsCiphersuite;
    use mls_crypto_provider::EntropySeed;

    use super::*;

    /// Configuration parameters for [Client].
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct MlsClientConfiguration {
        /// Location where the SQLite/IndexedDB database will be stored
        pub store_path: String,
        /// Database key to be used to instantiate the [MlsCryptoProvider]
        pub database_key: DatabaseKey,
        /// Identifier for the client to be used by [MlsCentral]
        pub client_id: Option<ClientId>,
        /// Entropy pool seed for the internal PRNG
        pub external_entropy: Option<EntropySeed>,
        /// All supported ciphersuites
        pub ciphersuites: Vec<ciphersuite::MlsCiphersuite>,
        /// Number of [openmls::prelude::KeyPackage] to create when creating a MLS client. Default to [INITIAL_KEYING_MATERIAL_COUNT]
        pub nb_init_key_packages: Option<usize>,
    }

    impl MlsClientConfiguration {
        /// Creates a new instance of the configuration.
        ///
        /// # Arguments
        /// * `store_path` - location where the SQLite/IndexedDB database will be stored
        /// * `database_key` - key to be used to instantiate the [MlsCryptoProvider]
        /// * `client_id` - identifier for the client to be used by [MlsCentral]
        /// * `ciphersuites` - Ciphersuites supported by this device
        /// * `entropy` - External source of entropy for platforms where default source insufficient
        ///
        /// # Errors
        /// Any empty string parameter will result in a [Error::MalformedIdentifier] error.
        ///
        /// # Examples
        ///
        /// ```
        /// use core_crypto::prelude::{MlsClientConfiguration, MlsCiphersuite};
        /// use core_crypto::DatabaseKey;
        ///
        /// let result = MlsClientConfiguration::try_new(
        ///     "/tmp/crypto".to_string(),
        ///     DatabaseKey::generate(),
        ///     Some(b"MY_CLIENT_ID".to_vec().into()),
        ///     vec![MlsCiphersuite::default()],
        ///     None,
        ///     Some(100),
        /// );
        /// assert!(result.is_ok());
        /// ```
        pub fn try_new(
            store_path: String,
            database_key: DatabaseKey,
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
                .map_err(MlsError::wrap("gathering external entropy"))?;
            Ok(Self {
                store_path,
                database_key,
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

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub(crate) trait HasSessionAndCrypto: Send {
    async fn session(&self) -> Result<Session>;
    async fn crypto_provider(&self) -> Result<MlsCryptoProvider>;
}

#[cfg(test)]
mod tests {
    use crate::transaction_context::Error as TransactionError;
    use wasm_bindgen_test::*;

    use crate::prelude::{
        CertificateBundle, ClientIdentifier, INITIAL_KEYING_MATERIAL_COUNT, MlsClientConfiguration, MlsCredentialType,
    };
    use crate::{
        CoreCrypto,
        mls::Session,
        test_utils::{x509::X509TestChain, *},
    };

    wasm_bindgen_test_configure!(run_in_browser);

    use core_crypto_keystore::DatabaseKey;

    mod conversation_epoch {
        use super::*;
        use crate::mls::conversation::Conversation as _;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn can_get_newly_created_conversation_epoch(case: TestContext) {
            run_test_with_central(case.clone(), move |[central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    let epoch = central.context.conversation(&id).await.unwrap().epoch().await;
                    assert_eq!(epoch, 0);
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn can_get_conversation_epoch(case: TestContext) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();
                    let epoch = alice_central.context.conversation(&id).await.unwrap().epoch().await;
                    assert_eq!(epoch, 1);
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn conversation_not_found(case: TestContext) {
            use crate::LeafError;

            run_test_with_central(case.clone(), move |[central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    let err = central.context.conversation(&id).await.unwrap_err();
                    assert!(matches!(
                        err,
                        TransactionError::Leaf(LeafError::ConversationNotFound(i)) if i == id
                    ));
                })
            })
            .await;
        }
    }

    mod invariants {
        use crate::{mls, prelude::MlsCiphersuite};

        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn can_create_from_valid_configuration(case: TestContext) {
            run_tests(move |[tmp_dir_argument]| {
                Box::pin(async move {
                    let configuration = MlsClientConfiguration::try_new(
                        tmp_dir_argument,
                        DatabaseKey::generate(),
                        Some("alice".into()),
                        vec![case.ciphersuite()],
                        None,
                        Some(INITIAL_KEYING_MATERIAL_COUNT),
                    )
                    .unwrap();

                    let new_client_result = Session::try_new(configuration).await;
                    assert!(new_client_result.is_ok())
                })
            })
            .await
        }

        #[test]
        #[wasm_bindgen_test]
        fn store_path_should_not_be_empty_nor_blank() {
            let ciphersuites = vec![MlsCiphersuite::default()];
            let configuration = MlsClientConfiguration::try_new(
                " ".to_string(),
                DatabaseKey::generate(),
                Some("alice".into()),
                ciphersuites,
                None,
                Some(INITIAL_KEYING_MATERIAL_COUNT),
            );
            assert!(matches!(
                configuration.unwrap_err(),
                mls::Error::MalformedIdentifier("store_path")
            ));
        }

        #[cfg_attr(not(target_family = "wasm"), async_std::test)]
        #[wasm_bindgen_test]
        async fn client_id_should_not_be_empty() {
            run_tests(|[tmp_dir_argument]| {
                Box::pin(async move {
                    let ciphersuites = vec![MlsCiphersuite::default()];
                    let configuration = MlsClientConfiguration::try_new(
                        tmp_dir_argument,
                        DatabaseKey::generate(),
                        Some("".into()),
                        ciphersuites,
                        None,
                        Some(INITIAL_KEYING_MATERIAL_COUNT),
                    );
                    assert!(matches!(
                        configuration.unwrap_err(),
                        mls::Error::MalformedIdentifier("client_id")
                    ));
                })
            })
            .await
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn create_conversation_should_fail_when_already_exists(case: TestContext) {
        use crate::LeafError;

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
                assert!(matches!(repeat_create.unwrap_err(), TransactionError::Leaf(LeafError::ConversationAlreadyExists(i)) if i == id));
            })
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_fetch_client_public_key(case: TestContext) {
        run_tests(move |[tmp_dir_argument]| {
            Box::pin(async move {
                let configuration = MlsClientConfiguration::try_new(
                    tmp_dir_argument,
                    DatabaseKey::generate(),
                    Some("potato".into()),
                    vec![case.ciphersuite()],
                    None,
                    Some(INITIAL_KEYING_MATERIAL_COUNT),
                )
                .unwrap();

                let result = Session::try_new(configuration.clone()).await;
                println!("{:?}", result);
                assert!(result.is_ok());
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_2_phase_init_central(case: TestContext) {
        run_tests(move |[tmp_dir_argument]| {
            Box::pin(async move {
                let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());
                let configuration = MlsClientConfiguration::try_new(
                    tmp_dir_argument,
                    DatabaseKey::generate(),
                    None,
                    vec![case.ciphersuite()],
                    None,
                    Some(INITIAL_KEYING_MATERIAL_COUNT),
                )
                .unwrap();
                // phase 1: init without initialized mls_client
                let client = Session::try_new(configuration).await.unwrap();
                let cc = CoreCrypto::from(client);
                let context = cc.new_transaction().await.unwrap();
                x509_test_chain.register_with_central(&context).await;

                assert!(!context.session().await.unwrap().is_ready().await);
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
                assert!(context.session().await.unwrap().is_ready().await);
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
