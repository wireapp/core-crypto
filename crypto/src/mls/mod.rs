use crate::prelude::{ClientId, MlsConversation, Session};
use mls_crypto_provider::MlsCryptoProvider;

pub(crate) mod ciphersuite;
pub mod conversation;
pub(crate) mod credential;
mod error;
pub(crate) mod proposal;
pub(crate) mod session;

pub use error::{Error, Result};
pub use session::EpochObserver;
pub use session::HistoryObserver;

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub(crate) trait HasSessionAndCrypto: Send {
    async fn session(&self) -> Result<Session>;
    async fn crypto_provider(&self) -> Result<MlsCryptoProvider>;
}

#[cfg(test)]
mod tests {
    use crate::transaction_context::Error as TransactionError;

    use crate::prelude::{
        CertificateBundle, ClientIdentifier, INITIAL_KEYING_MATERIAL_COUNT, MlsCredentialType, SessionConfig,
    };
    use crate::{
        CoreCrypto,
        mls::Session,
        test_utils::{x509::X509TestChain, *},
    };

    use core_crypto_keystore::DatabaseKey;

    mod conversation_epoch {
        use super::*;
        use crate::mls::conversation::Conversation as _;

        #[apply(all_cred_cipher)]
        async fn can_get_newly_created_conversation_epoch(case: TestContext) {
            let [session] = case.sessions().await;
            let conversation = case.create_conversation([&session]).await;
            let epoch = conversation.guard().await.epoch().await;
            assert_eq!(epoch, 0);
        }

        #[apply(all_cred_cipher)]
        async fn can_get_conversation_epoch(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;
                let epoch = conversation.guard().await.epoch().await;
                assert_eq!(epoch, 1);
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        async fn conversation_not_found(case: TestContext) {
            use crate::LeafError;
            let [session] = case.sessions().await;
            let id = conversation_id();
            let err = session.transaction.conversation(&id).await.unwrap_err();
            assert!(matches!(
                err,
                TransactionError::Leaf(LeafError::ConversationNotFound(i)) if i == id
            ));
        }
    }

    mod invariants {
        use crate::{mls, prelude::MlsCiphersuite};

        use super::*;

        #[apply(all_cred_cipher)]
        async fn can_create_from_valid_configuration(mut case: TestContext) {
            let tmp_dir = case.tmp_dir().await;
            Box::pin(async move {
                let configuration = SessionConfig::builder()
                    .persistent(&tmp_dir)
                    .database_key(DatabaseKey::generate())
                    .client_id("alice".into())
                    .ciphersuites([case.ciphersuite()])
                    .build()
                    .validate()
                    .unwrap();

                let new_client_result = Session::try_new(configuration).await;
                assert!(new_client_result.is_ok())
            })
            .await
        }

        #[test]
        fn store_path_should_not_be_empty_nor_blank() {
            let config_err = SessionConfig::builder()
                .persistent(" ")
                .database_key(DatabaseKey::generate())
                .ciphersuites([MlsCiphersuite::default()])
                .build()
                .validate()
                .unwrap_err();

            assert!(matches!(config_err, mls::Error::MalformedIdentifier(msg) if msg.contains("path")));
        }

        #[async_std::test]
        async fn client_id_should_not_be_empty() {
            let mut case = TestContext::default();
            let tmp_dir = case.tmp_dir().await;
            Box::pin(async move {
                let config_err = SessionConfig::builder()
                    .persistent(&tmp_dir)
                    .database_key(DatabaseKey::generate())
                    .client_id("".into())
                    .ciphersuites([MlsCiphersuite::default()])
                    .build()
                    .validate()
                    .unwrap_err();

                assert!(matches!(config_err, mls::Error::MalformedIdentifier("client_id")));
            })
            .await
        }
    }

    #[apply(all_cred_cipher)]
    async fn create_conversation_should_fail_when_already_exists(case: TestContext) {
        use crate::LeafError;

        let [alice] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;
            let id = conversation.id().clone();

                // creating a conversation should first verify that the conversation does not already exist ; only then create it
                let repeat_create = alice
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await;
                assert!(matches!(repeat_create.unwrap_err(), TransactionError::Leaf(LeafError::ConversationAlreadyExists(i)) if i == id));
            })
        .await;
    }

    #[apply(all_cred_cipher)]
    async fn can_fetch_client_public_key(mut case: TestContext) {
        let tmp_dir = case.tmp_dir().await;
        Box::pin(async move {
            let configuration = SessionConfig::builder()
                .persistent(&tmp_dir)
                .database_key(DatabaseKey::generate())
                .client_id("potato".into())
                .ciphersuites([case.ciphersuite()])
                .build()
                .validate()
                .unwrap();

            let result = Session::try_new(configuration).await;
            println!("{result:?}");
            assert!(result.is_ok());
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn can_2_phase_init_central(mut case: TestContext) {
        let tmp_dir = case.tmp_dir().await;
        Box::pin(async move {
            let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());
            let configuration = SessionConfig::builder()
                .persistent(&tmp_dir)
                .database_key(DatabaseKey::generate())
                .ciphersuites([case.ciphersuite()])
                .build()
                .validate()
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
        .await
    }
}
