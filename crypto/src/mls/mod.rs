use mls_crypto_provider::MlsCryptoProvider;

use crate::{ClientId, MlsConversation, Session};

pub(crate) mod ciphersuite;
pub mod conversation;
pub mod credential;
mod error;
pub mod key_package;
pub(crate) mod proposal;
pub(crate) mod session;

pub use error::{Error, Result};
pub use session::{EpochObserver, HistoryObserver};

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub(crate) trait HasSessionAndCrypto: Send {
    async fn session(&self) -> Result<Session>;
    async fn crypto_provider(&self) -> Result<MlsCryptoProvider>;
}

#[cfg(test)]
mod tests {

    use crate::{
        CertificateBundle, ClientIdentifier, CoreCrypto, CredentialType,
        mls::Session,
        test_utils::{x509::X509TestChain, *},
        transaction_context::Error as TransactionError,
    };

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
        use super::*;

        #[apply(all_cred_cipher)]
        async fn can_create_from_valid_configuration(mut case: TestContext) {
            let db = case.create_persistent_db().await;
            Box::pin(async move {
                let new_client_result = Session::try_new(&db).await;
                assert!(new_client_result.is_ok())
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
        let db = case.create_persistent_db().await;
        Box::pin(async move {
            let result = Session::try_new(&db).await;
            println!("{result:?}");
            assert!(result.is_ok());
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn can_2_phase_init_central(mut case: TestContext) {
        let db = case.create_persistent_db().await;
        Box::pin(async move {
            use crate::{ClientId, Credential};

            let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

            // phase 1: init without initialized mls_client
            let client = Session::try_new(&db).await.unwrap();
            let cc = CoreCrypto::from(client);
            let context = cc.new_transaction().await.unwrap();
            x509_test_chain.register_with_central(&context).await;

            assert!(!context.session().await.unwrap().is_ready().await);
            // phase 2: init mls_client
            let client_id = ClientId::from("alice");
            let identifier = match case.credential_type {
                CredentialType::Basic => ClientIdentifier::Basic(client_id.clone()),
                CredentialType::X509 => {
                    CertificateBundle::rand_identifier(&client_id, &[x509_test_chain.find_local_intermediate_ca()])
                }
            };
            context
                .mls_init(identifier.clone(), &[case.ciphersuite()])
                .await
                .unwrap();

            let credential =
                Credential::from_identifier(&identifier, case.ciphersuite(), &cc.mls.crypto_provider).unwrap();
            let credential_ref = cc.add_credential(credential).await.unwrap();

            assert!(context.session().await.unwrap().is_ready().await);
            // expect mls_client to work
            assert!(context.generate_keypackage(&credential_ref, None).await.is_ok());
        })
        .await
    }
}
