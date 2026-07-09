pub(crate) mod cipher_suite;
pub mod conversation;
pub(crate) mod conversation_cache;
pub mod credential;
mod error;
mod external_sender;
pub mod key_package;
pub(crate) mod session;

pub use error::{Error, Result};
pub use external_sender::ExternalSender;
pub use session::{EpochObserver, HistoryObserver};

#[cfg(test)]
mod tests {
    use crate::{CoreCrypto, test_utils::*, transaction_context::Error as TransactionError};

    mod conversation_epoch {
        use super::*;

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

    #[apply(all_cred_cipher)]
    async fn create_conversation_should_fail_when_already_exists(case: TestContext) {
        use crate::LeafError;

        let [alice] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;
            let id = conversation.id().clone();
            let credentials = alice.find_credentials(Default::default()).await.expect("finding credentials");
            let credential = credentials.first().expect("first credential");

                // creating a conversation should first verify that the conversation does not already exist ; only then create it
                let repeat_create = alice
                    .transaction
                    .new_conversation(&id, credential, case.cfg.clone())
                    .await;
                assert!(matches!(repeat_create.unwrap_err(), TransactionError::Leaf(LeafError::ConversationAlreadyExists(i)) if i == id));
            })
        .await;
    }

    #[apply(all_cred_cipher)]
    async fn can_2_phase_init_central(mut case: TestContext) {
        let db = case.create_persistent_db().await;
        Box::pin(async move {
            use std::sync::Arc;

            use wire_e2e_identity::pki_env::PkiEnvironment;

            use crate::test_utils::DummyPkiEnvironmentHooks;

            let x509_test_chain = case.set_test_chain(&[], &[], None).await;

            // phase 1: init without initialized mls_client
            let cc = CoreCrypto::new(db.clone());
            let context = cc.new_transaction().await.unwrap();

            let hooks = Arc::new(DummyPkiEnvironmentHooks);
            let pki_env = PkiEnvironment::new(hooks, db).await.expect("creating pki environment");
            cc.set_pki_environment(Some(Arc::new(pki_env))).await;

            x509_test_chain.register_with_central(&context).await;

            // phase 2: init mls_client
            let credential = case.generate_credential().await;
            let session_id = credential.client_id().to_owned();
            context
                .mls_init(
                    session_id.clone(),
                    Arc::new(CoreCryptoTransportSuccessProvider::default()),
                )
                .await
                .unwrap();

            let credential_ref = context.add_credential(credential).await.unwrap();

            // expect mls_client to work
            assert!(context.generate_key_package(&credential_ref, None).await.is_ok());
        })
        .await
    }
}
