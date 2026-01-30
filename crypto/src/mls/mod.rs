use crate::{ClientId, MlsConversation, Session, mls_provider::MlsCryptoProvider};

pub(crate) mod ciphersuite;
pub mod conversation;
pub mod credential;
mod error;
pub mod key_package;
pub(crate) mod proposal;
pub(crate) mod session;

use core_crypto_keystore::Database;
pub use error::{Error, Result};
pub use session::{EpochObserver, HistoryObserver};

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub(crate) trait HasSessionAndCrypto: Send {
    async fn session(&self) -> Result<Session<Database>>;
    async fn crypto_provider(&self) -> Result<MlsCryptoProvider>;
}

#[cfg(test)]
mod tests {

    use crate::{
        CertificateBundle, ClientIdentifier, CoreCrypto, CredentialType,
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

    #[apply(all_cred_cipher)]
    async fn create_conversation_should_fail_when_already_exists(case: TestContext) {
        use crate::LeafError;

        let [alice] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;
            let id = conversation.id().clone();
            let credentials =alice.session().await.find_credentials(Default::default()).await.expect("finding credentials");
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

            use crate::{ClientId, Credential, test_utils::DummyPkiEnvironmentHooks};

            let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

            // phase 1: init without initialized mls_client
            let cc = CoreCrypto::new(db.clone());
            let context = cc.new_transaction().await.unwrap();

            let hooks = Arc::new(DummyPkiEnvironmentHooks);
            let pki_env = PkiEnvironment::new(hooks, db).await.expect("creating pki environment");
            cc.set_pki_environment(Some(pki_env))
                .await
                .expect("setting pki environment");

            x509_test_chain.register_with_central(&context).await;

            // phase 2: init mls_client
            let session_id = ClientId::from("alice");
            let identifier = match case.credential_type {
                CredentialType::Basic => ClientIdentifier::Basic(session_id),
                CredentialType::X509 => {
                    CertificateBundle::rand_identifier(&session_id, &[x509_test_chain.find_local_intermediate_ca()])
                }
            };
            let session_id = identifier
                .get_id()
                .expect("get session_id from identifier")
                .into_owned();
            context
                .mls_init(
                    session_id.clone(),
                    Arc::new(CoreCryptoTransportSuccessProvider::default()),
                )
                .await
                .unwrap();

            let credential = Credential::from_identifier(&identifier, case.ciphersuite()).unwrap();
            let credential_ref = context.add_credential(credential).await.unwrap();

            // expect mls_client to work
            assert!(context.generate_keypackage(&credential_ref, None).await.is_ok());
        })
        .await
    }
}
