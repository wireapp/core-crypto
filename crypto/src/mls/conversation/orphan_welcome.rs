//! This deals with DS inconsistencies. When a Welcome message is received, the client might have
//! already deleted its associated KeyPackage (and encryption key).
//! Feel free to remove this when this is no longer a problem !!!

#[cfg(test)]
mod tests {

    use openmls::prelude::KeyPackage;
    use openmls_traits::OpenMlsCryptoProvider;

    use super::super::error::Error;
    use crate::test_utils::*;

    #[apply(all_cred_cipher)]
    pub async fn orphan_welcome_should_generate_external_commit(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;

                let bob_kp = bob.rand_key_package(&case).await;
                let bob_kp_ref = KeyPackage::from(bob_kp.clone())
                    .hash_ref(bob.transaction.mls_provider().await.unwrap().crypto())
                    .unwrap();

                // Alice invites Bob with a KeyPackage...
                conversation.guard().await
                    .add_members(vec![bob_kp])
                    .await
                    .unwrap();

                // ...Bob deletes locally (with the associated private key) before processing the Welcome
                bob.transaction.delete_keypackages([bob_kp_ref]).await.unwrap();

                let welcome = alice.mls_transport().await.latest_welcome_message().await;

                // in that case a dedicated error is thrown for clients to identify this case
                // and rejoin with an external commit
                let process_welcome = bob
                    .transaction
                    .process_welcome_message(welcome.into(), case.custom_cfg())
                    .await;
                assert!(matches!(
                    process_welcome.unwrap_err(),
                    crate::transaction_context::Error::Recursive(crate::RecursiveError::MlsConversation { source, .. }) if matches!(*source, Error::OrphanWelcome)
                ));
            })
        .await;
    }
}
