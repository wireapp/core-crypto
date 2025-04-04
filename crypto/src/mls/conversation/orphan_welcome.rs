//! This deals with DS inconsistencies. When a Welcome message is received, the client might have
//! already deleted its associated KeyPackage (and encryption key).
//! Feel free to remove this when this is no longer a problem !!!

#[cfg(test)]
mod tests {

    use openmls::prelude::KeyPackage;
    use openmls_traits::OpenMlsCryptoProvider;
    use wasm_bindgen_test::*;

    use super::super::error::Error;
    use crate::test_utils::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn orphan_welcome_should_generate_external_commit(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();

                alice_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();

                let bob = bob_central.rand_key_package(&case).await;
                let bob_kp_ref = KeyPackage::from(bob.clone())
                    .hash_ref(bob_central.context.mls_provider().await.unwrap().crypto())
                    .unwrap();

                // Alice invites Bob with a KeyPackage...
                alice_central
                    .context
                    .conversation(&id)
                    .await
                    .unwrap()
                    .add_members(vec![bob])
                    .await
                    .unwrap();

                // ...Bob deletes locally (with the associated private key) before processing the Welcome
                bob_central.context.delete_keypackages(&[bob_kp_ref]).await.unwrap();

                let welcome = alice_central.mls_transport.latest_welcome_message().await;

                // in that case a dedicated error is thrown for clients to identify this case
                // and rejoin with an external commit
                let process_welcome = bob_central
                    .context
                    .process_welcome_message(welcome.into(), case.custom_cfg())
                    .await;
                assert!(matches!(
                    process_welcome.unwrap_err(),
                    crate::transaction_context::Error::Recursive(crate::RecursiveError::MlsConversation { source, .. }) if matches!(*source, Error::OrphanWelcome)
                ));
            })
        })
        .await;
    }
}
