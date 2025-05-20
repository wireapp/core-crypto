//! cf <https://www.rfc-editor.org/rfc/rfc9420.html#name-leaf-node-validation>

#[cfg(test)]
mod tests {
    use openmls::prelude::Lifetime;
    use wasm_bindgen_test::*;

    use crate::{MlsErrorKind, test_utils::*};

    use openmls::prelude::{AddMembersError, KeyPackageVerifyError};

    wasm_bindgen_test_configure!(run_in_browser);

    mod stages {

        use super::*;

        /// The validity of a LeafNode needs to be verified at the following stages:
        /// When a LeafNode is downloaded in a KeyPackage, before it is used to add the client to the group
        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_validate_leaf_node_when_adding(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let expiration_time = 14;
                let start = web_time::Instant::now();
                let conversation = case.create_conversation([&alice]).await;
                let id = conversation.id().clone();

                // should fail when creating Add proposal
                let invalid_kp = bob.new_keypackage(&case, Lifetime::new(expiration_time)).await;

                // Give time to the KeyPackage to expire
                let expiration_time = core::time::Duration::from_secs(expiration_time);
                let elapsed = start.elapsed();
                if expiration_time > elapsed {
                    async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1)).await;
                }

                let proposal_creation = alice.transaction.new_add_proposal(&id, invalid_kp).await;
                let error = proposal_creation.unwrap_err();
                assert!(innermost_source_matches!(
                    error,
                    MlsErrorKind::ProposeAddMemberError(
                        openmls::prelude::ProposeAddMemberError::KeyPackageVerifyError(
                            KeyPackageVerifyError::InvalidLeafNode(_)
                        )
                    ),
                ));
                assert!(alice.pending_proposals(&id).await.is_empty());

                // should fail when creating Add commits
                let expiration_time = 14;
                let start = web_time::Instant::now();

                let invalid_kp = bob.new_keypackage(&case, Lifetime::new(expiration_time)).await;

                // Give time to the KeyPackage to expire
                let expiration_time = core::time::Duration::from_secs(expiration_time);
                let elapsed = start.elapsed();
                if expiration_time > elapsed {
                    async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1)).await;
                }

                let commit_creation = alice
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .add_members(vec![invalid_kp.into()])
                    .await;

                let error = commit_creation.unwrap_err();
                assert!(innermost_source_matches!(
                    error,
                    MlsErrorKind::MlsAddMembersError(AddMembersError::KeyPackageVerifyError(
                        KeyPackageVerifyError::InvalidLeafNode(_)
                    )),
                ));
                assert!(alice.pending_proposals(&id).await.is_empty());
                assert!(alice.pending_commit(&id).await.is_none());
            })
            .await
        }

        /// The validity of a LeafNode needs to be verified at the following stages:
        /// When a LeafNode is received by a group member in an Add, Update, or Commit message
        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_validate_leaf_node_when_receiving_expired_add_proposal(case: TestContext) {
            #[expect(unused_variables)]
            let [alice, bob, charlie] = case.sessions().await;
            // Skipping, see reason below
            return;
            #[expect(unreachable_code)]
            Box::pin(async move {
                let expiration_time = 14;
                let start = web_time::Instant::now();
                let conversation = case.create_conversation([&alice, &bob]).await;
                let id = conversation.id().clone();

                let invalid_kp = charlie.new_keypackage(&case, Lifetime::new(expiration_time)).await;

                let proposal = alice.transaction.new_add_proposal(&id, invalid_kp).await.unwrap();

                let proposal = proposal.proposal.to_bytes().unwrap();
                let elapsed = start.elapsed();
                // Give time to the certificate to expire
                let expiration_time = core::time::Duration::from_secs(expiration_time);
                if expiration_time > elapsed {
                    async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1)).await;
                }

                let decrypting = bob
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(proposal)
                    .await;

                // TODO: currently succeeds as we don't anymore validate KeyPackage lifetime upon reception: find another way to craft an invalid KeyPackage. Tracking issue number: WPB-9623
                decrypting.unwrap();
                /*assert!(matches!(
                    decrypting.unwrap_err(),
                    CryptoError::MlsError(MlsError::MlsMessageError(ProcessMessageError::ValidationError(
                        ValidationError::KeyPackageVerifyError(KeyPackageVerifyError::InvalidLeafNode(
                            LeafNodeValidationError::Lifetime(_)
                        ))
                    )))
                ));*/
            })
            .await
        }

        /// The validity of a LeafNode needs to be verified at the following stages:
        /// When a LeafNode is received by a group member in an Add, Update, or Commit message
        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_validate_leaf_node_when_receiving_add_commit(case: TestContext) {
            #[expect(unused_variables)]
            let [alice, bob, charlie] = case.sessions().await;
            // Skipping, see reason below
            return;
            #[expect(unreachable_code)]
            Box::pin(async move {
                let expiration_time = 14;
                let start = web_time::Instant::now();
                let conversation = case.create_conversation([&alice, &bob]).await;
                let id = conversation.id().clone();

                // should fail when receiving Add commit
                let invalid_kp = charlie.new_keypackage(&case, Lifetime::new(expiration_time)).await;

                alice
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .add_members(vec![invalid_kp.into()])
                    .await
                    .unwrap();
                let commit = alice.mls_transport().await.latest_commit().await;
                let commit = commit.to_bytes().unwrap();

                let elapsed = start.elapsed();
                // Give time to the certificate to expire
                let expiration_time = core::time::Duration::from_secs(expiration_time);
                if expiration_time > elapsed {
                    async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1)).await;
                }

                let decrypting = bob
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(commit)
                    .await;

                // TODO: currently succeeds as we don't anymore validate KeyPackage lifetime upon reception: find another way to craft an invalid KeyPackage. Tracking issue number: WPB-9623
                decrypting.unwrap();
                /*assert!(matches!(
                    decrypting.unwrap_err(),
                    CryptoError::MlsError(MlsError::MlsMessageError(ProcessMessageError::ValidationError(
                        ValidationError::KeyPackageVerifyError(KeyPackageVerifyError::InvalidLeafNode(_))
                    )))
                ));*/
            })
            .await
        }

        /// The validity of a LeafNode needs to be verified at the following stages:
        /// When a client validates a ratchet tree, e.g., when joining a group or after processing a Commit
        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_validate_leaf_node_when_receiving_welcome(case: TestContext) {
            #[expect(unused_variables)]
            let [alice, bob] = case.sessions().await;
            // Skipping, see reason below
            return;
            #[expect(unreachable_code)]
            Box::pin(async move {
                let expiration_time = 14;
                let start = web_time::Instant::now();
                let conversation = case.create_conversation([&alice]).await;
                let id = conversation.id().clone();

                let invalid_kp = bob.new_keypackage(&case, Lifetime::new(expiration_time)).await;
                alice
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .add_members(vec![invalid_kp.into()])
                    .await
                    .unwrap();

                let elapsed = start.elapsed();
                // Give time to the certificate to expire
                let expiration_time = core::time::Duration::from_secs(expiration_time);
                if expiration_time > elapsed {
                    async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1)).await;
                }

                let process_welcome = bob
                    .transaction
                    .process_welcome_message(
                        alice.mls_transport().await.latest_welcome_message().await.into(),
                        case.custom_cfg(),
                    )
                    .await;

                // TODO: currently succeeds as we don't anymore validate KeyPackage lifetime upon reception: find another way to craft an invalid KeyPackage. Tracking issue number: WPB-9623
                process_welcome.unwrap();
                /*assert!(matches!(
                    process_welcome.unwrap_err(),
                    CryptoError::MlsError(MlsError::MlsWelcomeError(WelcomeError::PublicGroupError(
                        CreationFromExternalError::TreeSyncError(
                            TreeSyncFromNodesError::LeafNodeValidationError(LeafNodeValidationError::Lifetime(
                                _
                            ))
                        )
                    )))
                ));*/
            })
            .await
        }
    }
}
