//! cf <https://www.rfc-editor.org/rfc/rfc9420.html#name-leaf-node-validation>

#[cfg(test)]
pub mod tests {
    use openmls::prelude::Lifetime;
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod stages {
        use openmls::{
            prelude::{
                AddMembersError, CreationFromExternalError, KeyPackageVerifyError, LeafNodeValidationError,
                ProcessMessageError, ProposeAddMemberError, ValidationError, WelcomeError,
            },
            treesync::errors::TreeSyncFromNodesError,
        };

        use crate::{CryptoError, MlsError};

        use super::*;

        /// The validity of a LeafNode needs to be verified at the following stages:
        /// When a LeafNode is downloaded in a KeyPackage, before it is used to add the client to the group
        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_validate_leaf_node_when_adding(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, bob_central]| {
                    Box::pin(async move {
                        let expiration_time = 14;
                        let start = fluvio_wasm_timer::Instant::now();
                        let id = conversation_id();
                        alice_central
                            .mls_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();

                        // should fail when creating Add proposal
                        let invalid_kp = bob_central
                            .mls_central
                            .new_keypackage(&case, Lifetime::new(expiration_time))
                            .await;

                        // Give time to the KeyPackage to expire
                        let expiration_time = core::time::Duration::from_secs(expiration_time);
                        let elapsed = start.elapsed();
                        if expiration_time > elapsed {
                            async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1))
                                .await;
                        }

                        let proposal_creation = alice_central.mls_central.new_add_proposal(&id, invalid_kp).await;
                        assert!(matches!(
                            proposal_creation.unwrap_err(),
                            CryptoError::MlsError(MlsError::ProposeAddMemberError(
                                ProposeAddMemberError::KeyPackageVerifyError(KeyPackageVerifyError::InvalidLeafNode(_))
                            ))
                        ));
                        assert!(alice_central.mls_central.pending_proposals(&id).await.is_empty());

                        // should fail when creating Add commits
                        let expiration_time = 14;
                        let start = fluvio_wasm_timer::Instant::now();

                        let invalid_kp = bob_central
                            .mls_central
                            .new_keypackage(&case, Lifetime::new(expiration_time))
                            .await;

                        // Give time to the KeyPackage to expire
                        let expiration_time = core::time::Duration::from_secs(expiration_time);
                        let elapsed = start.elapsed();
                        if expiration_time > elapsed {
                            async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1))
                                .await;
                        }

                        let commit_creation = alice_central
                            .mls_central
                            .add_members_to_conversation(&id, vec![invalid_kp.into()])
                            .await;

                        assert!(matches!(
                            commit_creation.unwrap_err(),
                            CryptoError::MlsError(MlsError::MlsAddMembersError(
                                AddMembersError::KeyPackageVerifyError(KeyPackageVerifyError::InvalidLeafNode(_))
                            ))
                        ));
                        assert!(alice_central.mls_central.pending_proposals(&id).await.is_empty());
                        assert!(alice_central.mls_central.pending_commit(&id).await.is_none());
                    })
                },
            )
            .await
        }

        /// The validity of a LeafNode needs to be verified at the following stages:
        /// When a LeafNode is received by a group member in an Add, Update, or Commit message
        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_validate_leaf_node_when_receiving_expired_add_proposal(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, charlie_central]| {
                    Box::pin(async move {
                        let expiration_time = 14;
                        let start = fluvio_wasm_timer::Instant::now();
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

                        let invalid_kp = charlie_central
                            .mls_central
                            .new_keypackage(&case, Lifetime::new(expiration_time))
                            .await;

                        let proposal = alice_central
                            .mls_central
                            .new_add_proposal(&id, invalid_kp)
                            .await
                            .unwrap();
                        let proposal = proposal.proposal.to_bytes().unwrap();

                        let elapsed = start.elapsed();
                        // Give time to the certificate to expire
                        let expiration_time = core::time::Duration::from_secs(expiration_time);
                        if expiration_time > elapsed {
                            async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1))
                                .await;
                        }

                        let decrypting = bob_central.mls_central.decrypt_message(&id, proposal).await;
                        assert!(matches!(
                            decrypting.unwrap_err(),
                            CryptoError::MlsError(MlsError::MlsMessageError(ProcessMessageError::ValidationError(
                                ValidationError::KeyPackageVerifyError(KeyPackageVerifyError::InvalidLeafNode(
                                    LeafNodeValidationError::Lifetime(_)
                                ))
                            )))
                        ));
                    })
                },
            )
            .await
        }

        /// The validity of a LeafNode needs to be verified at the following stages:
        /// When a LeafNode is received by a group member in an Add, Update, or Commit message
        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_validate_leaf_node_when_receiving_add_commit(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, charlie_central]| {
                    Box::pin(async move {
                        let expiration_time = 14;
                        let start = fluvio_wasm_timer::Instant::now();
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

                        // should fail when receiving Add commit
                        let invalid_kp = charlie_central
                            .mls_central
                            .new_keypackage(&case, Lifetime::new(expiration_time))
                            .await;

                        let commit = alice_central
                            .mls_central
                            .add_members_to_conversation(&id, vec![invalid_kp.into()])
                            .await
                            .unwrap();
                        let commit = commit.commit.to_bytes().unwrap();

                        let elapsed = start.elapsed();
                        // Give time to the certificate to expire
                        let expiration_time = core::time::Duration::from_secs(expiration_time);
                        if expiration_time > elapsed {
                            async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1))
                                .await;
                        }

                        let decrypting = bob_central.mls_central.decrypt_message(&id, commit).await;
                        assert!(matches!(
                            decrypting.unwrap_err(),
                            CryptoError::MlsError(MlsError::MlsMessageError(ProcessMessageError::ValidationError(
                                ValidationError::KeyPackageVerifyError(KeyPackageVerifyError::InvalidLeafNode(_))
                            )))
                        ));
                    })
                },
            )
            .await
        }

        /// The validity of a LeafNode needs to be verified at the following stages:
        /// When a client validates a ratchet tree, e.g., when joining a group or after processing a Commit
        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_validate_leaf_node_when_receiving_welcome(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let expiration_time = 14;
                        let start = fluvio_wasm_timer::Instant::now();
                        let id = conversation_id();
                        alice_central
                            .mls_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();

                        let invalid_kp = bob_central
                            .mls_central
                            .new_keypackage(&case, Lifetime::new(expiration_time))
                            .await;
                        let commit = alice_central
                            .mls_central
                            .add_members_to_conversation(&id, vec![invalid_kp.into()])
                            .await
                            .unwrap();
                        alice_central.mls_central.commit_accepted(&id).await.unwrap();

                        let elapsed = start.elapsed();
                        // Give time to the certificate to expire
                        let expiration_time = core::time::Duration::from_secs(expiration_time);
                        if expiration_time > elapsed {
                            async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1))
                                .await;
                        }

                        let process_welcome_err = bob_central
                            .mls_central
                            .process_welcome_message(commit.welcome.into(), case.custom_cfg())
                            .await
                            .unwrap_err();

                        dbg!(&process_welcome_err);

                        assert!(matches!(
                            process_welcome_err,
                            CryptoError::MlsError(MlsError::MlsWelcomeError(WelcomeError::PublicGroupError(
                                CreationFromExternalError::TreeSyncError(
                                    TreeSyncFromNodesError::LeafNodeValidationError(LeafNodeValidationError::Lifetime(
                                        _
                                    ))
                                )
                            )))
                        ));
                    })
                },
            )
            .await
        }
    }
}
