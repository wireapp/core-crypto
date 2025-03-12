//! This table summarizes when a MLS group can create a commit or proposal:
//!
//! | can create handshake ? | 0 pend. Commit | 1 pend. Commit |
//! |------------------------|----------------|----------------|
//! | 0 pend. Proposal       | ✅              | ❌              |
//! | 1+ pend. Proposal      | ✅              | ❌              |

use openmls::prelude::{LeafNode, MlsMessageOut};

use mls_crypto_provider::MlsCryptoProvider;

use super::{Error, Result};
use crate::{
    LeafError, RecursiveError,
    e2e_identity::init_certificates::NewCrlDistributionPoint,
    mls::{MlsConversation, credential::CredentialBundle},
    prelude::{Client, MlsError, MlsGroupInfoBundle},
};

impl MlsConversation {
    /// see [MlsCentral::update_keying_material]
    #[cfg_attr(test, crate::durable)]
    pub(crate) async fn update_keying_material(
        &mut self,
        client: &Client,
        backend: &MlsCryptoProvider,
        cb: Option<&CredentialBundle>,
        leaf_node: Option<LeafNode>,
    ) -> Result<MlsCommitBundle> {
        let cb = match cb {
            None => &self
                .find_most_recent_credential_bundle(client)
                .await
                .map_err(RecursiveError::mls_client("finding most recent credential bundle"))?,
            Some(cb) => cb,
        };
        let (commit, welcome, group_info) = self
            .group
            .explicit_self_update(backend, &cb.signature_key, leaf_node)
            .await
            .map_err(MlsError::wrap("group self update"))?;

        // We should always have ratchet tree extension turned on hence GroupInfo should always be present
        let group_info = group_info.ok_or(LeafError::MissingGroupInfo)?;
        let group_info = MlsGroupInfoBundle::try_new_full_plaintext(group_info)?;

        self.persist_group_when_changed(&backend.keystore(), false).await?;

        Ok(MlsCommitBundle {
            welcome,
            commit,
            group_info,
        })
    }

    /// see [MlsCentral::commit_pending_proposals]
    #[cfg_attr(test, crate::durable)]
    pub(crate) async fn commit_pending_proposals(
        &mut self,
        client: &Client,
        backend: &MlsCryptoProvider,
    ) -> Result<Option<MlsCommitBundle>> {
        if self.group.pending_proposals().count() == 0 {
            return Ok(None);
        }
        let signer = &self
            .find_most_recent_credential_bundle(client)
            .await
            .map_err(RecursiveError::mls_client("finding most recent credential bundle"))?
            .signature_key;

        let (commit, welcome, gi) = self
            .group
            .commit_to_pending_proposals(backend, signer)
            .await
            .map_err(MlsError::wrap("group commit to pending proposals"))?;
        let group_info = MlsGroupInfoBundle::try_new_full_plaintext(gi.unwrap())?;

        self.persist_group_when_changed(&backend.keystore(), false).await?;

        Ok(Some(MlsCommitBundle {
            welcome,
            commit,
            group_info,
        }))
    }
}

/// Returned when initializing a conversation through a commit.
/// Different from conversation created from a [`openmls::prelude::Welcome`] message or an external commit.
#[derive(Debug)]
pub struct MlsConversationCreationMessage {
    /// A welcome message for new members to join the group
    pub welcome: MlsMessageOut,
    /// Commit message adding members to the group
    pub commit: MlsMessageOut,
    /// `GroupInfo` if the commit is merged
    pub group_info: MlsGroupInfoBundle,
    /// New CRL distribution points that appeared by the introduction of a new credential
    pub crl_new_distribution_points: NewCrlDistributionPoint,
}

impl MlsConversationCreationMessage {
    /// Serializes both wrapped objects into TLS and return them as a tuple of byte arrays.
    /// 0 -> welcome
    /// 1 -> commit
    /// 2 -> group_info
    #[allow(clippy::type_complexity)]
    pub fn to_bytes(self) -> Result<(Vec<u8>, Vec<u8>, MlsGroupInfoBundle, NewCrlDistributionPoint)> {
        use openmls::prelude::TlsSerializeTrait as _;
        let welcome = self
            .welcome
            .tls_serialize_detached()
            .map_err(Error::tls_serialize("serialize welcome"))?;
        let msg = self
            .commit
            .tls_serialize_detached()
            .map_err(Error::tls_serialize("serialize commit"))?;
        Ok((welcome, msg, self.group_info, self.crl_new_distribution_points))
    }
}

/// Returned when a commit is created
#[derive(Debug, Clone)]
pub struct MlsCommitBundle {
    /// A welcome message if there are pending Add proposals
    pub welcome: Option<MlsMessageOut>,
    /// The commit message
    pub commit: MlsMessageOut,
    /// `GroupInfo` if the commit is merged
    pub group_info: MlsGroupInfoBundle,
}

impl MlsCommitBundle {
    /// Serializes both wrapped objects into TLS and return them as a tuple of byte arrays.
    /// 0 -> welcome
    /// 1 -> message
    /// 2 -> public group state
    #[allow(clippy::type_complexity)]
    pub fn to_bytes_triple(self) -> Result<(Option<Vec<u8>>, Vec<u8>, MlsGroupInfoBundle)> {
        use openmls::prelude::TlsSerializeTrait as _;
        let welcome = self
            .welcome
            .as_ref()
            .map(|w| {
                w.tls_serialize_detached()
                    .map_err(Error::tls_serialize("serialize welcome"))
            })
            .transpose()?;
        let commit = self
            .commit
            .tls_serialize_detached()
            .map_err(Error::tls_serialize("serialize commit"))?;
        Ok((welcome, commit, self.group_info))
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use openmls::prelude::SignaturePublicKey;
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

    use super::{Error, *};

    wasm_bindgen_test_configure!(run_in_browser);

    mod transport {
        use super::*;
        use std::sync::Arc;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn retry_should_work(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[alice_central, bob_central, charlie_central]| {
                    Box::pin(async move {
                        // Create conversation
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        // Add bob
                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                        // Bob produces a commit that Alice will receive only after she tried sending a commit
                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .update_key_material()
                            .await
                            .unwrap();
                        let bob_epoch = bob_central.get_conversation_unchecked(&id).await.group.epoch().as_u64();
                        assert_eq!(2, bob_epoch);
                        let alice_epoch = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .group
                            .epoch()
                            .as_u64();
                        assert_eq!(1, alice_epoch);
                        let intermediate_commit = bob_central.mls_transport.latest_commit().await;

                        // Next time a commit is sent, process the intermediate commit and return retry, success the second time
                        let retry_provider = Arc::new(
                            CoreCryptoTransportRetrySuccessProvider::default().with_intermediate_commits(
                                alice_central.clone(),
                                &[intermediate_commit],
                                &id,
                            ),
                        );

                        alice_central
                            .context
                            .set_transport_callbacks(Some(retry_provider.clone()))
                            .await
                            .unwrap();

                        // Send two commits and process them on bobs side
                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .update_key_material()
                            .await
                            .unwrap();
                        let commit = retry_provider.latest_commit().await;
                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(&commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // For this second commit, the retry provider will first return retry and
                        // then success, but now without an intermediate commit
                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .add_members(vec![charlie_central.rand_key_package(&case).await])
                            .await
                            .unwrap();
                        let commit = retry_provider.latest_commit().await;
                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(&commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // Retry should have been returned twice
                        assert_eq!(retry_provider.retry_count().await, 2);
                        // Success should have been returned twice
                        assert_eq!(retry_provider.success_count().await, 2);

                        // Group is still in valid state
                        assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());
                    })
                },
            )
            .await;
        }
    }

    mod add_members {
        use super::*;
        use std::sync::Arc;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn can_add_members_to_conversation(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();

                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    let bob = bob_central.rand_key_package(&case).await;
                    // First, abort commit transport
                    alice_central
                        .context
                        .set_transport_callbacks(Some(Arc::<CoreCryptoTransportAbortProvider>::default()))
                        .await
                        .unwrap();
                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .add_members(vec![bob.clone()])
                        .await
                        .unwrap_err();

                    // commit is not applied
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);

                    let success_provider = Arc::<CoreCryptoTransportSuccessProvider>::default();
                    alice_central
                        .context
                        .set_transport_callbacks(Some(success_provider.clone()))
                        .await
                        .unwrap();
                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .add_members(vec![bob])
                        .await
                        .unwrap();

                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.id, id);
                    assert_eq!(
                        alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .group
                            .group_id()
                            .as_slice(),
                        id
                    );
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);
                    let commit = success_provider.latest_commit_bundle().await;
                    bob_central
                        .context
                        .process_welcome_message(commit.welcome.unwrap().into(), case.custom_cfg())
                        .await
                        .unwrap();
                    assert_eq!(
                        alice_central.get_conversation_unchecked(&id).await.id(),
                        bob_central.get_conversation_unchecked(&id).await.id()
                    );
                    assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 2);
                    assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_return_valid_welcome(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let bob = bob_central.rand_key_package(&case).await;
                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .add_members(vec![bob])
                        .await
                        .unwrap();

                    let welcome = alice_central
                        .mls_transport
                        .latest_commit_bundle()
                        .await
                        .welcome
                        .unwrap();

                    bob_central
                        .context
                        .process_welcome_message(welcome.into(), case.custom_cfg())
                        .await
                        .unwrap();
                    assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_return_valid_group_info(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "guest"],
                move |[alice_central, bob_central, mut guest_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();

                        let bob = bob_central.rand_key_package(&case).await;
                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .add_members(vec![bob])
                            .await
                            .unwrap();
                        let commit_bundle = alice_central.mls_transport.latest_commit_bundle().await;
                        let group_info = commit_bundle.group_info.get_group_info();

                        assert!(
                            guest_central
                                .try_join_from_group_info(&case, &id, group_info, vec![&alice_central])
                                .await
                                .is_ok()
                        );
                    })
                },
            )
            .await
        }
    }

    mod remove_members {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn alice_can_remove_bob_from_conversation(case: TestCase) {
            use crate::mls;

            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();

                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .remove_members(&[bob_central.get_client_id().await])
                        .await
                        .unwrap();
                    let MlsCommitBundle { commit, welcome, .. } =
                        alice_central.mls_transport.latest_commit_bundle().await;
                    assert!(welcome.is_none());

                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);

                    bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(commit.to_bytes().unwrap())
                        .await
                        .unwrap();

                    // But has been removed from the conversation
                    assert!(matches!(
                       bob_central.context.conversation(&id).await.unwrap_err(),
                        mls::conversation::error::Error::Leaf(LeafError::ConversationNotFound(conv_id)) if conv_id == id
                    ));
                    assert!(alice_central.try_talk_to(&id, &bob_central).await.is_err());
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_return_valid_welcome(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "guest"],
                move |[alice_central, bob_central, mut guest_central]| {
                    Box::pin(async move {
                        let id = conversation_id();

                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                        let proposal = alice_central
                            .context
                            .new_add_proposal(&id, guest_central.get_one_key_package(&case).await)
                            .await
                            .unwrap();
                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(proposal.proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .remove_members(&[bob_central.get_client_id().await])
                            .await
                            .unwrap();

                        let welcome = alice_central.mls_transport.latest_welcome_message().await;

                        assert!(
                            guest_central
                                .try_join_from_welcome(&id, welcome.into(), case.custom_cfg(), vec![&alice_central])
                                .await
                                .is_ok()
                        );
                        // because Bob has been removed from the group
                        assert!(guest_central.try_talk_to(&id, &bob_central).await.is_err());
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_return_valid_group_info(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "guest"],
                move |[alice_central, bob_central, mut guest_central]| {
                    Box::pin(async move {
                        let id = conversation_id();

                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .remove_members(&[bob_central.get_client_id().await])
                            .await
                            .unwrap();

                        let commit_bundle = alice_central.mls_transport.latest_commit_bundle().await;

                        let group_info = commit_bundle.group_info.get_group_info();

                        assert!(
                            guest_central
                                .try_join_from_group_info(&case, &id, group_info, vec![&alice_central])
                                .await
                                .is_ok()
                        );
                        // because Bob has been removed from the group
                        assert!(guest_central.try_talk_to(&id, &bob_central).await.is_err());
                    })
                },
            )
            .await;
        }
    }

    mod update_keying_material {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_succeed(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    let init_count = alice_central.context.count_entities().await;

                    let bob_keys = bob_central
                        .get_conversation_unchecked(&id)
                        .await
                        .encryption_keys()
                        .collect::<Vec<Vec<u8>>>();
                    let alice_keys = alice_central
                        .get_conversation_unchecked(&id)
                        .await
                        .encryption_keys()
                        .collect::<Vec<Vec<u8>>>();
                    assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

                    let alice_key = alice_central
                        .encryption_key_of(&id, alice_central.get_client_id().await)
                        .await;

                    // proposing the key update for alice
                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();
                    let MlsCommitBundle { commit, welcome, .. } =
                        alice_central.mls_transport.latest_commit_bundle().await;
                    assert!(welcome.is_none());

                    assert!(
                        !alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .contains(&alice_key)
                    );

                    let alice_new_keys = alice_central
                        .get_conversation_unchecked(&id)
                        .await
                        .encryption_keys()
                        .collect::<Vec<_>>();
                    assert!(!alice_new_keys.contains(&alice_key));

                    // receiving the commit on bob's side (updating key from alice)
                    bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(&commit.to_bytes().unwrap())
                        .await
                        .unwrap();

                    let bob_new_keys = bob_central
                        .get_conversation_unchecked(&id)
                        .await
                        .encryption_keys()
                        .collect::<Vec<_>>();
                    assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

                    // ensuring both can encrypt messages
                    assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());

                    // make sure inline update commit + merge does not leak anything
                    // that's obvious since no new encryption keypair is created in this case
                    let final_count = alice_central.context.count_entities().await;
                    assert_eq!(init_count, final_count);
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_create_welcome_for_pending_add_proposals(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[alice_central, bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                        let bob_keys = bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .signature_keys()
                            .collect::<Vec<SignaturePublicKey>>();
                        let alice_keys = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .signature_keys()
                            .collect::<Vec<SignaturePublicKey>>();

                        // checking that the members on both sides are the same
                        assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

                        let alice_key = alice_central
                            .encryption_key_of(&id, alice_central.get_client_id().await)
                            .await;

                        // proposing adding charlie
                        let charlie_kp = charlie_central.get_one_key_package(&case).await;
                        let add_charlie_proposal =
                            alice_central.context.new_add_proposal(&id, charlie_kp).await.unwrap();

                        // receiving the proposal on Bob's side
                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(add_charlie_proposal.proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        assert!(
                            alice_central
                                .get_conversation_unchecked(&id)
                                .await
                                .encryption_keys()
                                .contains(&alice_key)
                        );

                        // performing an update on Alice's key. this should generate a welcome for Charlie
                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .update_key_material()
                            .await
                            .unwrap();
                        let MlsCommitBundle { commit, welcome, .. } =
                            alice_central.mls_transport.latest_commit_bundle().await;
                        assert!(welcome.is_some());
                        assert!(
                            !alice_central
                                .get_conversation_unchecked(&id)
                                .await
                                .encryption_keys()
                                .contains(&alice_key)
                        );

                        // create the group on charlie's side
                        charlie_central
                            .context
                            .process_welcome_message(welcome.unwrap().into(), case.custom_cfg())
                            .await
                            .unwrap();

                        assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 3);
                        assert_eq!(charlie_central.get_conversation_unchecked(&id).await.members().len(), 3);
                        // bob still didn't receive the message with the updated key and charlie's addition
                        assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 2);

                        let alice_new_keys = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .collect::<Vec<Vec<u8>>>();
                        assert!(!alice_new_keys.contains(&alice_key));

                        // receiving the key update and the charlie's addition to the group
                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(&commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 3);

                        let bob_new_keys = bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .collect::<Vec<Vec<u8>>>();
                        assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

                        // ensure all parties can encrypt messages
                        assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());
                        assert!(bob_central.try_talk_to(&id, &charlie_central).await.is_ok());
                        assert!(charlie_central.try_talk_to(&id, &alice_central).await.is_ok());
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_return_valid_welcome(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "guest"],
                move |[alice_central, bob_central, mut guest_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                        let proposal = alice_central
                            .context
                            .new_add_proposal(&id, guest_central.get_one_key_package(&case).await)
                            .await
                            .unwrap()
                            .proposal;
                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .update_key_material()
                            .await
                            .unwrap();
                        let MlsCommitBundle { commit, welcome, .. } =
                            alice_central.mls_transport.latest_commit_bundle().await;

                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        assert!(
                            guest_central
                                .try_join_from_welcome(
                                    &id,
                                    welcome.unwrap().into(),
                                    case.custom_cfg(),
                                    vec![&alice_central, &bob_central]
                                )
                                .await
                                .is_ok()
                        );
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_return_valid_group_info(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "guest"],
                move |[alice_central, bob_central, mut guest_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .update_key_material()
                            .await
                            .unwrap();
                        let group_info = alice_central.mls_transport.latest_group_info().await;
                        let group_info = group_info.get_group_info();

                        assert!(
                            guest_central
                                .try_join_from_group_info(&case, &id, group_info, vec![&alice_central])
                                .await
                                .is_ok()
                        );
                    })
                },
            )
            .await;
        }
    }

    mod commit_pending_proposals {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_create_a_commit_out_of_self_pending_proposals(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .context
                            .new_add_proposal(&id, bob_central.get_one_key_package(&case).await)
                            .await
                            .unwrap();
                        assert!(!alice_central.pending_proposals(&id).await.is_empty());
                        assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);
                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .commit_pending_proposals()
                            .await
                            .unwrap();
                        assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);

                        let welcome = alice_central.mls_transport.latest_commit_bundle().await.welcome;
                        bob_central
                            .context
                            .process_welcome_message(welcome.unwrap().into(), case.custom_cfg())
                            .await
                            .unwrap();
                        assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_create_a_commit_out_of_pending_proposals_by_ref(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[alice_central, mut bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();
                        let proposal = bob_central
                            .context
                            .new_add_proposal(&id, charlie_central.get_one_key_package(&case).await)
                            .await
                            .unwrap();
                        assert!(!bob_central.pending_proposals(&id).await.is_empty());
                        assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 2);
                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(proposal.proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .commit_pending_proposals()
                            .await
                            .unwrap();
                        let commit = alice_central.mls_transport.latest_commit_bundle().await.commit;
                        assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 3);

                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 3);
                        assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_return_valid_welcome(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central
                        .context
                        .new_add_proposal(&id, bob_central.get_one_key_package(&case).await)
                        .await
                        .unwrap();
                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .commit_pending_proposals()
                        .await
                        .unwrap();

                    let welcome = alice_central.mls_transport.latest_commit_bundle().await.welcome;

                    bob_central
                        .context
                        .process_welcome_message(welcome.unwrap().into(), case.custom_cfg())
                        .await
                        .unwrap();
                    assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_return_valid_group_info(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "guest"],
                move |[alice_central, bob_central, mut guest_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .context
                            .new_add_proposal(&id, bob_central.get_one_key_package(&case).await)
                            .await
                            .unwrap();
                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .commit_pending_proposals()
                            .await
                            .unwrap();
                        let commit_bundle = alice_central.mls_transport.latest_commit_bundle().await;
                        let group_info = commit_bundle.group_info.get_group_info();

                        assert!(
                            guest_central
                                .try_join_from_group_info(&case, &id, group_info, vec![&alice_central])
                                .await
                                .is_ok()
                        );
                    })
                },
            )
            .await;
        }
    }

    mod delivery_semantics {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_prevent_out_of_order_commits(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();
                    let commit1 = alice_central.mls_transport.latest_commit().await;
                    let commit1 = commit1.to_bytes().unwrap();
                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();
                    let commit2 = alice_central.mls_transport.latest_commit().await;
                    let commit2 = commit2.to_bytes().unwrap();

                    // fails when a commit is skipped
                    let out_of_order = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(&commit2)
                        .await;
                    assert!(matches!(out_of_order.unwrap_err(), Error::BufferedFutureMessage { .. }));

                    // works in the right order though
                    // NB: here 'commit2' has been buffered so it is also applied when we decrypt commit1
                    bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(&commit1)
                        .await
                        .unwrap();

                    // and then fails again when trying to decrypt a commit with an epoch in the past
                    let past_commit = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(&commit1)
                        .await;
                    assert!(matches!(past_commit.unwrap_err(), Error::StaleCommit));
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_prevent_replayed_encrypted_handshake_messages(case: TestCase) {
            if !case.is_pure_ciphertext() {
                return;
            }
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    let proposal1 = alice_central.context.new_update_proposal(&id).await.unwrap().proposal;
                    let proposal2 = proposal1.clone();
                    alice_central
                        .get_conversation_unchecked(&id)
                        .await
                        .group
                        .clear_pending_proposals();

                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();
                    let commit1 = alice_central.mls_transport.latest_commit().await;
                    let commit2 = commit1.clone();

                    // replayed encrypted proposal should fail
                    bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(proposal1.to_bytes().unwrap())
                        .await
                        .unwrap();
                    assert!(matches!(
                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(proposal2.to_bytes().unwrap())
                            .await
                            .unwrap_err(),
                        Error::DuplicateMessage
                    ));
                    bob_central
                        .get_conversation_unchecked(&id)
                        .await
                        .group
                        .clear_pending_proposals();

                    // replayed encrypted commit should fail
                    bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(commit1.to_bytes().unwrap())
                        .await
                        .unwrap();
                    assert!(matches!(
                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(commit2.to_bytes().unwrap())
                            .await
                            .unwrap_err(),
                        Error::StaleCommit
                    ));
                })
            })
            .await;
        }
    }
}
