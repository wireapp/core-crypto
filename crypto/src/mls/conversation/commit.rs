//! This table summarizes when a MLS group can create a commit or proposal:
//!
//! | can create handshake ? | 0 pend. Commit | 1 pend. Commit |
//! |------------------------|----------------|----------------|
//! | 0 pend. Proposal       | ✅              | ❌              |
//! | 1+ pend. Proposal      | ✅              | ❌              |

use std::ops::Deref;

use openmls::prelude::{KeyPackageIn, LeafNode, LeafNodeIndex, MlsMessageOut};

use mls_crypto_provider::MlsCryptoProvider;

use crate::{
    e2e_identity::init_certificates::NewCrlDistributionPoint,
    mls::credential::{
        crl::{extract_crl_uris_from_credentials, get_new_crl_distribution_points},
        CredentialBundle,
    },
    prelude::{Client, ClientId, ConversationId, CryptoError, CryptoResult, MlsCentral, MlsError, MlsGroupInfoBundle},
};
use tracing::Instrument;

use super::MlsConversation;

impl MlsCentral {
    /// Adds new members to the group/conversation
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    /// * `members` - members to be added to the group
    ///
    /// # Return type
    /// An optional struct containing a welcome and a message will be returned on successful call.
    /// The value will be `None` only if the group can't be found locally (no error will be returned
    /// in this case).
    ///
    /// # Errors
    /// If the authorisation callback is set, an error can be caused when the authorization fails.
    /// Other errors are KeyStore and OpenMls errors:
    #[cfg_attr(test, crate::idempotent)]
    #[cfg_attr(not(test), tracing::instrument(err, skip(self, key_packages), fields(id = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, id))))]
    pub async fn add_members_to_conversation(
        &self,
        id: &ConversationId,
        key_packages: Vec<KeyPackageIn>,
    ) -> CryptoResult<MlsConversationCreationMessage> {
        let client = self.mls_client().await?;
        if let Some(callbacks) = self.callbacks.read().await.as_ref() {
            let client_id = client.id().clone();
            if !callbacks.authorize(id.clone(), client_id).await {
                return Err(CryptoError::Unauthorized);
            }
        }
        self.get_conversation(id)
            .await?
            .write()
            .await
            .add_members(client.deref(), key_packages, &self.mls_backend)
            .await
    }

    /// Removes clients from the group/conversation.
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    /// * `clients` - list of client ids to be removed from the group
    ///
    /// # Return type
    /// An struct containing a welcome(optional, will be present only if there's pending add
    /// proposals in the store), a message with the commit to fan out to other clients and
    /// the group info will be returned on successful call.
    ///
    /// # Errors
    /// If the authorisation callback is set, an error can be caused when the authorization fails. Other errors are KeyStore and OpenMls errors.
    #[cfg_attr(test, crate::idempotent)]
    #[cfg_attr(not(test), tracing::instrument(err, skip(self), fields(id = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, id))))]
    pub async fn remove_members_from_conversation(
        &self,
        id: &ConversationId,
        clients: &[ClientId],
    ) -> CryptoResult<MlsCommitBundle> {
        let client = self.mls_client().await?;
        if let Some(callbacks) = self.callbacks.read().await.as_ref() {
            let client_id = client.id().clone();
            if !callbacks.authorize(id.clone(), client_id).await {
                return Err(CryptoError::Unauthorized);
            }
        }
        self.get_conversation(id)
            .await?
            .write()
            .await
            .remove_members(client.deref(), clients, &self.mls_backend)
            .await
    }

    /// Self updates the KeyPackage and automatically commits. Pending proposals will be commited
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    ///
    /// # Return type
    /// An struct containing a welcome(optional, will be present only if there's pending add
    /// proposals in the store), a message with the commit to fan out to other clients and
    /// the group info will be returned on successful call.
    ///
    /// # Errors
    /// If the conversation can't be found, an error will be returned. Other errors are originating
    /// from OpenMls and the KeyStore
    #[cfg_attr(test, crate::idempotent)]
    #[cfg_attr(not(test), tracing::instrument(err, skip(self), fields(id = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, id))))]
    pub async fn update_keying_material(&self, id: &ConversationId) -> CryptoResult<MlsCommitBundle> {
        self.get_conversation(id)
            .await?
            .write()
            .await
            .update_keying_material(self.mls_client().await?.deref(), &self.mls_backend, None, None)
            .await
    }

    /// Commits all pending proposals of the group
    ///
    /// # Arguments
    /// * `backend` - the KeyStore to persist group changes
    ///
    /// # Return type
    /// A tuple containing the commit message and a possible welcome (in the case `Add` proposals were pending within the internal MLS Group)
    ///
    /// # Errors
    /// Errors can be originating from the KeyStore and OpenMls
    #[cfg_attr(test, crate::idempotent)]
    #[cfg_attr(not(test), tracing::instrument(err, skip(self), fields(id = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, id))))]
    pub async fn commit_pending_proposals(&self, id: &ConversationId) -> CryptoResult<Option<MlsCommitBundle>> {
        self.get_conversation(id)
            .await?
            .write()
            .await
            .commit_pending_proposals(self.mls_client().await?.deref(), &self.mls_backend)
            .await
    }
}

/// Creating commit
impl MlsConversation {
    /// see [MlsCentral::add_members_to_conversation]
    /// Note: this is not exposed publicly because authorization isn't handled at this level
    #[cfg_attr(test, crate::durable)]
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub(crate) async fn add_members(
        &mut self,
        client: &Client,
        key_packages: Vec<KeyPackageIn>,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsConversationCreationMessage> {
        let signer = &self
            .find_most_recent_credential_bundle(client)?
            .ok_or(CryptoError::IdentityInitializationError)?
            .signature_key;

        // No need to also check pending proposals since they should already have been scanned while decrypting the proposal message
        let crl_new_distribution_points = get_new_crl_distribution_points(
            backend,
            extract_crl_uris_from_credentials(key_packages.iter().filter_map(|kp| {
                let mls_credential = kp.credential().mls_credential();
                if matches!(mls_credential, openmls::prelude::MlsCredentialType::X509(_)) {
                    Some(mls_credential)
                } else {
                    None
                }
            }))?,
        )
        .await?;

        let (commit, welcome, gi) = self
            .group
            .add_members(backend, signer, key_packages)
            .in_current_span()
            .await
            .map_err(MlsError::from)?;

        // SAFETY: This should be safe as adding members always generates a new commit
        let gi = gi.ok_or(CryptoError::ImplementationError)?;
        let group_info = MlsGroupInfoBundle::try_new_full_plaintext(gi)?;

        self.persist_group_when_changed(backend, false).await?;

        Ok(MlsConversationCreationMessage {
            welcome,
            commit,
            group_info,
            crl_new_distribution_points,
        })
    }

    /// see [MlsCentral::remove_members_from_conversation]
    /// Note: this is not exposed publicly because authorization isn't handled at this level
    #[cfg_attr(test, crate::durable)]
    #[cfg_attr(not(test), tracing::instrument(err, skip(self, client, backend)))]
    pub(crate) async fn remove_members(
        &mut self,
        client: &Client,
        clients: &[ClientId],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsCommitBundle> {
        let member_kps = self
            .group
            .members()
            .filter(|kp| {
                clients
                    .iter()
                    .any(move |client_id| client_id.as_slice() == kp.credential.identity())
            })
            .try_fold(vec![], |mut acc, kp| -> CryptoResult<Vec<LeafNodeIndex>> {
                acc.push(kp.index);
                Ok(acc)
            })?;

        let signer = &self
            .find_most_recent_credential_bundle(client)?
            .ok_or(CryptoError::IdentityInitializationError)?
            .signature_key;

        let (commit, welcome, gi) = self
            .group
            .remove_members(backend, signer, &member_kps)
            .in_current_span()
            .await
            .map_err(MlsError::from)?;

        // SAFETY: This should be safe as removing members always generates a new commit
        let gi = gi.ok_or(CryptoError::ImplementationError)?;
        let group_info = MlsGroupInfoBundle::try_new_full_plaintext(gi)?;

        self.persist_group_when_changed(backend, false).await?;

        Ok(MlsCommitBundle {
            commit,
            welcome,
            group_info,
        })
    }

    /// see [MlsCentral::update_keying_material]
    #[cfg_attr(test, crate::durable)]
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub(crate) async fn update_keying_material(
        &mut self,
        client: &Client,
        backend: &MlsCryptoProvider,
        cb: Option<&CredentialBundle>,
        leaf_node: Option<LeafNode>,
    ) -> CryptoResult<MlsCommitBundle> {
        let cb = cb
            .or_else(|| self.find_most_recent_credential_bundle(client).ok().flatten())
            .ok_or(CryptoError::IdentityInitializationError)?;
        let (commit, welcome, group_info) = self
            .group
            .explicit_self_update(backend, &cb.signature_key, leaf_node)
            .in_current_span()
            .await
            .map_err(MlsError::from)?;

        // We should always have ratchet tree extension turned on hence GroupInfo should always be present
        let group_info = group_info.ok_or(CryptoError::ImplementationError)?;
        let group_info = MlsGroupInfoBundle::try_new_full_plaintext(group_info)?;

        self.persist_group_when_changed(backend, false).await?;

        Ok(MlsCommitBundle {
            welcome,
            commit,
            group_info,
        })
    }

    /// see [MlsCentral::commit_pending_proposals]
    #[cfg_attr(test, crate::durable)]
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub(crate) async fn commit_pending_proposals(
        &mut self,
        client: &Client,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Option<MlsCommitBundle>> {
        if self.group.pending_proposals().count() > 0 {
            let signer = &self
                .find_most_recent_credential_bundle(client)?
                .ok_or(CryptoError::IdentityInitializationError)?
                .signature_key;

            let (commit, welcome, gi) = self
                .group
                .commit_to_pending_proposals(backend, signer)
                .in_current_span()
                .await
                .map_err(MlsError::from)?;
            let group_info = MlsGroupInfoBundle::try_new_full_plaintext(gi.unwrap())?;

            self.persist_group_when_changed(backend, false).await?;

            Ok(Some(MlsCommitBundle {
                welcome,
                commit,
                group_info,
            }))
        } else {
            Ok(None)
        }
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
    pub fn to_bytes(self) -> CryptoResult<(Vec<u8>, Vec<u8>, MlsGroupInfoBundle, NewCrlDistributionPoint)> {
        use openmls::prelude::TlsSerializeTrait as _;
        let welcome = self.welcome.tls_serialize_detached().map_err(MlsError::from)?;
        let msg = self.commit.tls_serialize_detached().map_err(MlsError::from)?;
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
    pub fn to_bytes_triple(self) -> CryptoResult<(Option<Vec<u8>>, Vec<u8>, MlsGroupInfoBundle)> {
        use openmls::prelude::TlsSerializeTrait as _;
        let welcome = self
            .welcome
            .as_ref()
            .map(|w| w.tls_serialize_detached().map_err(MlsError::from))
            .transpose()?;
        let commit = self.commit.tls_serialize_detached().map_err(MlsError::from)?;
        Ok((welcome, commit, self.group_info))
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use openmls::prelude::SignaturePublicKey;
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod add_members {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn can_add_members_to_conversation(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();

                        alice_central
                            .mls_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        let bob = bob_central.mls_central.rand_key_package(&case).await;
                        let MlsConversationCreationMessage { welcome, .. } = alice_central
                            .mls_central
                            .add_members_to_conversation(&id, vec![bob])
                            .await
                            .unwrap();

                        // before merging, commit is not applied
                        assert_eq!(
                            alice_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            1
                        );
                        alice_central.mls_central.commit_accepted(&id).await.unwrap();

                        assert_eq!(alice_central.mls_central.get_conversation_unchecked(&id).await.id, id);
                        assert_eq!(
                            alice_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .group
                                .group_id()
                                .as_slice(),
                            id
                        );
                        assert_eq!(
                            alice_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            2
                        );

                        bob_central
                            .mls_central
                            .process_welcome_message(welcome.into(), case.custom_cfg())
                            .await
                            .unwrap();
                        assert_eq!(
                            alice_central.mls_central.get_conversation_unchecked(&id).await.id(),
                            bob_central.mls_central.get_conversation_unchecked(&id).await.id()
                        );
                        assert_eq!(
                            bob_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            2
                        );
                        assert!(alice_central
                            .mls_central
                            .try_talk_to(&id, &mut bob_central.mls_central)
                            .await
                            .is_ok());
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_return_valid_welcome(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .mls_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();

                        let bob = bob_central.mls_central.rand_key_package(&case).await;
                        let welcome = alice_central
                            .mls_central
                            .add_members_to_conversation(&id, vec![bob])
                            .await
                            .unwrap()
                            .welcome;
                        alice_central.mls_central.commit_accepted(&id).await.unwrap();

                        bob_central
                            .mls_central
                            .process_welcome_message(welcome.into(), case.custom_cfg())
                            .await
                            .unwrap();
                        assert!(alice_central
                            .mls_central
                            .try_talk_to(&id, &mut bob_central.mls_central)
                            .await
                            .is_ok());
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_return_valid_group_info(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "guest"],
                move |[mut alice_central, bob_central, mut guest_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .mls_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();

                        let bob = bob_central.mls_central.rand_key_package(&case).await;
                        let commit_bundle = alice_central
                            .mls_central
                            .add_members_to_conversation(&id, vec![bob])
                            .await
                            .unwrap();
                        let group_info = commit_bundle.group_info.get_group_info();
                        alice_central.mls_central.commit_accepted(&id).await.unwrap();

                        assert!(guest_central
                            .mls_central
                            .try_join_from_group_info(&case, &id, group_info, vec![&mut alice_central.mls_central])
                            .await
                            .is_ok());
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
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
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

                        let MlsCommitBundle { commit, welcome, .. } = alice_central
                            .mls_central
                            .remove_members_from_conversation(&id, &[bob_central.mls_central.get_client_id()])
                            .await
                            .unwrap();
                        assert!(welcome.is_none());

                        // before merging, commit is not applied
                        assert_eq!(
                            alice_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            2
                        );
                        alice_central.mls_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(
                            alice_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            1
                        );

                        bob_central
                            .mls_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // But has been removed from the conversation
                        assert!(matches!(
                           bob_central.mls_central.get_conversation(&id).await.unwrap_err(),
                            CryptoError::ConversationNotFound(conv_id) if conv_id == id
                        ));
                        assert!(alice_central
                            .mls_central
                            .try_talk_to(&id, &mut bob_central.mls_central)
                            .await
                            .is_err());
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
                move |[mut alice_central, mut bob_central, mut guest_central]| {
                    Box::pin(async move {
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

                        let proposal = alice_central
                            .mls_central
                            .new_add_proposal(&id, guest_central.mls_central.get_one_key_package(&case).await)
                            .await
                            .unwrap();
                        bob_central
                            .mls_central
                            .decrypt_message(&id, proposal.proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let welcome = alice_central
                            .mls_central
                            .remove_members_from_conversation(&id, &[bob_central.mls_central.get_client_id()])
                            .await
                            .unwrap()
                            .welcome;
                        alice_central.mls_central.commit_accepted(&id).await.unwrap();

                        assert!(guest_central
                            .mls_central
                            .try_join_from_welcome(
                                &id,
                                welcome.unwrap().into(),
                                case.custom_cfg(),
                                vec![&mut alice_central.mls_central]
                            )
                            .await
                            .is_ok());
                        // because Bob has been removed from the group
                        assert!(guest_central
                            .mls_central
                            .try_talk_to(&id, &mut bob_central.mls_central)
                            .await
                            .is_err());
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
                move |[mut alice_central, mut bob_central, mut guest_central]| {
                    Box::pin(async move {
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

                        let commit_bundle = alice_central
                            .mls_central
                            .remove_members_from_conversation(&id, &[bob_central.mls_central.get_client_id()])
                            .await
                            .unwrap();

                        alice_central.mls_central.commit_accepted(&id).await.unwrap();
                        let group_info = commit_bundle.group_info.get_group_info();

                        assert!(guest_central
                            .mls_central
                            .try_join_from_group_info(&case, &id, group_info, vec![&mut alice_central.mls_central])
                            .await
                            .is_ok());
                        // because Bob has been removed from the group
                        assert!(guest_central
                            .mls_central
                            .try_talk_to(&id, &mut bob_central.mls_central)
                            .await
                            .is_err());
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
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
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

                        let init_count = alice_central.mls_central.count_entities().await;

                        let bob_keys = bob_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .collect::<Vec<Vec<u8>>>();
                        let alice_keys = alice_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .collect::<Vec<Vec<u8>>>();
                        assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

                        let alice_key = alice_central
                            .mls_central
                            .encryption_key_of(&id, alice_central.mls_central.get_client_id())
                            .await;

                        // proposing the key update for alice
                        let MlsCommitBundle { commit, welcome, .. } =
                            alice_central.mls_central.update_keying_material(&id).await.unwrap();
                        assert!(welcome.is_none());

                        // before merging, commit is not applied
                        assert!(alice_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .contains(&alice_key));

                        alice_central.mls_central.commit_accepted(&id).await.unwrap();

                        assert!(!alice_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .contains(&alice_key));

                        let alice_new_keys = alice_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .collect::<Vec<_>>();
                        assert!(!alice_new_keys.contains(&alice_key));

                        // receiving the commit on bob's side (updating key from alice)
                        bob_central
                            .mls_central
                            .decrypt_message(&id, &commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let bob_new_keys = bob_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .collect::<Vec<_>>();
                        assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

                        // ensuring both can encrypt messages
                        assert!(alice_central
                            .mls_central
                            .try_talk_to(&id, &mut bob_central.mls_central)
                            .await
                            .is_ok());

                        // make sure inline update commit + merge does not leak anything
                        // that's obvious since no new encryption keypair is created in this case
                        let final_count = alice_central.mls_central.count_entities().await;
                        assert_eq!(init_count, final_count);
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_create_welcome_for_pending_add_proposals(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
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

                        let bob_keys = bob_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .signature_keys()
                            .collect::<Vec<SignaturePublicKey>>();
                        let alice_keys = alice_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .signature_keys()
                            .collect::<Vec<SignaturePublicKey>>();

                        // checking that the members on both sides are the same
                        assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

                        let alice_key = alice_central
                            .mls_central
                            .encryption_key_of(&id, alice_central.mls_central.get_client_id())
                            .await;

                        // proposing adding charlie
                        let charlie_kp = charlie_central.mls_central.get_one_key_package(&case).await;
                        let add_charlie_proposal = alice_central
                            .mls_central
                            .new_add_proposal(&id, charlie_kp)
                            .await
                            .unwrap();

                        // receiving the proposal on Bob's side
                        bob_central
                            .mls_central
                            .decrypt_message(&id, add_charlie_proposal.proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // performing an update on Alice's key. this should generate a welcome for Charlie
                        let MlsCommitBundle { commit, welcome, .. } =
                            alice_central.mls_central.update_keying_material(&id).await.unwrap();
                        assert!(welcome.is_some());
                        assert!(alice_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .contains(&alice_key));
                        alice_central.mls_central.commit_accepted(&id).await.unwrap();
                        assert!(!alice_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .contains(&alice_key));

                        // create the group on charlie's side
                        charlie_central
                            .mls_central
                            .process_welcome_message(welcome.unwrap().into(), case.custom_cfg())
                            .await
                            .unwrap();

                        assert_eq!(
                            alice_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            3
                        );
                        assert_eq!(
                            charlie_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            3
                        );
                        // bob still didn't receive the message with the updated key and charlie's addition
                        assert_eq!(
                            bob_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            2
                        );

                        let alice_new_keys = alice_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .collect::<Vec<Vec<u8>>>();
                        assert!(!alice_new_keys.contains(&alice_key));

                        // receiving the key update and the charlie's addition to the group
                        bob_central
                            .mls_central
                            .decrypt_message(&id, &commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(
                            bob_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            3
                        );

                        let bob_new_keys = bob_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .collect::<Vec<Vec<u8>>>();
                        assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

                        // ensure all parties can encrypt messages
                        assert!(alice_central
                            .mls_central
                            .try_talk_to(&id, &mut bob_central.mls_central)
                            .await
                            .is_ok());
                        assert!(bob_central
                            .mls_central
                            .try_talk_to(&id, &mut charlie_central.mls_central)
                            .await
                            .is_ok());
                        assert!(charlie_central
                            .mls_central
                            .try_talk_to(&id, &mut alice_central.mls_central)
                            .await
                            .is_ok());
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
                move |[mut alice_central, mut bob_central, mut guest_central]| {
                    Box::pin(async move {
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

                        let proposal = alice_central
                            .mls_central
                            .new_add_proposal(&id, guest_central.mls_central.get_one_key_package(&case).await)
                            .await
                            .unwrap()
                            .proposal;
                        bob_central
                            .mls_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let MlsCommitBundle { commit, welcome, .. } =
                            alice_central.mls_central.update_keying_material(&id).await.unwrap();
                        alice_central.mls_central.commit_accepted(&id).await.unwrap();

                        bob_central
                            .mls_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        assert!(guest_central
                            .mls_central
                            .try_join_from_welcome(
                                &id,
                                welcome.unwrap().into(),
                                case.custom_cfg(),
                                vec![&mut alice_central.mls_central, &mut bob_central.mls_central]
                            )
                            .await
                            .is_ok());
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
                move |[mut alice_central, mut bob_central, mut guest_central]| {
                    Box::pin(async move {
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

                        let commit_bundle = alice_central.mls_central.update_keying_material(&id).await.unwrap();
                        let group_info = commit_bundle.group_info.get_group_info();
                        alice_central.mls_central.commit_accepted(&id).await.unwrap();

                        assert!(guest_central
                            .mls_central
                            .try_join_from_group_info(&case, &id, group_info, vec![&mut alice_central.mls_central])
                            .await
                            .is_ok());
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
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .mls_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .mls_central
                            .new_add_proposal(&id, bob_central.mls_central.get_one_key_package(&case).await)
                            .await
                            .unwrap();
                        assert!(!alice_central.mls_central.pending_proposals(&id).await.is_empty());
                        assert_eq!(
                            alice_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            1
                        );
                        let MlsCommitBundle { welcome, .. } = alice_central
                            .mls_central
                            .commit_pending_proposals(&id)
                            .await
                            .unwrap()
                            .unwrap();
                        alice_central.mls_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(
                            alice_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            2
                        );

                        bob_central
                            .mls_central
                            .process_welcome_message(welcome.unwrap().into(), case.custom_cfg())
                            .await
                            .unwrap();
                        assert!(alice_central
                            .mls_central
                            .try_talk_to(&id, &mut bob_central.mls_central)
                            .await
                            .is_ok());
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_return_none_when_there_are_no_pending_proposals(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .mls_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    assert!(alice_central.mls_central.pending_proposals(&id).await.is_empty());
                    assert!(alice_central
                        .mls_central
                        .commit_pending_proposals(&id)
                        .await
                        .unwrap()
                        .is_none());
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_create_a_commit_out_of_pending_proposals_by_ref(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, charlie_central]| {
                    Box::pin(async move {
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
                        let proposal = bob_central
                            .mls_central
                            .new_add_proposal(&id, charlie_central.mls_central.get_one_key_package(&case).await)
                            .await
                            .unwrap();
                        assert!(!bob_central.mls_central.pending_proposals(&id).await.is_empty());
                        assert_eq!(
                            bob_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            2
                        );
                        alice_central
                            .mls_central
                            .decrypt_message(&id, proposal.proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let MlsCommitBundle { commit, .. } = alice_central
                            .mls_central
                            .commit_pending_proposals(&id)
                            .await
                            .unwrap()
                            .unwrap();
                        alice_central.mls_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(
                            alice_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            3
                        );

                        bob_central
                            .mls_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(
                            bob_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            3
                        );
                        assert!(alice_central
                            .mls_central
                            .try_talk_to(&id, &mut bob_central.mls_central)
                            .await
                            .is_ok());
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
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .mls_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .mls_central
                            .new_add_proposal(&id, bob_central.mls_central.get_one_key_package(&case).await)
                            .await
                            .unwrap();
                        let MlsCommitBundle { welcome, .. } = alice_central
                            .mls_central
                            .commit_pending_proposals(&id)
                            .await
                            .unwrap()
                            .unwrap();
                        alice_central.mls_central.commit_accepted(&id).await.unwrap();

                        bob_central
                            .mls_central
                            .process_welcome_message(welcome.unwrap().into(), case.custom_cfg())
                            .await
                            .unwrap();
                        assert!(alice_central
                            .mls_central
                            .try_talk_to(&id, &mut bob_central.mls_central)
                            .await
                            .is_ok());
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
                move |[mut alice_central, bob_central, mut guest_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .mls_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .mls_central
                            .new_add_proposal(&id, bob_central.mls_central.get_one_key_package(&case).await)
                            .await
                            .unwrap();
                        let commit_bundle = alice_central
                            .mls_central
                            .commit_pending_proposals(&id)
                            .await
                            .unwrap()
                            .unwrap();
                        let group_info = commit_bundle.group_info.get_group_info();
                        alice_central.mls_central.commit_accepted(&id).await.unwrap();

                        assert!(guest_central
                            .mls_central
                            .try_join_from_group_info(&case, &id, group_info, vec![&mut alice_central.mls_central])
                            .await
                            .is_ok());
                    })
                },
            )
            .await;
        }
    }

    mod delivery_semantics {
        use crate::prelude::MlsWirePolicy;

        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_prevent_out_of_order_commits(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
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

                        let commit1 = alice_central
                            .mls_central
                            .update_keying_material(&id)
                            .await
                            .unwrap()
                            .commit;
                        let commit1 = commit1.to_bytes().unwrap();
                        alice_central.mls_central.commit_accepted(&id).await.unwrap();
                        let commit2 = alice_central
                            .mls_central
                            .update_keying_material(&id)
                            .await
                            .unwrap()
                            .commit;
                        let commit2 = commit2.to_bytes().unwrap();
                        alice_central.mls_central.commit_accepted(&id).await.unwrap();

                        // fails when a commit is skipped
                        let out_of_order = bob_central.mls_central.decrypt_message(&id, &commit2).await;
                        assert!(matches!(out_of_order.unwrap_err(), CryptoError::BufferedFutureMessage));

                        // works in the right order though
                        // NB: here 'commit2' has been buffered so it is also applied when we decrypt commit1
                        bob_central.mls_central.decrypt_message(&id, &commit1).await.unwrap();

                        // and then fails again when trying to decrypt a commit with an epoch in the past
                        let past_commit = bob_central.mls_central.decrypt_message(&id, &commit1).await;
                        assert!(matches!(past_commit.unwrap_err(), CryptoError::StaleCommit));
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_allow_dropped_commits(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
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

                        let _alice_commit = alice_central
                            .mls_central
                            .update_keying_material(&id)
                            .await
                            .unwrap()
                            .commit;
                        let bob_commit = bob_central
                            .mls_central
                            .update_keying_material(&id)
                            .await
                            .unwrap()
                            .commit;
                        // Bob commit arrives first and has precedence hence Alice's commit is dropped
                        alice_central
                            .mls_central
                            .decrypt_message(&id, bob_commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        bob_central.mls_central.commit_accepted(&id).await.unwrap();
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_prevent_replayed_encrypted_handshake_messages(case: TestCase) {
            if case.custom_cfg().wire_policy == MlsWirePolicy::Ciphertext {
                run_test_with_client_ids(
                    case.clone(),
                    ["alice", "bob"],
                    move |[mut alice_central, mut bob_central]| {
                        Box::pin(async move {
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

                            let proposal1 = alice_central
                                .mls_central
                                .new_update_proposal(&id)
                                .await
                                .unwrap()
                                .proposal;
                            let proposal2 = proposal1.clone();
                            alice_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .group
                                .clear_pending_proposals();

                            let commit1 = alice_central
                                .mls_central
                                .update_keying_material(&id)
                                .await
                                .unwrap()
                                .commit;
                            let commit2 = commit1.clone();

                            // replayed encrypted proposal should fail
                            bob_central
                                .mls_central
                                .decrypt_message(&id, proposal1.to_bytes().unwrap())
                                .await
                                .unwrap();
                            assert!(matches!(
                                bob_central
                                    .mls_central
                                    .decrypt_message(&id, proposal2.to_bytes().unwrap())
                                    .await
                                    .unwrap_err(),
                                CryptoError::DuplicateMessage
                            ));
                            bob_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .group
                                .clear_pending_proposals();

                            // replayed encrypted commit should fail
                            bob_central
                                .mls_central
                                .decrypt_message(&id, commit1.to_bytes().unwrap())
                                .await
                                .unwrap();
                            assert!(matches!(
                                bob_central
                                    .mls_central
                                    .decrypt_message(&id, commit2.to_bytes().unwrap())
                                    .await
                                    .unwrap_err(),
                                CryptoError::StaleCommit
                            ));
                        })
                    },
                )
                .await;
            }
        }
    }
}
