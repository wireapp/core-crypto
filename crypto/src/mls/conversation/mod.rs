// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

//! MLS groups (aka conversation) are the actual entities cementing all the participants in a
//! conversation.
//!
//! This table summarizes what operations are permitted on a group depending its state:
//! *(PP=pending proposal, PC=pending commit)*
//!
//! | can I ?   | 0 PP / 0 PC | 1+ PP / 0 PC | 0 PP / 1 PC | 1+ PP / 1 PC |
//! |-----------|-------------|--------------|-------------|--------------|
//! | encrypt   | ✅           | ❌            | ❌           | ❌            |
//! | handshake | ✅           | ✅            | ❌           | ❌            |
//! | merge     | ❌           | ❌            | ✅           | ✅            |
//! | decrypt   | ✅           | ✅            | ✅           | ✅            |

use std::collections::HashMap;

use openmls::prelude::{CredentialWithKey, SignaturePublicKey};
use openmls::{group::MlsGroup, prelude::Credential};
use openmls_traits::types::SignatureScheme;

use core_crypto_keystore::{Connection, CryptoKeystoreMls};
use mls_crypto_provider::{CryptoKeystore, MlsCryptoProvider};

use config::MlsConversationConfiguration;

use crate::{
    group_store::{GroupStore, GroupStoreValue},
    mls::{client::Client, MlsCentral},
    prelude::{CryptoError, CryptoResult, MlsCiphersuite, MlsCredentialType, MlsError},
};

use crate::context::CentralContext;

mod buffer_messages;
pub(crate) mod commit;
mod commit_delay;
pub(crate) mod config;
#[cfg(test)]
mod db_count;
pub mod decrypt;
mod duplicate;
#[cfg(test)]
mod durability;
pub(crate) mod encrypt;
pub(crate) mod export;
pub(crate) mod external_sender;
pub(crate) mod group_info;
mod leaf_node_validation;
pub(crate) mod merge;
mod orphan_welcome;
mod own_commit;
pub(crate) mod proposal;
mod renew;
pub(crate) mod welcome;
mod wipe;
/// A unique identifier for a group/conversation. The identifier must be unique within a client.
pub type ConversationId = Vec<u8>;

/// This is a wrapper on top of the OpenMls's [MlsGroup], that provides Core Crypto specific functionality
///
/// This type will store the state of a group. With the [MlsGroup] it holds, it provides all
/// operations that can be done in a group, such as creating proposals and commits.
/// More information [here](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html#name-general-setting)
#[derive(Debug)]
#[allow(dead_code)]
pub struct MlsConversation {
    pub(crate) id: ConversationId,
    pub(crate) parent_id: Option<ConversationId>,
    pub(crate) group: MlsGroup,
    configuration: MlsConversationConfiguration,
}

impl MlsConversation {
    /// Creates a new group/conversation
    ///
    /// # Arguments
    /// * `id` - group/conversation identifier
    /// * `author_client` - the client responsible for creating the group
    /// * `creator_credential_type` - kind of credential the creator wants to join the group with
    /// * `config` - group configuration
    /// * `backend` - MLS Provider that will be used to persist the group
    ///
    /// # Errors
    /// Errors can happen from OpenMls or from the KeyStore
    pub async fn create(
        id: ConversationId,
        author_client: &Client,
        creator_credential_type: MlsCredentialType,
        configuration: MlsConversationConfiguration,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        let (cs, ct) = (configuration.ciphersuite, creator_credential_type);
        let cb = author_client
            .get_most_recent_or_create_credential_bundle(backend, cs.signature_algorithm(), ct)
            .await?;

        let group = MlsGroup::new_with_group_id(
            backend,
            &cb.signature_key,
            &configuration.as_openmls_default_configuration()?,
            openmls::prelude::GroupId::from_slice(id.as_slice()),
            cb.to_mls_credential_with_key(),
        )
        .await
        .map_err(MlsError::from)?;

        let mut conversation = Self {
            id,
            group,
            parent_id: None,
            configuration,
        };

        conversation
            .persist_group_when_changed(&backend.keystore(), true)
            .await?;

        Ok(conversation)
    }

    /// Internal API: create a group from an existing conversation. For example by external commit
    pub(crate) async fn from_mls_group(
        group: MlsGroup,
        configuration: MlsConversationConfiguration,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        let id = ConversationId::from(group.group_id().as_slice());

        let mut conversation = Self {
            id,
            group,
            configuration,
            parent_id: None,
        };

        conversation
            .persist_group_when_changed(&backend.keystore(), true)
            .await?;

        Ok(conversation)
    }

    /// Internal API: restore the conversation from a persistence-saved serialized Group State.
    pub(crate) fn from_serialized_state(buf: Vec<u8>, parent_id: Option<ConversationId>) -> CryptoResult<Self> {
        let group: MlsGroup = core_crypto_keystore::deser(&buf)?;
        let id = ConversationId::from(group.group_id().as_slice());
        let configuration = MlsConversationConfiguration {
            ciphersuite: group.ciphersuite().into(),
            ..Default::default()
        };

        Ok(Self {
            id,
            group,
            parent_id,
            configuration,
        })
    }

    /// Group/conversation id
    pub fn id(&self) -> &ConversationId {
        &self.id
    }

    /// Returns all members credentials from the group/conversation
    pub fn members(&self) -> HashMap<Vec<u8>, Credential> {
        self.group.members().fold(HashMap::new(), |mut acc, kp| {
            let credential = kp.credential;
            let id = credential.identity().to_vec();
            acc.entry(id).or_insert(credential);
            acc
        })
    }

    /// Returns all members credentials with their signature public key from the group/conversation
    pub fn members_with_key(&self) -> HashMap<Vec<u8>, CredentialWithKey> {
        self.group.members().fold(HashMap::new(), |mut acc, kp| {
            let credential = kp.credential;
            let id = credential.identity().to_vec();
            let signature_key = SignaturePublicKey::from(kp.signature_key);
            let credential = CredentialWithKey {
                credential,
                signature_key,
            };
            acc.entry(id).or_insert(credential);
            acc
        })
    }

    pub(crate) async fn persist_group_when_changed(
        &mut self,
        keystore: &CryptoKeystore,
        force: bool,
    ) -> CryptoResult<()> {
        if force || self.group.state_changed() == openmls::group::InnerState::Changed {
            keystore
                .mls_group_persist(
                    &self.id,
                    &core_crypto_keystore::ser(&self.group)?,
                    self.parent_id.as_deref(),
                )
                .await?;

            self.group.set_state(openmls::group::InnerState::Persisted);
        }

        Ok(())
    }

    /// Marks this conversation as child of another.
    /// Prequisite: Being a member of this group and for it to be stored in the keystore
    pub async fn mark_as_child_of(&mut self, parent_id: &ConversationId, keystore: &Connection) -> CryptoResult<()> {
        if keystore.mls_group_exists(parent_id).await {
            self.parent_id = Some(parent_id.clone());
            self.persist_group_when_changed(keystore, true).await?;
            Ok(())
        } else {
            Err(CryptoError::ParentGroupNotFound)
        }
    }

    pub(crate) fn own_credential_type(&self) -> CryptoResult<MlsCredentialType> {
        Ok(self
            .group
            .own_leaf_node()
            .ok_or(CryptoError::InternalMlsError)?
            .credential()
            .credential_type()
            .into())
    }

    pub(crate) fn ciphersuite(&self) -> MlsCiphersuite {
        self.configuration.ciphersuite
    }

    pub(crate) fn signature_scheme(&self) -> SignatureScheme {
        self.ciphersuite().signature_algorithm()
    }
}

impl MlsCentral {
    pub(crate) async fn get_conversation(&self, id: &ConversationId) -> CryptoResult<Option<MlsConversation>> {
        GroupStore::fetch_from_keystore(id, &self.mls_backend.keystore(), None).await
    }
}

impl CentralContext {
    pub(crate) async fn get_conversation(&self, id: &ConversationId) -> CryptoResult<GroupStoreValue<MlsConversation>> {
        let keystore = self.mls_provider().await?.keystore();
        self.mls_groups()
            .await?
            .get_fetch(id, &keystore, None)
            .await?
            .ok_or_else(|| CryptoError::ConversationNotFound(id.clone()))
    }

    pub(crate) async fn get_parent_conversation(
        &self,
        conversation: &GroupStoreValue<MlsConversation>,
    ) -> CryptoResult<Option<GroupStoreValue<MlsConversation>>> {
        let conversation_lock = conversation.read().await;
        if let Some(parent_id) = conversation_lock.parent_id.as_ref() {
            Ok(Some(
                self.get_conversation(parent_id)
                    .await
                    .map_err(|_| CryptoError::ParentGroupNotFound)?,
            ))
        } else {
            Ok(None)
        }
    }

    pub(crate) async fn get_all_conversations(&self) -> CryptoResult<Vec<GroupStoreValue<MlsConversation>>> {
        let keystore = self.mls_provider().await?.keystore();
        self.mls_groups().await?.get_fetch_all(&keystore).await
    }

    /// Mark a conversation as child of another one
    /// This will affect the behavior of callbacks in particular
    #[cfg_attr(test, crate::idempotent)]
    pub async fn mark_conversation_as_child_of(
        &self,
        child_id: &ConversationId,
        parent_id: &ConversationId,
    ) -> CryptoResult<()> {
        let conversation = self.get_conversation(child_id).await?;
        conversation
            .write()
            .await
            .mark_as_child_of(parent_id, &self.keystore().await?)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::e2e_identity::rotate::tests::all::failsafe_ctx;

    use wasm_bindgen_test::*;

    use crate::{
        prelude::{
            ClientIdentifier, MlsCentralConfiguration, MlsConversationCreationMessage, INITIAL_KEYING_MATERIAL_COUNT,
        },
        test_utils::*,
        CoreCrypto,
    };

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn create_self_conversation_should_succeed(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
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
                assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);
                let alice_can_send_message = alice_central.context.encrypt_message(&id, b"me").await;
                assert!(alice_can_send_message.is_ok());
            })
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn create_1_1_conversation_should_succeed(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();

                alice_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();

                let bob = bob_central.rand_key_package(&case).await;
                let MlsConversationCreationMessage { welcome, .. } = alice_central
                    .context
                    .add_members_to_conversation(&id, vec![bob])
                    .await
                    .unwrap();
                // before merging, commit is not applied
                assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);
                alice_central.context.commit_accepted(&id).await.unwrap();

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

                bob_central
                    .context
                    .process_welcome_message(welcome.into(), case.custom_cfg())
                    .await
                    .unwrap();

                assert_eq!(
                    bob_central.get_conversation_unchecked(&id).await.id(),
                    alice_central.get_conversation_unchecked(&id).await.id()
                );
                assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());
            })
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn create_many_people_conversation(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
            Box::pin(async move {
                let x509_test_chain_arc = failsafe_ctx(&mut [&mut alice_central], case.signature_scheme()).await;
                let x509_test_chain = x509_test_chain_arc.as_ref().as_ref().unwrap();

                let id = conversation_id();
                alice_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();

                let mut bob_and_friends: Vec<ClientContext> = Vec::with_capacity(GROUP_SAMPLE_SIZE);
                for _ in 0..GROUP_SAMPLE_SIZE {
                    let uuid = uuid::Uuid::new_v4();
                    let name = uuid.hyphenated().to_string();
                    let path = tmp_db_file();
                    let config = MlsCentralConfiguration::try_new(
                        path.0,
                        name.clone(),
                        None,
                        vec![case.ciphersuite()],
                        None,
                        Some(INITIAL_KEYING_MATERIAL_COUNT),
                    )
                    .unwrap();
                    let central = MlsCentral::try_new(config).await.unwrap();
                    let cc = CoreCrypto::from(central);
                    let friend_context = cc.new_transaction().await.unwrap();
                    let central = cc.mls;

                    x509_test_chain.register_with_central(&friend_context).await;

                    let client_id: crate::prelude::ClientId = name.as_str().into();
                    let identity = match case.credential_type {
                        MlsCredentialType::Basic => ClientIdentifier::Basic(client_id),
                        MlsCredentialType::X509 => {
                            let x509_test_chain = alice_central
                                .x509_test_chain
                                .as_ref()
                                .as_ref()
                                .expect("No x509 test chain");
                            let cert = crate::prelude::CertificateBundle::rand(
                                &client_id,
                                x509_test_chain.find_local_intermediate_ca(),
                            );
                            ClientIdentifier::X509(HashMap::from([(case.cfg.ciphersuite.signature_algorithm(), cert)]))
                        }
                    };
                    friend_context
                        .mls_init(
                            identity,
                            vec![case.cfg.ciphersuite],
                            Some(INITIAL_KEYING_MATERIAL_COUNT),
                        )
                        .await
                        .unwrap();

                    let context = ClientContext {
                        context: friend_context,
                        central,
                        x509_test_chain: x509_test_chain_arc.clone(),
                    };
                    bob_and_friends.push(context);
                }

                let number_of_friends = bob_and_friends.len();

                let mut bob_and_friends_kps = vec![];
                for c in &bob_and_friends {
                    bob_and_friends_kps.push(c.rand_key_package(&case).await);
                }

                let MlsConversationCreationMessage { welcome, .. } = alice_central
                    .context
                    .add_members_to_conversation(&id, bob_and_friends_kps)
                    .await
                    .unwrap();
                // before merging, commit is not applied
                assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);
                alice_central.context.commit_accepted(&id).await.unwrap();

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
                assert_eq!(
                    alice_central.get_conversation_unchecked(&id).await.members().len(),
                    1 + number_of_friends
                );

                let mut bob_and_friends_groups = Vec::with_capacity(bob_and_friends.len());
                // TODO: Do things in parallel, this is waaaaay too slow (takes around 5 minutes). Tracking issue: WPB-9624
                for c in bob_and_friends {
                    c.context
                        .process_welcome_message(welcome.clone().into(), case.custom_cfg())
                        .await
                        .unwrap();
                    assert!(c.try_talk_to(&id, &alice_central).await.is_ok());
                    bob_and_friends_groups.push(c);
                }

                assert_eq!(bob_and_friends_groups.len(), GROUP_SAMPLE_SIZE);
            })
        })
        .await;
    }
}
