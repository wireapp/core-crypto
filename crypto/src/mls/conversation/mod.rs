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

use openmls::{group::MlsGroup, messages::Welcome, prelude::Credential};
use openmls_traits::OpenMlsCryptoProvider;

use core_crypto_keystore::CryptoKeystoreMls;
use mls_crypto_provider::MlsCryptoProvider;

use config::MlsConversationConfiguration;

use crate::prelude::MlsCredentialType;
use crate::{
    mls::{client::Client, member::MemberId, ClientId, MlsCentral},
    CryptoError, CryptoResult, MlsError,
};

mod commit_delay;
pub mod config;
pub mod decrypt;
#[cfg(test)]
mod durability;
pub mod encrypt;
pub mod export;
pub mod handshake;
pub mod merge;
pub(crate) mod public_group_state;
mod renew;

/// A unique identifier for a group/conversation. The identifier must be unique within a client.
pub type ConversationId = Vec<u8>;

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
        author_client: &mut Client,
        creator_credential_type: MlsCredentialType,
        configuration: MlsConversationConfiguration,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        let kp = author_client
            .generate_keypackage(backend, configuration.ciphersuite, creator_credential_type)
            .await?;
        let kp_hash = kp.hash_ref(backend.crypto()).map_err(MlsError::from)?;

        let group = MlsGroup::new(
            backend,
            &configuration.as_openmls_default_configuration()?,
            openmls::group::GroupId::from_slice(&id),
            kp_hash.value(),
        )
        .await
        .map_err(MlsError::from)?;

        let mut conversation = Self {
            id,
            group,
            parent_id: None,
            configuration,
        };

        conversation.persist_group_when_changed(backend, true).await?;

        Ok(conversation)
    }

    // ? Do we need to provide the ratchet_tree to the MlsGroup? Does everything crumble down if we can't actually get it?
    /// Create the MLS conversation from an MLS Welcome message
    ///
    /// # Arguments
    /// * `welcome` - welcome message to create the group from
    /// * `config` - group configuration
    /// * `backend` - the KeyStore to persist the group
    ///
    /// # Errors
    /// Errors can happen from OpenMls or from the KeyStore
    pub async fn from_welcome_message(
        welcome: Welcome,
        configuration: MlsConversationConfiguration,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        let mls_group_config = configuration.as_openmls_default_configuration()?;
        let group = MlsGroup::new_from_welcome(backend, &mls_group_config, welcome, None)
            .await
            .map_err(MlsError::from)?;
        Self::from_mls_group(group, configuration, backend).await
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

        conversation.persist_group_when_changed(backend, true).await?;

        Ok(conversation)
    }

    /// Internal API: restore the conversation from a persistence-saved serialized Group State.
    pub(crate) fn from_serialized_state(buf: Vec<u8>, parent_id: Option<ConversationId>) -> CryptoResult<Self> {
        let group = MlsGroup::load(&mut &buf[..])?;
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
    pub fn members(&self) -> HashMap<MemberId, Vec<Credential>> {
        self.group.members().iter().fold(HashMap::new(), |mut acc, kp| {
            let credential = kp.credential();
            let client_id: ClientId = credential.identity().into();
            let member_id: MemberId = client_id.to_vec();
            acc.entry(member_id).or_insert_with(Vec::new).push(credential.clone());
            acc
        })
    }

    pub(crate) async fn persist_group_when_changed(
        &mut self,
        backend: &MlsCryptoProvider,
        force: bool,
    ) -> CryptoResult<()> {
        if force || self.group.state_changed() == openmls::group::InnerState::Changed {
            let mut buf = vec![];
            self.group.save(&mut buf)?;

            use core_crypto_keystore::CryptoKeystoreMls as _;
            Ok(backend
                .key_store()
                .mls_group_persist(&self.id, &buf, self.parent_id.as_deref())
                .await?)
        } else {
            Ok(())
        }
    }

    /// Marks this conversation as child of another.
    /// Prequisite: Being a member of this group and for it to be stored in the keystore
    pub async fn mark_as_child_of(
        &mut self,
        parent_id: &ConversationId,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<()> {
        if backend.key_store().mls_group_exists(parent_id).await {
            self.parent_id = Some(parent_id.clone());
            self.persist_group_when_changed(backend, true).await?;
            Ok(())
        } else {
            Err(CryptoError::ParentGroupNotFound)
        }
    }
}

impl MlsCentral {
    pub(crate) async fn get_conversation(
        &mut self,
        id: &ConversationId,
    ) -> CryptoResult<crate::group_store::GroupStoreValue<MlsConversation>> {
        let keystore = self.mls_backend.borrow_keystore_mut();
        self.mls_groups
            .get_fetch(id, keystore, None)
            .await?
            .ok_or_else(|| CryptoError::ConversationNotFound(id.clone()))
    }

    pub(crate) async fn get_parent_conversation(
        &mut self,
        id: &ConversationId,
    ) -> CryptoResult<Option<crate::group_store::GroupStoreValue<MlsConversation>>> {
        let conversation = self.get_conversation(id).await?;
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

    /// Mark a conversation as child of another one
    /// This will affect the behavior of callbacks in particular
    pub async fn mark_conversation_as_child_of(
        &mut self,
        child_id: &ConversationId,
        parent_id: &ConversationId,
    ) -> CryptoResult<()> {
        let conversation = self.get_conversation(child_id).await?;
        conversation
            .write()
            .await
            .mark_as_child_of(parent_id, &self.mls_backend)
            .await?;

        Ok(())
    }

    /// Destroys a group locally
    ///
    /// # Errors
    /// KeyStore errors, such as IO
    pub async fn wipe_conversation(&mut self, conversation_id: &ConversationId) -> CryptoResult<()> {
        if !self.conversation_exists(conversation_id).await {
            return Err(CryptoError::ConversationNotFound(conversation_id.clone()));
        }
        self.mls_backend.key_store().mls_group_delete(conversation_id).await?;
        let _ = self.mls_groups.remove(conversation_id);
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{
        mls::{
            conversation::handshake::MlsConversationCreationMessage, member::ConversationMember,
            MlsCentralConfiguration,
        },
        test_utils::*,
    };

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn create_self_conversation_should_succeed(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
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
                let alice_can_send_message = alice_central.encrypt_message(&id, b"me").await;
                assert!(alice_can_send_message.is_ok());
            })
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn create_1_1_conversation_should_succeed(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();

                    alice_central
                        .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let MlsConversationCreationMessage { welcome, .. } = alice_central
                        .add_members_to_conversation(&id, &mut [bob_central.rand_member().await])
                        .await
                        .unwrap();
                    // before merging, commit is not applied
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);
                    alice_central.commit_accepted(&id).await.unwrap();

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
                        .process_welcome_message(welcome, case.custom_cfg())
                        .await
                        .unwrap();

                    assert_eq!(
                        bob_central.get_conversation_unchecked(&id).await.id(),
                        alice_central.get_conversation_unchecked(&id).await.id()
                    );
                    assert!(alice_central.try_talk_to(&id, &mut bob_central).await.is_ok());
                })
            },
        )
        .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn create_many_people_conversation(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();

                let mut bob_and_friends = Vec::with_capacity(GROUP_SAMPLE_SIZE);
                for _ in 0..GROUP_SAMPLE_SIZE {
                    let uuid = uuid::Uuid::new_v4();
                    let name = uuid.hyphenated().to_string();
                    let path = tmp_db_file();
                    let config = MlsCentralConfiguration::try_new(
                        path.0,
                        name.clone(),
                        Some(name.as_str().into()),
                        vec![case.ciphersuite()],
                        None,
                    )
                    .unwrap();
                    let central = MlsCentral::try_new(config).await.unwrap();
                    bob_and_friends.push(central);
                }

                let number_of_friends = bob_and_friends.len();

                let mut bob_and_friends_members: Vec<ConversationMember> = futures_util::future::join_all(
                    bob_and_friends.iter().map(|c| async move { c.rand_member().await }),
                )
                .await;

                let MlsConversationCreationMessage { welcome, .. } = alice_central
                    .add_members_to_conversation(&id, &mut bob_and_friends_members)
                    .await
                    .unwrap();
                // before merging, commit is not applied
                assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);
                alice_central.commit_accepted(&id).await.unwrap();

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
                // TODO: Do things in parallel, this is waaaaay too slow (takes around 5 minutes)
                for mut c in bob_and_friends {
                    c.process_welcome_message(welcome.clone(), case.custom_cfg())
                        .await
                        .unwrap();
                    assert!(c.try_talk_to(&id, &mut alice_central).await.is_ok());
                    bob_and_friends_groups.push(c);
                }

                assert_eq!(bob_and_friends_groups.len(), GROUP_SAMPLE_SIZE);
            })
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn conversation_from_welcome_prunes_local_keypackage(case: TestCase) {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        use openmls_traits::OpenMlsCryptoProvider as _;
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    // has to be before the original key_package count because it creates one
                    let bob = bob_central.rand_member().await;
                    // Keep track of the whatever amount was initially generated
                    let original_kpb_count = bob_central
                        .mls_backend
                        .key_store()
                        .mls_keypackagebundle_count()
                        .await
                        .unwrap();

                    // Create a conversation from alice, where she invites bob
                    alice_central
                        .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let MlsConversationCreationMessage { welcome, .. } = alice_central
                        .add_members_to_conversation(&id, &mut [bob])
                        .await
                        .unwrap();

                    // Bob accepts the welcome message, and as such, it should prune the used keypackage from the store
                    bob_central
                        .process_welcome_message(welcome, case.custom_cfg())
                        .await
                        .unwrap();

                    // Ensure we're left with 1 less keypackage bundle in the store, because it was consumed with the OpenMLS Welcome message
                    let new_kpb_count = bob_central
                        .mls_backend
                        .key_store()
                        .mls_keypackagebundle_count()
                        .await
                        .unwrap();
                    assert_eq!(new_kpb_count, original_kpb_count - 1);
                })
            },
        )
        .await;
    }

    pub mod wipe_group {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_wipe_group(case: TestCase) {
            run_test_with_central(case.clone(), move |[mut central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    central
                        .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    assert!(central.get_conversation_unchecked(&id).await.group.is_active());

                    central.wipe_conversation(&id).await.unwrap();
                    assert!(!central.conversation_exists(&id).await);
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn cannot_wipe_group_inexistent(case: TestCase) {
            run_test_with_central(case.clone(), move |[mut central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    let err = central.wipe_conversation(&id).await.unwrap_err();
                    assert!(matches!(err, CryptoError::ConversationNotFound(conv_id) if conv_id == id));
                })
            })
            .await;
        }
    }
}
