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

use openmls::prelude::{ExternalSender, SignaturePublicKey};
use openmls::{group::MlsGroup, messages::Welcome, prelude::Credential, prelude::SenderRatchetConfiguration};
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsCryptoProvider;

use core_crypto_keystore::CryptoKeystoreMls;
use mls_crypto_provider::MlsCryptoProvider;

use crate::{
    client::Client, member::MemberId, ClientId, CryptoError, CryptoResult, MlsCentral, MlsCiphersuite, MlsError,
};

mod commit_delay;
pub mod decrypt;
#[cfg(test)]
mod durability;
pub mod encrypt;
pub mod handshake;
pub mod merge;
pub(crate) mod public_group_state;
mod renew;

/// A unique identifier for a group/conversation. The identifier must be unique within a client.
pub type ConversationId = Vec<u8>;

/// The configuration parameters for a group/conversation
#[derive(Debug, Default, Clone)]
pub struct MlsConversationConfiguration {
    /// Admins of the group/conversation
    pub admins: Vec<MemberId>,
    /// The `OpenMls` Ciphersuite used in the group
    pub ciphersuite: MlsCiphersuite,
    // TODO: Implement the key rotation manually instead.
    /// The duration for which a key must be rotated
    pub key_rotation_span: Option<std::time::Duration>,
    /// Delivery service public signature key and credential
    pub external_senders: Vec<ExternalSender>,
}

impl MlsConversationConfiguration {
    // TODO: pending a long term solution with a real certificate
    const WIRE_SERVER_IDENTITY: &'static str = "wire-server";
    const PADDING_SIZE: usize = 128;

    /// Generates an `MlsGroupConfig` from this configuration
    #[inline(always)]
    pub fn as_openmls_default_configuration(&self) -> CryptoResult<openmls::group::MlsGroupConfig> {
        Ok(openmls::group::MlsGroupConfig::builder()
            .wire_format_policy(openmls::group::MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(3)
            .padding_size(Self::PADDING_SIZE)
            .number_of_resumtion_secrets(1)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(2, 1000))
            .use_ratchet_tree_extension(true)
            .external_senders(self.external_senders.clone())
            .build())
    }

    /// Parses supplied key from Delivery Service in order to build back an [ExternalSender]
    /// Note that this only works currently with Ed25519 keys and will have to be changed to accept
    /// other key schemes
    pub fn set_raw_external_senders(&mut self, external_senders: Vec<Vec<u8>>) {
        let external_senders = external_senders
            .iter()
            .map(|key| {
                SignaturePublicKey::new(key.clone(), SignatureScheme::ED25519)
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
            })
            .filter_map(|r: CryptoResult<SignaturePublicKey>| r.ok())
            .map(|signature_key| ExternalSender::new_basic(Self::WIRE_SERVER_IDENTITY, signature_key))
            .collect();
        self.external_senders = external_senders;
    }
}

/// This type will store the state of a group. With the [MlsGroup] it holds, it provides all
/// operations that can be done in a group, such as creating proposals and commits.
/// More information [here](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html#name-general-setting)
#[derive(Debug)]
#[allow(dead_code)]
pub struct MlsConversation {
    pub(crate) id: ConversationId,
    pub(crate) group: MlsGroup,
    pub(crate) admins: Vec<MemberId>,
    configuration: MlsConversationConfiguration,
}

impl MlsConversation {
    /// Creates a new group/conversation
    ///
    /// # Arguments
    /// * `id` - group/conversation identifier
    /// * `author_client` - the client responsible for creating the group
    /// * `config` - group configuration
    /// * `backend` - MLS Provider that will be used to persist the group
    ///
    /// # Errors
    /// Errors can happen from OpenMls or from the KeyStore
    pub async fn create(
        id: ConversationId,
        author_client: &mut Client,
        config: MlsConversationConfiguration,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        let kp_hash = author_client.keypackage_raw_hash(backend).await?;

        let group = MlsGroup::new(
            backend,
            &config.as_openmls_default_configuration()?,
            openmls::group::GroupId::from_slice(&id),
            &kp_hash,
        )
        .await
        .map_err(MlsError::from)?;

        let mut conversation = Self {
            id,
            group,
            admins: config.admins.clone(),
            configuration: config,
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
        mut group: MlsGroup,
        configuration: MlsConversationConfiguration,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        let id = ConversationId::from(group.group_id().as_slice());

        let mut buf = vec![];
        group.save(&mut buf)?;
        use core_crypto_keystore::CryptoKeystoreMls as _;
        backend.key_store().mls_group_persist(&id, &buf).await?;

        Ok(Self {
            id,
            admins: configuration.admins.clone(),
            group,
            configuration,
        })
    }

    /// Internal API: restore the conversation from a persistence-saved serialized Group State.
    pub(crate) fn from_serialized_state(buf: Vec<u8>) -> CryptoResult<Self> {
        let group = MlsGroup::load(&mut &buf[..])?;
        let id = ConversationId::from(group.group_id().as_slice());
        let configuration = MlsConversationConfiguration {
            ciphersuite: group.ciphersuite().into(),
            ..Default::default()
        };

        Ok(Self {
            id,
            group,
            configuration,
            admins: Default::default(),
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

    /// Checks if the user can perform an operation (AKA if the user is an admin)
    pub fn can_user_act(&self, uuid: MemberId) -> bool {
        self.admins.contains(&uuid)
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
            Ok(backend.key_store().mls_group_persist(&self.id, &buf).await?)
        } else {
            Ok(())
        }
    }
}

impl MlsCentral {
    pub(crate) fn get_conversation(&self, id: &ConversationId) -> CryptoResult<&MlsConversation> {
        self.mls_groups
            .get(id)
            .ok_or_else(|| CryptoError::ConversationNotFound(id.clone()))
    }

    pub(crate) fn get_conversation_mut<'a>(
        groups: &'a mut HashMap<ConversationId, MlsConversation>,
        id: &ConversationId,
    ) -> CryptoResult<&'a mut MlsConversation> {
        groups
            .get_mut(id)
            .ok_or_else(|| CryptoError::ConversationNotFound(id.clone()))
    }

    /// Destroys a group locally
    ///
    /// # Errors
    /// KeyStore errors, such as IO
    pub async fn wipe_conversation(&mut self, conversation_id: &ConversationId) -> CryptoResult<()> {
        if !self.conversation_exists(conversation_id) {
            return Err(CryptoError::ConversationNotFound(conversation_id.clone()));
        }
        self.mls_backend.key_store().mls_group_delete(conversation_id).await?;
        self.mls_groups.remove(conversation_id);
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{
        conversation::handshake::MlsConversationCreationMessage, credential::CredentialSupplier,
        member::ConversationMember, test_utils::*, MlsCentralConfiguration, MlsConversationConfiguration,
    };

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn create_self_conversation_should_succeed(credential: CredentialSupplier) {
        run_test_with_client_ids(credential, ["alice"], move |[mut alice_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .new_conversation(id.clone(), MlsConversationConfiguration::default())
                    .await
                    .unwrap();
                assert_eq!(alice_central[&id].id, id);
                assert_eq!(alice_central[&id].group.group_id().as_slice(), id);
                assert_eq!(alice_central[&id].members().len(), 1);
                let alice_can_send_message = alice_central.encrypt_message(&id, b"me").await;
                assert!(alice_can_send_message.is_ok());
            })
        })
        .await;
    }

    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn create_1_1_conversation_should_succeed(credential: CredentialSupplier) {
        run_test_with_client_ids(
            credential,
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();

                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();

                    let MlsConversationCreationMessage { welcome, .. } = alice_central
                        .add_members_to_conversation(&id, &mut [bob_central.rnd_member().await])
                        .await
                        .unwrap();
                    // before merging, commit is not applied
                    assert_eq!(alice_central[&id].members().len(), 1);
                    alice_central.commit_accepted(&id).await.unwrap();

                    assert_eq!(alice_central[&id].id, id);
                    assert_eq!(alice_central[&id].group.group_id().as_slice(), id);
                    assert_eq!(alice_central[&id].members().len(), 2);

                    bob_central
                        .process_welcome_message(welcome, MlsConversationConfiguration::default())
                        .await
                        .unwrap();

                    assert_eq!(bob_central[&id].id(), alice_central[&id].id());
                    assert!(alice_central.talk_to(&id, &mut bob_central).await.is_ok());
                })
            },
        )
        .await;
    }

    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn create_100_people_conversation(credential: CredentialSupplier) {
        run_test_with_client_ids(credential, ["alice"], move |[mut alice_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .new_conversation(id.clone(), MlsConversationConfiguration::default())
                    .await
                    .unwrap();

                let mut bob_and_friends = Vec::with_capacity(GROUP_SAMPLE_SIZE);
                for _ in 0..GROUP_SAMPLE_SIZE {
                    let uuid = uuid::Uuid::new_v4();
                    let name = uuid.hyphenated().to_string();
                    let path = tmp_db_file();
                    let cfg =
                        MlsCentralConfiguration::try_new(path.0, name.as_str().into(), name.as_str().into()).unwrap();
                    let central = MlsCentral::try_new(cfg, credential()).await.unwrap();
                    bob_and_friends.push(central);
                }

                let number_of_friends = bob_and_friends.len();

                let mut bob_and_friends_members: Vec<ConversationMember> =
                    futures_util::future::join_all(bob_and_friends.iter().map(|c| async move { c.rnd_member().await }))
                        .await;

                let MlsConversationCreationMessage { welcome, .. } = alice_central
                    .add_members_to_conversation(&id, &mut bob_and_friends_members)
                    .await
                    .unwrap();
                // before merging, commit is not applied
                assert_eq!(alice_central[&id].members().len(), 1);
                alice_central.commit_accepted(&id).await.unwrap();

                assert_eq!(alice_central[&id].id, id);
                assert_eq!(alice_central[&id].group.group_id().as_slice(), id);
                assert_eq!(alice_central[&id].members().len(), 1 + number_of_friends);

                let mut bob_and_friends_groups = Vec::with_capacity(bob_and_friends.len());
                for mut c in bob_and_friends {
                    c.process_welcome_message(welcome.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    assert!(c.talk_to(&id, &mut alice_central).await.is_ok());
                    bob_and_friends_groups.push(c);
                }

                assert_eq!(bob_and_friends_groups.len(), GROUP_SAMPLE_SIZE);
            })
        })
        .await;
    }

    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn conversation_from_welcome_prunes_local_keypackage(credential: CredentialSupplier) {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        use openmls_traits::OpenMlsCryptoProvider as _;
        run_test_with_client_ids(
            credential,
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    // has to be before the original key_package count because it creates one
                    let bob = bob_central.rnd_member().await;
                    // Keep track of the whatever amount was initially generated
                    let original_kpb_count = bob_central
                        .mls_backend
                        .key_store()
                        .mls_keypackagebundle_count()
                        .await
                        .unwrap();

                    // Create a conversation from alice, where she invites bob
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();

                    let MlsConversationCreationMessage { welcome, .. } = alice_central
                        .add_members_to_conversation(&id, &mut [bob])
                        .await
                        .unwrap();

                    // Bob accepts the welcome message, and as such, it should prune the used keypackage from the store
                    bob_central
                        .process_welcome_message(welcome, MlsConversationConfiguration::default())
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

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn can_wipe_group(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    let conversation_configuration = MlsConversationConfiguration::default();
                    let id = conversation_id();
                    central
                        .new_conversation(id.clone(), conversation_configuration)
                        .await
                        .unwrap();
                    assert!(central[&id].group.is_active());

                    central.wipe_conversation(&id).await.unwrap();
                    assert!(!central.conversation_exists(&id));
                })
            })
            .await;
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn cannot_wipe_group_inexistent(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
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
