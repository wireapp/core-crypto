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

use openmls::{group::MlsGroup, messages::Welcome, prelude::Credential, prelude::SenderRatchetConfiguration};
use openmls_traits::OpenMlsCryptoProvider;

use mls_crypto_provider::MlsCryptoProvider;

use crate::{
    client::Client, member::MemberId, ClientId, CryptoError, CryptoResult, MlsCentral, MlsCiphersuite, MlsError,
};

mod commit_delay;
pub mod decrypt;
pub mod encrypt;
pub mod handshake;
pub mod merge;
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
    /// Delivery service credential
    pub external_senders: Vec<Credential>,
}

impl MlsConversationConfiguration {
    /// Generates an `MlsGroupConfig` from this configuration
    #[inline(always)]
    pub fn as_openmls_default_configuration(&self) -> openmls::group::MlsGroupConfig {
        let external_senders = self.external_senders.clone();
        openmls::group::MlsGroupConfig::builder()
            .wire_format_policy(openmls::group::MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(3)
            .padding_size(16)
            .number_of_resumtion_secrets(1)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(2, 1000))
            .use_ratchet_tree_extension(true)
            .external_senders(external_senders)
            .build()
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
            &config.as_openmls_default_configuration(),
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
    /// * `backend` - the KeyStore to persiste the group
    ///
    /// # Errors
    /// Errors can happen from OpenMls or from the KeyStore
    pub async fn from_welcome_message(
        welcome: Welcome,
        configuration: MlsConversationConfiguration,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        let mls_group_config = configuration.as_openmls_default_configuration();
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
}

#[cfg(test)]
pub mod state_tests_utils {
    use crate::{proposal::MlsProposal, MlsCentral, MlsConversationConfiguration};

    pub async fn conv_no_pending(central: &mut MlsCentral, id: &Vec<u8>) {
        central
            .new_conversation(id.clone(), MlsConversationConfiguration::default())
            .await
            .unwrap();
        let conv = central.get_conversation(id).unwrap();
        assert_eq!(conv.group.pending_proposals().count(), 0);
        assert!(conv.group.pending_commit().is_none());
    }

    pub async fn conv_pending_proposal_and_no_pending_commit(central: &mut MlsCentral, id: &Vec<u8>) {
        central
            .new_conversation(id.clone(), MlsConversationConfiguration::default())
            .await
            .unwrap();
        let _ = central.new_proposal(id, MlsProposal::Update).await.unwrap();
        let conv = central.get_conversation(id).unwrap();
        assert_eq!(conv.group.pending_proposals().count(), 1);
        assert!(conv.group.pending_commit().is_none());
    }

    pub async fn conv_no_pending_proposal_and_pending_commit(central: &mut MlsCentral, id: &Vec<u8>) {
        central
            .new_conversation(id.clone(), MlsConversationConfiguration::default())
            .await
            .unwrap();
        let _ = central.update_keying_material(id).await.unwrap();
        let conv = central.get_conversation(id).unwrap();
        assert_eq!(conv.group.pending_proposals().count(), 0);
        assert!(conv.group.pending_commit().is_some());
    }

    pub async fn conv_pending_proposal_and_pending_commit(
        alice_central: &mut MlsCentral,
        bob_central: MlsCentral,
        id: &Vec<u8>,
    ) {
        alice_central
            .new_conversation(id.clone(), MlsConversationConfiguration::default())
            .await
            .unwrap();

        let bob_kp = bob_central.get_one_key_package().await.unwrap();
        let epoch = alice_central.get_conversation(id).unwrap().group.epoch();
        let bob_proposal = bob_central
            .new_external_add_proposal(id.clone(), epoch, bob_kp)
            .await
            .unwrap();

        alice_central.update_keying_material(id).await.unwrap();

        alice_central
            .decrypt_message(id, bob_proposal.to_bytes().unwrap())
            .await
            .unwrap();
        let alice_group = alice_central.get_conversation(id).unwrap();
        assert_eq!(alice_group.group.pending_proposals().count(), 1);
        assert!(alice_group.group.pending_commit().is_some());
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{
        conversation::handshake::MlsConversationCreationMessage, credential::CredentialSupplier,
        member::ConversationMember, test_fixture_utils::*, MlsConversationConfiguration,
    };

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod create {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn create_self_conversation_should_succeed(credential: CredentialSupplier) {
            let conversation_id = conversation_id();
            let (alice_backend, mut alice) = alice(credential).await.unwrap();

            let mut alice_group = MlsConversation::create(
                conversation_id.clone(),
                alice.local_client_mut(),
                MlsConversationConfiguration::default(),
                &alice_backend,
            )
            .await
            .unwrap();

            assert_eq!(alice_group.id, conversation_id);
            assert_eq!(alice_group.group.group_id().as_slice(), conversation_id);
            assert_eq!(alice_group.members().len(), 1);
            let alice_can_send_message = alice_group.encrypt_message(b"me", &alice_backend).await;
            assert!(alice_can_send_message.is_ok());
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn create_1_1_conversation_should_succeed(credential: CredentialSupplier) {
            let conversation_id = conversation_id();
            let (alice_backend, mut alice) = alice(credential).await.unwrap();
            let (bob_backend, bob) = bob(credential).await.unwrap();

            let mut alice_group = MlsConversation::create(
                conversation_id.clone(),
                alice.local_client_mut(),
                MlsConversationConfiguration::default(),
                &alice_backend,
            )
            .await
            .unwrap();

            let conversation_creation_message = alice_group.add_members(&mut [bob], &alice_backend).await.unwrap();
            // before merging, commit is not applied
            assert_eq!(alice_group.members().len(), 1);
            alice_group.commit_accepted(&alice_backend).await.unwrap();

            assert_eq!(alice_group.id, conversation_id);
            assert_eq!(alice_group.group.group_id().as_slice(), conversation_id);
            assert_eq!(alice_group.members().len(), 2);

            let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message;

            let mut bob_group =
                MlsConversation::from_welcome_message(welcome, MlsConversationConfiguration::default(), &bob_backend)
                    .await
                    .unwrap();

            assert_eq!(bob_group.id(), alice_group.id());

            let alice_can_send_message = alice_group.encrypt_message(b"me", &alice_backend).await;
            assert!(alice_can_send_message.is_ok());
            let bob_can_send_message = bob_group.encrypt_message(b"me", &bob_backend).await;
            assert!(bob_can_send_message.is_ok());
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn create_100_people_conversation(credential: CredentialSupplier) {
            let (alice_backend, mut alice) = alice(credential).await.unwrap();
            let mut bob_and_friends = Vec::with_capacity(99);

            for _ in 0..99 {
                let uuid = uuid::Uuid::new_v4();
                let backend = init_keystore(&uuid.hyphenated().to_string()).await;

                let member = ConversationMember::random_generate(&backend, credential).await.unwrap();
                bob_and_friends.push((backend, member));
            }

            let number_of_friends = bob_and_friends.len();

            let conversation_id = conversation_id();

            let conversation_config = MlsConversationConfiguration::default();
            let mut alice_group = MlsConversation::create(
                conversation_id.clone(),
                alice.local_client_mut(),
                conversation_config.clone(),
                &alice_backend,
            )
            .await
            .unwrap();

            let mut bob_and_friends_members: Vec<ConversationMember> =
                bob_and_friends.iter().map(|(_, (m, _))| m.clone()).collect();

            let conversation_creation_message = alice_group
                .add_members(&mut bob_and_friends_members, &alice_backend)
                .await
                .unwrap();
            // before merging, commit is not applied
            assert_eq!(alice_group.members().len(), 1);
            alice_group.commit_accepted(&alice_backend).await.unwrap();

            assert_eq!(alice_group.id, conversation_id);
            assert_eq!(alice_group.group.group_id().as_slice(), conversation_id);
            assert_eq!(alice_group.members().len(), 1 + number_of_friends);

            let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message;

            let mut bob_and_friends_groups: Vec<MlsConversation> = Vec::with_capacity(bob_and_friends.len());
            for (backend, _) in bob_and_friends {
                bob_and_friends_groups.push(
                    MlsConversation::from_welcome_message(welcome.clone(), conversation_config.clone(), &backend)
                        .await
                        .unwrap(),
                );
            }

            assert_eq!(bob_and_friends_groups.len(), 99);
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn conversation_from_welcome_prunes_local_keypackage(credential: CredentialSupplier) {
            use core_crypto_keystore::CryptoKeystoreMls as _;
            use openmls_traits::OpenMlsCryptoProvider as _;
            let (alice_backend, mut alice) = alice(credential).await.unwrap();
            let (bob_backend, bob) = bob(credential).await.unwrap();
            // Keep track of the whatever amount was initially generated
            let original_kpb_count = bob_backend.key_store().mls_keypackagebundle_count().await.unwrap();

            // Create a conversation from alice, where she invites bob
            let conversation_id = conversation_id();
            let conversation_config = MlsConversationConfiguration::default();
            let mut alice_group = MlsConversation::create(
                conversation_id.clone(),
                alice.local_client_mut(),
                conversation_config.clone(),
                &alice_backend,
            )
            .await
            .unwrap();

            let MlsConversationCreationMessage { welcome, .. } = alice_group
                .add_members(&mut [bob.clone()], &alice_backend)
                .await
                .unwrap();

            // Bob accepts the welcome message, and as such, it should prune the used keypackage from the store
            let _bob_group = MlsConversation::from_welcome_message(welcome, conversation_config.clone(), &bob_backend)
                .await
                .unwrap();

            // Ensure we're left with 1 less keypackage bundle in the store, because it was consumed with the OpenMLS Welcome message
            let new_kpb_count = bob_backend.key_store().mls_keypackagebundle_count().await.unwrap();
            assert_eq!(new_kpb_count, original_kpb_count - 1);
        }
    }
}
