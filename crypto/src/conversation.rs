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

use crate::{commit_delay::calculate_delay, ClientId};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::Credential;
use openmls::{
    framing::{MlsMessageOut, ProcessedMessage},
    group::MlsGroup,
    messages::Welcome,
    prelude::{KeyPackage, KeyPackageRef, SenderRatchetConfiguration},
};
use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    client::Client,
    member::{ConversationMember, MemberId},
    CryptoError, CryptoResult, MlsCiphersuite, MlsError,
};

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

/// Returned when initializing a conversation. Different from conversation created from a [`Welcome`] message or an external commit.
#[derive(Debug)]
pub struct MlsConversationCreationMessage {
    /// A welcome message indicating new members were added by a commit
    pub welcome: Welcome,
    /// A message that will contain information about the last commit
    pub message: MlsMessageOut,
}

/// It is a wrapper for the self removal proposal and a message containing a commit with the
/// removal of other clients. It is returned when calling [crate::MlsCentral::leave_conversation]
#[derive(Debug)]
pub struct MlsConversationLeaveMessage {
    /// A message containing information about the last commit
    pub self_removal_proposal: MlsMessageOut,
    /// Optional message when other clients were also removed from the group
    pub other_clients_removal_commit: Option<MlsMessageOut>,
}

impl MlsConversationCreationMessage {
    /// Serializes both wrapped objects into TLS and return them as a tuple of byte arrays.
    /// 0 -> welcome
    /// 1 -> message
    pub fn to_bytes_pairs(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        use openmls::prelude::TlsSerializeTrait as _;
        let welcome = self.welcome.tls_serialize_detached().map_err(MlsError::from)?;

        let msg = self.message.to_bytes().map_err(MlsError::from)?;

        Ok((welcome, msg))
    }
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
    pub fn members(&self) -> std::collections::HashMap<MemberId, Vec<openmls::credentials::Credential>> {
        self.group
            .members()
            .iter()
            .fold(std::collections::HashMap::new(), |mut acc, kp| {
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

    /// Add new members to the conversation
    /// Note: this is not exposed publicly because authorization isn't handled at this level
    pub(crate) async fn add_members(
        &mut self,
        members: &mut [ConversationMember],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsConversationCreationMessage> {
        let keypackages = members
            .iter_mut()
            .flat_map(|member| member.keypackages_for_all_clients())
            .filter_map(|(_, kps)| kps)
            .collect::<Vec<KeyPackage>>();

        let (message, welcome) = self
            .group
            .add_members(backend, &keypackages)
            .await
            .map_err(MlsError::from)?;
        self.group.merge_pending_commit().map_err(MlsError::from)?;

        self.persist_group_when_changed(backend, false).await?;

        Ok(MlsConversationCreationMessage { welcome, message })
    }

    /// Remove members from the conversation
    /// Note: this is not exposed publicly because authorization isn't handled at this level
    pub(crate) async fn remove_members(
        &mut self,
        clients: &[ClientId],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsMessageOut> {
        let crypto = backend.crypto();

        let member_kps = self
            .group
            .members()
            .into_iter()
            .filter(|kp| {
                let identity = kp.credential().identity();
                clients.iter().any(move |client_id| client_id.as_slice() == identity)
            })
            .try_fold(Vec::new(), |mut acc, kp| -> CryptoResult<Vec<KeyPackageRef>> {
                acc.push(kp.hash_ref(crypto).map_err(MlsError::from)?);
                Ok(acc)
            })?;

        let (message, _) = self
            .group
            .remove_members(backend, &member_kps)
            .await
            .map_err(MlsError::from)?;
        self.group.merge_pending_commit().map_err(MlsError::from)?;

        self.persist_group_when_changed(backend, false).await?;

        Ok(message)
    }

    /// Deserializes a TLS-serialized message, then deciphers it
    ///
    /// # Arguments
    /// * `message` - the encrypted message as a byte array
    /// * `backend` - the KeyStore to persist possible group changes
    ///
    /// # Return type
    /// This method will return a tuple containing an optional message and an optional delay time
    /// for the callers to wait for committing. A message will be `None` in case the provided payload is
    /// a system message, such as Proposals and Commits. Otherwise it will return the message as a
    /// byte array. The delay will be `Some` only when the message contains a proposal
    ///
    /// # Errors
    /// KeyStore errors can happen only if it is not an Application Message (hence causing group
    /// changes). Otherwise OpenMls and deserialization errors can happen
    pub async fn decrypt_message(
        &mut self,
        message: impl AsRef<[u8]>,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<(Option<Vec<u8>>, Option<u64>)> {
        let msg_in = openmls::framing::MlsMessageIn::try_from_bytes(message.as_ref()).map_err(MlsError::from)?;

        let parsed_message = self.group.parse_message(msg_in, backend).map_err(MlsError::from)?;

        let message = self
            .group
            .process_unverified_message(parsed_message, None, backend)
            .await
            .map_err(MlsError::from)?;

        let message = match message {
            ProcessedMessage::ApplicationMessage(app_msg) => (Some(app_msg.into_bytes()), None),
            ProcessedMessage::ProposalMessage(proposal) => {
                self.group.store_pending_proposal(*proposal);
                let epoch = self.group.epoch().as_u64();
                let total_members = self.group.members().len();
                let self_index = self.get_self_index(backend)?;
                let delay = calculate_delay(self_index, epoch, total_members).map_err(CryptoError::from)?;
                (None, Some(delay))
            }
            ProcessedMessage::StagedCommitMessage(staged_commit) => {
                self.group.merge_staged_commit(*staged_commit).map_err(MlsError::from)?;
                (None, None)
            }
        };

        self.persist_group_when_changed(backend, false).await?;

        Ok(message)
    }

    fn get_self_index(&self, backend: &MlsCryptoProvider) -> CryptoResult<usize> {
        let myself = self
            .group
            .key_package_ref()
            .ok_or(CryptoError::SelfKeypackageNotFound)?;

        // TODO: switch to `try_find` when stabilized
        self.group
            .members()
            .iter()
            .enumerate()
            .find_map(|(i, kp)| {
                kp.hash_ref(backend.crypto())
                    .ok()
                    .filter(|kpr| kpr == myself)
                    .map(|_| i)
            })
            .ok_or(CryptoError::SelfKeypackageNotFound)
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
    pub async fn commit_pending_proposals(
        &mut self,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<(MlsMessageOut, Option<Welcome>)> {
        let (message, welcome) = self
            .group
            .commit_to_pending_proposals(backend)
            .await
            .map_err(MlsError::from)?;
        self.group.merge_pending_commit().map_err(MlsError::from)?;

        self.persist_group_when_changed(backend, false).await?;

        Ok((message, welcome))
    }

    /// Encrypts an Application Message then serializes it to the TLS wire format
    ///
    /// # Arguments
    /// * `message` - the message as a byte array
    /// * `backend` - the KeyStore to read credentials from
    ///
    /// # Return type
    /// This method will return an encrypted TLS serialized message.
    ///
    /// # Errors
    /// Errors are originating from OpenMls and the KeyStore
    pub async fn encrypt_message(
        &mut self,
        message: impl AsRef<[u8]>,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Vec<u8>> {
        self.group
            .create_message(backend, message.as_ref())
            .await
            .map_err(MlsError::from)
            .and_then(|m| m.to_bytes().map_err(MlsError::from))
            .map_err(CryptoError::from)
    }

    /// Self updates the KeyPackage and automatically commits. Pending proposals will be commited
    ///
    /// # Arguments
    /// * `backend` - the KeyStore to read credentials from
    ///
    /// # Return type
    /// A tuple containing the message with the commit this call generated and an optional welcome
    /// message that will be present if there were pending add proposals to be commited
    ///
    /// # Errors
    /// Errors are originating from OpenMls and the KeyStore
    pub async fn update_keying_material(
        &mut self,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<(MlsMessageOut, Option<Welcome>)> {
        Ok(self.group.self_update(backend, None).await.map_err(MlsError::from)?)
    }

    async fn persist_group_when_changed(&mut self, backend: &MlsCryptoProvider, force: bool) -> CryptoResult<()> {
        if force || self.group.state_changed() == openmls::group::InnerState::Changed {
            let mut buf = vec![];
            self.group.save(&mut buf)?;

            use core_crypto_keystore::CryptoKeystoreMls as _;
            Ok(backend.key_store().mls_group_persist(&self.id, &buf).await?)
        } else {
            Ok(())
        }
    }

    pub(crate) async fn leave(
        &mut self,
        other_clients: &[ClientId],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsConversationLeaveMessage> {
        let crypto = backend.crypto();

        let other_clients_removal_commit = if !other_clients.is_empty() {
            let other_clients_slice: Vec<&[u8]> = other_clients.iter().map(|c| c.as_slice()).collect();
            let other_keypackages: Vec<_> = self
                .group
                .members()
                .into_iter()
                .filter(|m| other_clients_slice.contains(&m.credential().identity()))
                .filter_map(|m| m.hash_ref(crypto).ok())
                .collect();

            if !other_keypackages.is_empty() {
                let (other_clients_removal_commit, _) = self
                    .group
                    .remove_members(backend, other_keypackages.as_slice())
                    .await
                    .map_err(MlsError::from)?;

                self.group.merge_pending_commit().map_err(MlsError::from)?;

                Some(other_clients_removal_commit)
            } else {
                None
            }
        } else {
            None
        };

        let self_removal_proposal = self.group.leave_group(backend).await.map_err(MlsError::from)?;

        Ok(MlsConversationLeaveMessage {
            other_clients_removal_commit,
            self_removal_proposal,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::{ConversationId, MlsConversation, MlsConversationConfiguration};
    use crate::{
        credential::{CertificateBundle, CredentialSupplier},
        member::ConversationMember,
        prelude::MlsConversationCreationMessage,
        test_fixture_utils::*,
    };
    use mls_crypto_provider::MlsCryptoProvider;
    use openmls::prelude::KeyPackage;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[inline(always)]
    pub async fn init_keystore(identifier: &str) -> MlsCryptoProvider {
        MlsCryptoProvider::try_new_in_memory(identifier).await.unwrap()
    }

    pub mod create {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn create_self_conversation_should_succeed(credential: CredentialSupplier) {
            let conversation_id = conversation_id();
            let (alice_backend, mut alice) = alice(credential).await;

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
            let (alice_backend, mut alice) = alice(credential).await;
            let (bob_backend, bob) = bob(credential).await;

            let mut alice_group = MlsConversation::create(
                conversation_id.clone(),
                alice.local_client_mut(),
                MlsConversationConfiguration::default(),
                &alice_backend,
            )
            .await
            .unwrap();

            let conversation_creation_message = alice_group.add_members(&mut [bob], &alice_backend).await.unwrap();

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
            let (alice_backend, mut alice) = alice(credential).await;
            let mut bob_and_friends = Vec::with_capacity(99);

            for _ in 0..99 {
                let uuid = uuid::Uuid::new_v4();
                let backend = init_keystore(&uuid.hyphenated().to_string()).await;

                let (member, _) = ConversationMember::random_generate(&backend, credential).await.unwrap();
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
                bob_and_friends.iter().map(|(_, m)| m.clone()).collect();

            let conversation_creation_message = alice_group
                .add_members(&mut bob_and_friends_members, &alice_backend)
                .await
                .unwrap();

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
            let (alice_backend, mut alice) = alice(credential).await;
            let (bob_backend, bob) = bob(credential).await;
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

    pub mod add_members {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn can_add_members_to_conversation(credential: CredentialSupplier) {
            let conversation_id = conversation_id();
            let (alice_backend, mut alice) = alice(credential).await;
            let (bob_backend, bob) = bob(credential).await;

            let conversation_config = MlsConversationConfiguration::default();
            let mut alice_group = MlsConversation::create(
                conversation_id.clone(),
                alice.local_client_mut(),
                conversation_config,
                &alice_backend,
            )
            .await
            .unwrap();

            let conversation_creation_message = alice_group.add_members(&mut [bob], &alice_backend).await.unwrap();

            assert_eq!(alice_group.id, conversation_id);
            assert_eq!(alice_group.group.group_id().as_slice(), conversation_id);
            assert_eq!(alice_group.members().len(), 2);

            let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message;

            let conversation_config = MlsConversationConfiguration::default();

            let mut bob_group = MlsConversation::from_welcome_message(welcome, conversation_config, &bob_backend)
                .await
                .unwrap();

            assert_eq!(bob_group.id(), alice_group.id());

            let msg = b"Hello";
            let alice_can_send_message = alice_group.encrypt_message(msg, &alice_backend).await;
            assert!(alice_can_send_message.is_ok());
            let bob_can_send_message = bob_group.encrypt_message(msg, &bob_backend).await;
            assert!(bob_can_send_message.is_ok());
        }
    }

    pub mod remove_members {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn alice_can_remove_bob_from_conversation(credential: CredentialSupplier) {
            let conversation_id = conversation_id();
            let (alice_backend, mut alice) = alice(credential).await;
            let (bob_backend, bob) = bob(credential).await;

            let conversation_config = MlsConversationConfiguration::default();

            let mut alice_group = MlsConversation::create(
                conversation_id,
                alice.local_client_mut(),
                conversation_config,
                &alice_backend,
            )
            .await
            .unwrap();

            let messages = alice_group
                .add_members(&mut [bob.clone()], &alice_backend)
                .await
                .unwrap();

            assert_eq!(alice_group.members().len(), 2);

            let mut bob_group = MlsConversation::from_welcome_message(
                messages.welcome,
                MlsConversationConfiguration::default(),
                &bob_backend,
            )
            .await
            .unwrap();

            let remove_result = alice_group
                .remove_members(bob.clients().cloned().collect::<Vec<_>>().as_slice(), &alice_backend)
                .await
                .unwrap();

            bob_group
                .decrypt_message(remove_result.to_bytes().unwrap(), &bob_backend)
                .await
                .unwrap();

            assert_eq!(alice_group.members().len(), 1);

            let alice_can_send_message = alice_group.encrypt_message(b"me", &alice_backend).await;
            assert!(alice_can_send_message.is_ok());
            let bob_cannot_send_message = alice_group.encrypt_message(b"me", &bob_backend).await;
            assert!(bob_cannot_send_message.is_err());
        }
    }

    pub mod encrypting_messages {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn can_roundtrip_message_in_1_1_conversation(credential: CredentialSupplier) {
            let conversation_id = conversation_id();
            let (alice_backend, mut alice) = alice(credential).await;
            let (bob_backend, bob) = bob(credential).await;
            let configuration = MlsConversationConfiguration::default();

            let mut alice_group = MlsConversation::create(
                conversation_id.clone(),
                alice.local_client_mut(),
                configuration,
                &alice_backend,
            )
            .await
            .unwrap();
            let conversation_creation_message = alice_group.add_members(&mut [bob], &alice_backend).await.unwrap();
            assert_eq!(alice_group.id, conversation_id);
            assert_eq!(alice_group.group.group_id().as_slice(), conversation_id);
            assert_eq!(alice_group.members().len(), 2);

            let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message;

            let mut bob_group =
                MlsConversation::from_welcome_message(welcome, MlsConversationConfiguration::default(), &bob_backend)
                    .await
                    .unwrap();

            let original_message = b"Hello World!";

            // alice -> bob
            let encrypted_message = alice_group
                .encrypt_message(original_message, &alice_backend)
                .await
                .unwrap();
            assert_ne!(&encrypted_message, original_message);
            let roundtripped_message = bob_group
                .decrypt_message(&encrypted_message, &bob_backend)
                .await
                .unwrap()
                .0
                .unwrap();
            assert_eq!(original_message, roundtripped_message.as_slice());

            // bob -> alice
            let encrypted_message = bob_group
                .encrypt_message(roundtripped_message, &bob_backend)
                .await
                .unwrap();
            assert_ne!(&encrypted_message, original_message);
            let roundtripped_message = alice_group
                .decrypt_message(&encrypted_message, &alice_backend)
                .await
                .unwrap()
                .0
                .unwrap();
            assert_eq!(original_message, roundtripped_message.as_slice());
        }
    }

    pub mod leave {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn can_leave_conversation(credential: CredentialSupplier) {
            let alice_backend = init_keystore("alice").await;
            let alice2_backend = init_keystore("alice2").await;
            let bob_backend = init_keystore("bob").await;
            let charlie_backend = init_keystore("charlie").await;

            let (mut alice, _) = ConversationMember::random_generate(&alice_backend, credential)
                .await
                .unwrap();
            let (alice2, _) = ConversationMember::random_generate(&alice2_backend, credential)
                .await
                .unwrap();
            let (bob, _) = ConversationMember::random_generate(&bob_backend, credential)
                .await
                .unwrap();
            let (charlie, _) = ConversationMember::random_generate(&charlie_backend, credential)
                .await
                .unwrap();

            let uuid = uuid::Uuid::new_v4();
            let conversation_id = ConversationId::from(format!("{}@conversations.wire.com", uuid.hyphenated()));

            let conversation_config = MlsConversationConfiguration { ..Default::default() };

            let mut alice_group = MlsConversation::create(
                conversation_id.clone(),
                alice.local_client_mut(),
                conversation_config,
                &alice_backend,
            )
            .await
            .unwrap();

            let conversation_creation_message = alice_group
                .add_members(&mut [alice2, bob, charlie], &alice_backend)
                .await
                .unwrap();

            assert_eq!(alice_group.id, conversation_id);
            assert_eq!(alice_group.group.group_id().as_slice(), conversation_id);
            assert_eq!(alice_group.members().len(), 4);

            let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message;

            let conversation_config = MlsConversationConfiguration::default();
            let mut bob_group =
                MlsConversation::from_welcome_message(welcome.clone(), conversation_config.clone(), &bob_backend)
                    .await
                    .unwrap();
            let mut charlie_group =
                MlsConversation::from_welcome_message(welcome.clone(), conversation_config.clone(), &charlie_backend)
                    .await
                    .unwrap();
            let mut alice2_group = MlsConversation::from_welcome_message(welcome, conversation_config, &alice2_backend)
                .await
                .unwrap();

            assert_eq!(bob_group.id(), alice_group.id());
            assert_eq!(alice2_group.id(), alice_group.id());
            assert_eq!(charlie_group.id(), alice_group.id());
            assert_eq!(alice2_group.members().len(), 4);
            assert_eq!(bob_group.members().len(), 4);
            assert_eq!(charlie_group.members().len(), 4);

            let message = alice2_group
                .leave(&[alice.id().clone().into()], &alice2_backend)
                .await
                .unwrap();

            // Only the `other_clients` have been effectively removed as of now
            // Removing alice2 will only be effective once bob or charlie commit the removal proposal that alice2 leaves
            assert_eq!(alice2_group.members().len(), 3);
            bob_group
                .decrypt_message(
                    message
                        .other_clients_removal_commit
                        .as_ref()
                        .unwrap()
                        .to_bytes()
                        .unwrap(),
                    &bob_backend,
                )
                .await
                .unwrap();

            charlie_group
                .decrypt_message(
                    message
                        .other_clients_removal_commit
                        .as_ref()
                        .unwrap()
                        .to_bytes()
                        .unwrap(),
                    &bob_backend,
                )
                .await
                .unwrap();

            assert_eq!(bob_group.members().len(), 3);
            assert_eq!(charlie_group.members().len(), 3);

            alice_group
                .decrypt_message(
                    message
                        .other_clients_removal_commit
                        .as_ref()
                        .unwrap()
                        .to_bytes()
                        .unwrap(),
                    &alice_backend,
                )
                .await
                .unwrap();

            // alice_group is now unuseable
            assert!(alice_group.encrypt_message(b"test", &alice_backend).await.is_err());
            assert!(!alice_group.group.is_active());

            bob_group
                .decrypt_message(message.self_removal_proposal.to_bytes().unwrap(), &bob_backend)
                .await
                .unwrap();

            let (removal_commit_from_bob, _) = bob_group.commit_pending_proposals(&bob_backend).await.unwrap();

            charlie_group
                .decrypt_message(message.self_removal_proposal.to_bytes().unwrap(), &bob_backend)
                .await
                .unwrap();

            charlie_group
                .decrypt_message(removal_commit_from_bob.to_bytes().unwrap(), &charlie_backend)
                .await
                .unwrap();
            alice2_group
                .decrypt_message(removal_commit_from_bob.to_bytes().unwrap(), &alice2_backend)
                .await
                .unwrap();

            // Check that alice2 understood that she's not welcome anymore (sorry alice2)
            assert!(!alice2_group.group.is_active());

            assert_eq!(charlie_group.members().len(), 2);
            assert_eq!(bob_group.members().len(), 2);
        }
    }

    pub mod update_keying_material {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_update_keying_material_conversation_group(credential: CredentialSupplier) {
            // create bob
            let conversation_id = b"conversation".to_vec();
            let (alice_backend, mut alice) = alice(credential).await;
            let (bob_backend, bob) = bob(credential).await;

            let bob_key = bob.local_client().keypackages(&bob_backend).await.unwrap()[0].clone();

            let configuration = MlsConversationConfiguration::default();

            // create new group and add bob
            let mut alice_group = MlsConversation::create(
                conversation_id,
                alice.local_client_mut(),
                configuration.clone(),
                &alice_backend,
            )
            .await
            .unwrap();

            let add_message = alice_group.add_members(&mut [bob], &alice_backend).await.unwrap();

            assert_eq!(alice_group.members().len(), 2);

            let MlsConversationCreationMessage { welcome, .. } = add_message;

            // creating group on bob's side
            let mut bob_group = MlsConversation::from_welcome_message(welcome, configuration, &bob_backend)
                .await
                .unwrap();

            // ensuring both sides can encrypt messages
            let msg = b"Hello";
            let alice_can_send_message = alice_group.encrypt_message(msg, &alice_backend).await;
            assert!(alice_can_send_message.is_ok());
            let bob_can_send_message = bob_group.encrypt_message(msg, &bob_backend).await;
            assert!(bob_can_send_message.is_ok());

            let bob_keys = bob_group
                .group
                .members()
                .into_iter()
                .cloned()
                .collect::<Vec<KeyPackage>>();

            let alice_keys = alice_group
                .group
                .members()
                .into_iter()
                .cloned()
                .collect::<Vec<KeyPackage>>();

            assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

            let alice_key = alice_keys.into_iter().find(|k| *k != bob_key).unwrap();

            // proposing the key update for alice
            let (msg_out, welcome) = alice_group.update_keying_material(&alice_backend).await.unwrap();
            assert!(welcome.is_none());

            alice_group.group.merge_pending_commit().unwrap();

            let alice_new_keys = alice_group
                .group
                .members()
                .into_iter()
                .cloned()
                .collect::<Vec<KeyPackage>>();

            assert!(!alice_new_keys.contains(&alice_key));

            // receiving the commit on bob's side (updating key from alice)
            assert!(bob_group
                .decrypt_message(&msg_out.to_bytes().unwrap(), &bob_backend)
                .await
                .unwrap()
                .0
                .is_none());

            let bob_new_keys = bob_group
                .group
                .members()
                .into_iter()
                .cloned()
                .collect::<Vec<KeyPackage>>();

            assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

            // ensuring both can encrypt messages
            let bob_can_send_message = bob_group.encrypt_message(msg, &bob_backend).await;
            assert!(bob_can_send_message.is_ok());

            let alice_can_send_message = alice_group.encrypt_message(msg, &alice_backend).await;
            assert!(alice_can_send_message.is_ok());
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_update_keying_material_group_pending_commit(credential: CredentialSupplier) {
            // create members
            let conversation_id = conversation_id();
            let (alice_backend, mut alice) = alice(credential).await;
            let (bob_backend, bob) = bob(credential).await;
            let (charlie_backend, charlie) = charlie(credential).await;

            let bob_key = bob.local_client().keypackages(&bob_backend).await.unwrap()[0].clone();
            let charlie_key = charlie.local_client().keypackages(&charlie_backend).await.unwrap()[0].clone();

            let configuration = MlsConversationConfiguration::default();

            // create group
            let mut alice_group = MlsConversation::create(
                conversation_id,
                alice.local_client_mut(),
                configuration.clone(),
                &alice_backend,
            )
            .await
            .unwrap();

            // adding bob and creating the group on bob's side
            let add_message = alice_group.add_members(&mut [bob], &alice_backend).await.unwrap();

            assert_eq!(alice_group.members().len(), 2);

            let MlsConversationCreationMessage { welcome, .. } = add_message;

            let mut bob_group = MlsConversation::from_welcome_message(welcome, configuration.clone(), &bob_backend)
                .await
                .unwrap();

            let bob_keys = bob_group
                .group
                .members()
                .into_iter()
                .cloned()
                .collect::<Vec<KeyPackage>>();

            let alice_keys = alice_group
                .group
                .members()
                .into_iter()
                .cloned()
                .collect::<Vec<KeyPackage>>();

            // checking that the members on both sides are the same
            assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

            let alice_key = alice_keys.into_iter().find(|k| *k != bob_key).unwrap();

            // proposing adding charlie
            let proposal_response = alice_group
                .group
                .propose_add_member(&alice_backend, &charlie_key)
                .await
                .unwrap();

            // receiving the proposal on bob's side
            assert!(bob_group
                .decrypt_message(&proposal_response.to_bytes().unwrap(), &bob_backend)
                .await
                .unwrap()
                .0
                .is_none());

            assert_eq!(alice_group.group.members().len(), 2);

            // performing an update on the alice's key. this should generate a welcome for charlie
            let (message, welcome) = alice_group.update_keying_material(&alice_backend).await.unwrap();
            assert!(welcome.is_some());

            alice_group.group.merge_pending_commit().unwrap();

            // create the group on charlie's side
            let charlie_welcome = welcome.unwrap();
            let mut charlie_group =
                MlsConversation::from_welcome_message(charlie_welcome, configuration, &charlie_backend)
                    .await
                    .unwrap();

            assert_eq!(alice_group.members().len(), 3);
            assert_eq!(charlie_group.members().len(), 3);
            // bob still didn't receive the message with the updated key and charlie's addition
            assert_eq!(bob_group.members().len(), 2);

            let alice_new_keys = alice_group
                .group
                .members()
                .into_iter()
                .cloned()
                .collect::<Vec<KeyPackage>>();

            assert!(!alice_new_keys.contains(&alice_key));

            // receiving the key update and the charlie's addition to the group
            assert!(bob_group
                .decrypt_message(&message.to_bytes().unwrap(), &bob_backend)
                .await
                .unwrap()
                .0
                .is_none());
            assert_eq!(bob_group.members().len(), 3);

            let bob_new_keys = bob_group
                .group
                .members()
                .into_iter()
                .cloned()
                .collect::<Vec<KeyPackage>>();

            assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

            // ensure all parties can encrypt messages
            let msg = b"Hello World";
            let bob_can_send_message = bob_group.encrypt_message(msg, &bob_backend).await;
            assert!(bob_can_send_message.is_ok());

            let alice_can_send_message = alice_group.encrypt_message(msg, &alice_backend).await;
            assert!(alice_can_send_message.is_ok());

            let charlie_can_send_message = charlie_group.encrypt_message(msg, &charlie_backend).await;
            assert!(charlie_can_send_message.is_ok());
        }
    }

    fn conversation_id() -> Vec<u8> {
        let uuid = uuid::Uuid::new_v4();
        ConversationId::from(format!("{}@conversations.wire.com", uuid.hyphenated()))
    }

    async fn alice(credential: CredentialSupplier) -> (MlsCryptoProvider, ConversationMember) {
        let alice_backend = init_keystore("alice").await;
        let (alice, _) = ConversationMember::random_generate(&alice_backend, credential)
            .await
            .unwrap();
        (alice_backend, alice)
    }

    async fn bob(credential: CredentialSupplier) -> (MlsCryptoProvider, ConversationMember) {
        let bob_backend = init_keystore("bob").await;
        let (bob, _) = ConversationMember::random_generate(&bob_backend, credential)
            .await
            .unwrap();
        (bob_backend, bob)
    }

    async fn charlie(credential: CredentialSupplier) -> (MlsCryptoProvider, ConversationMember) {
        let charlie_backend = init_keystore("charlie").await;
        let (charlie, _) = ConversationMember::random_generate(&charlie_backend, credential)
            .await
            .unwrap();
        (charlie_backend, charlie)
    }
}
