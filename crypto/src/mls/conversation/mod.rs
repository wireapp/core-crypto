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

use config::MlsConversationConfiguration;
use core_crypto_keystore::CryptoKeystoreMls;
use itertools::Itertools as _;
use log::trace;
use mls_crypto_provider::{CryptoKeystore, MlsCryptoProvider};
use openmls::{
    group::MlsGroup,
    prelude::{Credential, CredentialWithKey, LeafNodeIndex, Proposal, SignaturePublicKey},
};
use openmls_traits::OpenMlsCryptoProvider;
use openmls_traits::types::SignatureScheme;
use std::{collections::HashMap, sync::Arc};
use std::{collections::HashSet, ops::Deref};

use crate::{
    KeystoreError, LeafError, MlsError, RecursiveError,
    mls::Session,
    prelude::{ClientId, E2eiConversationState, MlsCiphersuite, MlsCredentialType, WireIdentity},
};

pub(crate) mod commit;
mod commit_delay;
pub(crate) mod config;
pub(crate) mod conversation_guard;
mod duplicate;
#[cfg(test)]
mod durability;
mod error;
pub(crate) mod group_info;
mod immutable_conversation;
pub(crate) mod merge;
mod orphan_welcome;
mod own_commit;
pub(crate) mod pending_conversation;
pub(crate) mod proposal;
mod renew;
pub(crate) mod welcome;
mod wipe;

use crate::mls::HasSessionAndCrypto;
use crate::mls::credential::ext::CredentialExt as _;
use crate::prelude::user_id::UserId;
pub use conversation_guard::ConversationGuard;
pub use error::{Error, Result};
pub use immutable_conversation::ImmutableConversation;

use super::credential::CredentialBundle;

/// The base layer for [Conversation].
/// The trait is only exposed internally.
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub(crate) trait ConversationWithMls<'a> {
    /// [Session] or [TransactionContext] both implement [HasSessionAndCrypto].
    type Context: HasSessionAndCrypto;

    type Conversation: Deref<Target = MlsConversation> + Send;

    async fn context(&self) -> Result<Self::Context>;

    async fn conversation(&'a self) -> Self::Conversation;

    async fn crypto_provider(&self) -> Result<MlsCryptoProvider> {
        self.context()
            .await?
            .crypto_provider()
            .await
            .map_err(RecursiveError::mls("getting mls provider"))
            .map_err(Into::into)
    }

    async fn session(&self) -> Result<Session> {
        self.context()
            .await?
            .session()
            .await
            .map_err(RecursiveError::mls("getting mls client"))
            .map_err(Into::into)
    }
}

/// The `Conversation` trait provides a set of operations that can be done on
/// an **immutable** conversation.
// We keep the super trait internal intentionally, as it is not meant to be used by the public API,
// hence #[expect(private_bounds)].
#[expect(private_bounds)]
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait Conversation<'a>: ConversationWithMls<'a> {
    /// Returns the epoch of a given conversation
    async fn epoch(&'a self) -> u64 {
        self.conversation().await.group().epoch().as_u64()
    }

    /// Returns the ciphersuite of a given conversation
    async fn ciphersuite(&'a self) -> MlsCiphersuite {
        self.conversation().await.ciphersuite()
    }

    /// Derives a new key from the one in the group, to be used elsewhere.
    ///
    /// # Arguments
    /// * `key_length` - the length of the key to be derived. If the value is higher than the
    ///     bounds of `u16` or the context hash * 255, an error will be returned
    ///
    /// # Errors
    /// OpenMls secret generation error
    async fn export_secret_key(&'a self, key_length: usize) -> Result<Vec<u8>> {
        const EXPORTER_LABEL: &str = "exporter";
        const EXPORTER_CONTEXT: &[u8] = &[];
        let backend = self.crypto_provider().await?;
        let inner = self.conversation().await;
        inner
            .group()
            .export_secret(&backend, EXPORTER_LABEL, EXPORTER_CONTEXT, key_length)
            .map_err(MlsError::wrap("exporting secret key"))
            .map_err(Into::into)
    }

    /// Exports the clients from a conversation
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    async fn get_client_ids(&'a self) -> Vec<ClientId> {
        let inner = self.conversation().await;
        inner
            .group()
            .members()
            .map(|kp| ClientId::from(kp.credential.identity()))
            .collect()
    }

    /// Returns the raw public key of the single external sender present in this group.
    /// This should be used to initialize a subconversation
    async fn get_external_sender(&'a self) -> Result<Vec<u8>> {
        let inner = self.conversation().await;
        let ext_senders = inner
            .group()
            .group_context_extensions()
            .external_senders()
            .ok_or(Error::MissingExternalSenderExtension)?;
        let ext_sender = ext_senders.first().ok_or(Error::MissingExternalSenderExtension)?;
        let ext_sender_public_key = ext_sender.signature_key().as_slice().to_vec();
        Ok(ext_sender_public_key)
    }

    /// Indicates when to mark a conversation as not verified i.e. when not all its members have a X509
    /// Credential generated by Wire's end-to-end identity enrollment
    async fn e2ei_conversation_state(&'a self) -> Result<E2eiConversationState> {
        let backend = self.crypto_provider().await?;
        let authentication_service = backend.authentication_service();
        authentication_service.refresh_time_of_interest().await;
        let inner = self.conversation().await;
        let state = Session::compute_conversation_state(
            inner.ciphersuite(),
            inner.group.members_credentials(),
            MlsCredentialType::X509,
            authentication_service.borrow().await.as_ref(),
        )
        .await;
        Ok(state)
    }

    /// From a given conversation, get the identity of the members supplied. Identity is only present for
    /// members with a Certificate Credential (after turning on end-to-end identity).
    /// If no member has a x509 certificate, it will return an empty Vec
    async fn get_device_identities(&'a self, device_ids: &[ClientId]) -> Result<Vec<WireIdentity>> {
        if device_ids.is_empty() {
            return Err(Error::CallerError(
                "This function accepts a list of IDs as a parameter, but that list was empty.",
            ));
        }
        let mls_provider = self.crypto_provider().await?;
        let auth_service = mls_provider.authentication_service();
        auth_service.refresh_time_of_interest().await;
        let auth_service = auth_service.borrow().await;
        let env = auth_service.as_ref();
        let conversation = self.conversation().await;
        conversation
            .members_with_key()
            .into_iter()
            .filter(|(id, _)| device_ids.contains(&ClientId::from(id.as_slice())))
            .map(|(_, c)| {
                c.extract_identity(conversation.ciphersuite(), env)
                    .map_err(RecursiveError::mls_credential("extracting identity"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// From a given conversation, get the identity of the users (device holders) supplied.
    /// Identity is only present for devices with a Certificate Credential (after turning on end-to-end identity).
    /// If no member has a x509 certificate, it will return an empty Vec.
    ///
    /// Returns a Map with all the identities for a given users. Consumers are then recommended to
    /// reduce those identities to determine the actual status of a user.
    async fn get_user_identities(&'a self, user_ids: &[String]) -> Result<HashMap<String, Vec<WireIdentity>>> {
        if user_ids.is_empty() {
            return Err(Error::CallerError(
                "This function accepts a list of IDs as a parameter, but that list was empty.",
            ));
        }
        let mls_provider = self.crypto_provider().await?;
        let auth_service = mls_provider.authentication_service();
        auth_service.refresh_time_of_interest().await;
        let auth_service = auth_service.borrow().await;
        let env = auth_service.as_ref();
        let conversation = self.conversation().await;
        let user_ids = user_ids.iter().map(|uid| uid.as_bytes()).collect::<Vec<_>>();

        conversation
            .members_with_key()
            .iter()
            .filter_map(|(id, c)| UserId::try_from(id.as_slice()).ok().zip(Some(c)))
            .filter(|(uid, _)| user_ids.contains(uid))
            .map(|(uid, c)| {
                let uid = String::try_from(uid).map_err(RecursiveError::mls_client("getting user identities"))?;
                let identity = c
                    .extract_identity(conversation.ciphersuite(), env)
                    .map_err(RecursiveError::mls_credential("extracting identity"))?;
                Ok((uid, identity))
            })
            .process_results(|iter| iter.into_group_map())
    }

    /// Generate a new [`crate::prelude::HistorySecret`].
    ///
    /// This is useful when it's this client's turn to generate a new history client.
    ///
    /// The generated secret is cryptographically unrelated to the current CoreCrypto client.
    async fn generate_history_secret(&'a self) -> Result<crate::prelude::HistorySecret> {
        let ciphersuite = self.ciphersuite().await;
        crate::ephemeral::generate_history_secret(ciphersuite)
            .await
            .map_err(RecursiveError::root("generating history secret"))
            .map_err(Into::into)
    }

    /// Check if history sharing is enabled, i.e., if any of the conversation members have a [ClientId] starting
    /// with [crate::prelude::HISTORY_CLIENT_ID_PREFIX].
    async fn is_history_sharing_enabled(&'a self) -> bool {
        self.get_client_ids()
            .await
            .iter()
            .any(|client_id| client_id.starts_with(crate::ephemeral::HISTORY_CLIENT_ID_PREFIX.as_bytes()))
    }
}

impl<'a, T: ConversationWithMls<'a>> Conversation<'a> for T {}

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
        author_client: &Session,
        creator_credential_type: MlsCredentialType,
        configuration: MlsConversationConfiguration,
        backend: &MlsCryptoProvider,
    ) -> Result<Self> {
        let (cs, ct) = (configuration.ciphersuite, creator_credential_type);
        let cb = author_client
            .get_most_recent_or_create_credential_bundle(backend, cs.signature_algorithm(), ct)
            .await
            .map_err(RecursiveError::mls_client("getting or creating credential bundle"))?;

        let group = MlsGroup::new_with_group_id(
            backend,
            &cb.signature_key,
            &configuration.as_openmls_default_configuration()?,
            openmls::prelude::GroupId::from_slice(id.as_slice()),
            cb.to_mls_credential_with_key(),
        )
        .await
        .map_err(MlsError::wrap("creating group with id"))?;

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
    ) -> Result<Self> {
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
    pub(crate) fn from_serialized_state(buf: Vec<u8>, parent_id: Option<ConversationId>) -> Result<Self> {
        let group: MlsGroup =
            core_crypto_keystore::deser(&buf).map_err(KeystoreError::wrap("deserializing group state"))?;
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

    pub(crate) fn group(&self) -> &MlsGroup {
        &self.group
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

    /// Get actual group members and subtract pending remove proposals
    pub fn members_in_next_epoch(&self) -> Vec<ClientId> {
        let pending_removals = self.pending_removals();
        let existing_clients = self
            .group
            .members()
            .filter_map(|kp| {
                if !pending_removals.contains(&kp.index) {
                    Some(kp.credential.identity().into())
                } else {
                    trace!(client_index:% = kp.index; "Client is pending removal");
                    None
                }
            })
            .collect::<HashSet<_>>();
        existing_clients.into_iter().collect()
    }

    /// Gather pending remove proposals
    fn pending_removals(&self) -> Vec<LeafNodeIndex> {
        self.group
            .pending_proposals()
            .filter_map(|proposal| match proposal.proposal() {
                Proposal::Remove(remove) => Some(remove.removed()),
                _ => None,
            })
            .collect::<Vec<_>>()
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

    pub(crate) async fn persist_group_when_changed(&mut self, keystore: &CryptoKeystore, force: bool) -> Result<()> {
        if force || self.group.state_changed() == openmls::group::InnerState::Changed {
            keystore
                .mls_group_persist(
                    &self.id,
                    &core_crypto_keystore::ser(&self.group).map_err(KeystoreError::wrap("serializing group state"))?,
                    self.parent_id.as_deref(),
                )
                .await
                .map_err(KeystoreError::wrap("persisting mls group"))?;

            self.group.set_state(openmls::group::InnerState::Persisted);
        }

        Ok(())
    }

    pub(crate) fn own_credential_type(&self) -> Result<MlsCredentialType> {
        Ok(self
            .group
            .own_leaf_node()
            .ok_or(Error::MlsGroupInvalidState("own_leaf_node not present in group"))?
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

    pub(crate) async fn find_current_credential_bundle(&self, client: &Session) -> Result<Arc<CredentialBundle>> {
        let own_leaf = self.group.own_leaf().ok_or(LeafError::InternalMlsError)?;
        let sc = self.ciphersuite().signature_algorithm();
        let ct = self
            .own_credential_type()
            .map_err(RecursiveError::mls_conversation("getting own credential type"))?;

        client
            .find_credential_bundle_by_public_key(sc, ct, own_leaf.signature_key())
            .await
            .map_err(RecursiveError::mls_client("finding current credential bundle"))
            .map_err(Into::into)
    }

    pub(crate) async fn find_most_recent_credential_bundle(&self, client: &Session) -> Result<Arc<CredentialBundle>> {
        let sc = self.ciphersuite().signature_algorithm();
        let ct = self
            .own_credential_type()
            .map_err(RecursiveError::mls_conversation("getting own credential type"))?;

        client
            .find_most_recent_credential_bundle(sc, ct)
            .await
            .map_err(RecursiveError::mls_client("finding most recent credential bundle"))
            .map_err(Into::into)
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;

    impl MlsConversation {
        pub fn signature_keys(&self) -> impl Iterator<Item = SignaturePublicKey> + '_ {
            self.group
                .members()
                .map(|m| m.signature_key)
                .map(|mpk| SignaturePublicKey::from(mpk.as_slice()))
        }

        pub fn encryption_keys(&self) -> impl Iterator<Item = Vec<u8>> + '_ {
            self.group.members().map(|m| m.encryption_key)
        }

        pub fn extensions(&self) -> &openmls::prelude::Extensions {
            self.group.export_group_context().extensions()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[apply(all_cred_cipher)]
    pub async fn create_self_conversation_should_succeed(case: TestContext) {
        let [alice] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;
            assert_eq!(1, conversation.member_count().await);
            let alice_can_send_message = conversation.guard().await.encrypt_message(b"me").await;
            assert!(alice_can_send_message.is_ok());
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    pub async fn create_1_1_conversation_should_succeed(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob]).await;
            assert_eq!(2, conversation.member_count().await);
            assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    pub async fn create_many_people_conversation(case: TestContext) {
        const SIZE_PLUS_1: usize = GROUP_SAMPLE_SIZE + 1;
        let alice_and_friends = case.sessions::<SIZE_PLUS_1>().await;
        Box::pin(async move {
            let alice = &alice_and_friends[0];
            let conversation = case.create_conversation([alice]).await;

            let bob_and_friends = &alice_and_friends[1..];
            let conversation = conversation.invite_notify(bob_and_friends).await;

            assert_eq!(conversation.member_count().await, 1 + GROUP_SAMPLE_SIZE);
            assert!(conversation.is_functional_and_contains(&alice_and_friends).await);
        })
        .await;
    }

    mod wire_identity_getters {
        use super::Error;
        use crate::mls::conversation::Conversation;
        use crate::prelude::{ClientId, MlsCredentialType};
        use crate::{
            prelude::{DeviceStatus, E2eiConversationState},
            test_utils::*,
        };

        async fn all_identities_check<'a, C, const N: usize>(
            conversation: &'a C,
            user_ids: &[String; N],
            expected_sizes: [usize; N],
        ) where
            C: Conversation<'a> + Sync,
        {
            let all_identities = conversation.get_user_identities(user_ids).await.unwrap();
            assert_eq!(all_identities.len(), N);
            for (expected_size, user_id) in expected_sizes.into_iter().zip(user_ids.iter()) {
                let alice_identities = all_identities.get(user_id).unwrap();
                assert_eq!(alice_identities.len(), expected_size);
            }
            // Not found
            let not_found = conversation
                .get_user_identities(&["aaaaaaaaaaaaa".to_string()])
                .await
                .unwrap();
            assert!(not_found.is_empty());

            // Invalid usage
            let invalid = conversation.get_user_identities(&[]).await;
            assert!(matches!(invalid.unwrap_err(), Error::CallerError(_)));
        }

        async fn check_identities_device_status<'a, C, const N: usize>(
            conversation: &'a C,
            client_ids: &[ClientId; N],
            name_status: &[(impl ToString, DeviceStatus); N],
        ) where
            C: Conversation<'a> + Sync,
        {
            let mut identities = conversation.get_device_identities(client_ids).await.unwrap();

            for (user_name, status) in name_status.iter() {
                let client_identity = identities.remove(
                    identities
                        .iter()
                        .position(|i| i.x509_identity.as_ref().unwrap().display_name == user_name.to_string())
                        .unwrap(),
                );
                assert_eq!(client_identity.status, *status);
            }
            assert!(identities.is_empty());

            assert_eq!(
                conversation.e2ei_conversation_state().await.unwrap(),
                E2eiConversationState::NotVerified
            );
        }

        #[async_std::test]
        async fn should_read_device_identities() {
            let case = TestContext::default_x509();

            let [alice_android, alice_ios] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice_android, &alice_ios]).await;

                let (android_id, ios_id) = (alice_android.get_client_id().await, alice_ios.get_client_id().await);

                let mut android_ids = conversation
                    .guard()
                    .await
                    .get_device_identities(&[android_id.clone(), ios_id.clone()])
                    .await
                    .unwrap();
                android_ids.sort_by(|a, b| a.client_id.cmp(&b.client_id));
                assert_eq!(android_ids.len(), 2);
                let mut ios_ids = conversation
                    .guard_of(&alice_ios)
                    .await
                    .get_device_identities(&[android_id.clone(), ios_id.clone()])
                    .await
                    .unwrap();
                ios_ids.sort_by(|a, b| a.client_id.cmp(&b.client_id));
                assert_eq!(ios_ids.len(), 2);

                assert_eq!(android_ids, ios_ids);

                let android_identities = conversation
                    .guard()
                    .await
                    .get_device_identities(&[android_id])
                    .await
                    .unwrap();
                let android_id = android_identities.first().unwrap();
                assert_eq!(
                    android_id.client_id.as_bytes(),
                    alice_android.transaction.client_id().await.unwrap().0.as_slice()
                );

                let ios_identities = conversation
                    .guard()
                    .await
                    .get_device_identities(&[ios_id])
                    .await
                    .unwrap();
                let ios_id = ios_identities.first().unwrap();
                assert_eq!(
                    ios_id.client_id.as_bytes(),
                    alice_ios.transaction.client_id().await.unwrap().0.as_slice()
                );

                let invalid = conversation.guard().await.get_device_identities(&[]).await;
                assert!(matches!(invalid.unwrap_err(), Error::CallerError(_)));
            })
            .await
        }

        #[async_std::test]
        async fn should_read_revoked_device_cross_signed() {
            let case = TestContext::default_x509();
            let alice_user_id = uuid::Uuid::new_v4();
            let bob_user_id = uuid::Uuid::new_v4();
            let rupert_user_id = uuid::Uuid::new_v4();
            let john_user_id = uuid::Uuid::new_v4();
            let dilbert_user_id = uuid::Uuid::new_v4();

            let [alice_client_id] = case.x509_client_ids_for_user(&alice_user_id);
            let [bob_client_id] = case.x509_client_ids_for_user(&bob_user_id);
            let [rupert_client_id] = case.x509_client_ids_for_user(&rupert_user_id);
            let [john_client_id] = case.x509_client_ids_for_user(&john_user_id);
            let [dilbert_client_id] = case.x509_client_ids_for_user(&dilbert_user_id);

            let sessions = case
                .sessions_x509_cross_signed_with_client_ids_and_revocation(
                    [alice_client_id, bob_client_id, rupert_client_id],
                    [john_client_id, dilbert_client_id],
                    &[dilbert_user_id.to_string(), rupert_user_id.to_string()],
                )
                .await;

            Box::pin(async move {
                let ([alice, bob, rupert], [john, dilbert]) = &sessions;
                let mut sessions = sessions.0.iter().chain(sessions.1.iter());
                let conversation = case.create_conversation(&mut sessions).await;

                let (alice_id, bob_id, rupert_id, john_id, dilbert_id) = (
                    alice.get_client_id().await,
                    bob.get_client_id().await,
                    rupert.get_client_id().await,
                    john.get_client_id().await,
                    dilbert.get_client_id().await,
                );

                let client_ids = [alice_id, bob_id, rupert_id, john_id, dilbert_id];
                let name_status = [
                    (alice_user_id, DeviceStatus::Valid),
                    (bob_user_id, DeviceStatus::Valid),
                    (rupert_user_id, DeviceStatus::Revoked),
                    (john_user_id, DeviceStatus::Valid),
                    (dilbert_user_id, DeviceStatus::Revoked),
                ];
                // Do it a multiple times to avoid WPB-6904 happening again
                for _ in 0..2 {
                    for session in sessions.clone() {
                        let conversation = conversation.guard_of(session).await;
                        check_identities_device_status(&conversation, &client_ids, &name_status).await;
                    }
                }
            })
            .await
        }

        #[async_std::test]
        async fn should_read_revoked_device() {
            let case = TestContext::default_x509();
            let rupert_user_id = uuid::Uuid::new_v4();
            let bob_user_id = uuid::Uuid::new_v4();
            let alice_user_id = uuid::Uuid::new_v4();

            let [rupert_client_id] = case.x509_client_ids_for_user(&rupert_user_id);
            let [alice_client_id] = case.x509_client_ids_for_user(&alice_user_id);
            let [bob_client_id] = case.x509_client_ids_for_user(&bob_user_id);

            let sessions = case
                .sessions_x509_with_client_ids_and_revocation(
                    [alice_client_id.clone(), bob_client_id.clone(), rupert_client_id.clone()],
                    &[rupert_user_id.to_string()],
                )
                .await;

            Box::pin(async move {
                let [alice, bob, rupert] = &sessions;
                let conversation = case.create_conversation(&sessions).await;

                let (alice_id, bob_id, rupert_id) = (
                    alice.get_client_id().await,
                    bob.get_client_id().await,
                    rupert.get_client_id().await,
                );

                let client_ids = [alice_id, bob_id, rupert_id];
                let name_status = [
                    (alice_user_id, DeviceStatus::Valid),
                    (bob_user_id, DeviceStatus::Valid),
                    (rupert_user_id, DeviceStatus::Revoked),
                ];

                // Do it a multiple times to avoid WPB-6904 happening again
                for _ in 0..2 {
                    for session in sessions.iter() {
                        let conversation = conversation.guard_of(session).await;
                        check_identities_device_status(&conversation, &client_ids, &name_status).await;
                    }
                }
            })
            .await
        }

        #[async_std::test]
        async fn should_not_fail_when_basic() {
            let case = TestContext::default();

            let [alice_android, alice_ios] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice_android, &alice_ios]).await;

                let (android_id, ios_id) = (alice_android.get_client_id().await, alice_ios.get_client_id().await);

                let mut android_ids = conversation
                    .guard()
                    .await
                    .get_device_identities(&[android_id.clone(), ios_id.clone()])
                    .await
                    .unwrap();
                android_ids.sort();

                let mut ios_ids = conversation
                    .guard_of(&alice_ios)
                    .await
                    .get_device_identities(&[android_id, ios_id])
                    .await
                    .unwrap();
                ios_ids.sort();

                assert_eq!(ios_ids.len(), 2);
                assert_eq!(ios_ids, android_ids);

                assert!(ios_ids.iter().all(|i| {
                    matches!(i.credential_type, MlsCredentialType::Basic)
                        && matches!(i.status, DeviceStatus::Valid)
                        && i.x509_identity.is_none()
                        && !i.thumbprint.is_empty()
                        && !i.client_id.is_empty()
                }));
            })
            .await
        }

        // this test is a duplicate of its counterpart but taking federation into account
        // The heavy lifting of cross-signing the certificates is being done by the test utils.
        #[async_std::test]
        async fn should_read_users_cross_signed() {
            let case = TestContext::default_x509();
            let [alice_1_id, alice_2_id] = case.x509_client_ids_for_user(&uuid::Uuid::new_v4());
            let [federated_alice_1_id, federated_alice_2_id] = case.x509_client_ids_for_user(&uuid::Uuid::new_v4());
            let [bob_id, federated_bob_id] = case.x509_client_ids();

            let ([alice_1, alice_2, bob], [federated_alice_1, federated_alice_2, federated_bob]) = case
                .sessions_x509_cross_signed_with_client_ids(
                    [alice_1_id, alice_2_id, bob_id],
                    [federated_alice_1_id, federated_alice_2_id, federated_bob_id],
                )
                .await;
            Box::pin(async move {
                let sessions = [
                    &alice_1,
                    &alice_2,
                    &bob,
                    &federated_bob,
                    &federated_alice_1,
                    &federated_alice_2,
                ];
                let conversation = case.create_conversation(sessions).await;

                let nb_members = conversation.member_count().await;
                assert_eq!(nb_members, 6);
                let conversation_guard = conversation.guard().await;

                assert_eq!(alice_1.get_user_id().await, alice_2.get_user_id().await);

                let alicem_user_id = federated_alice_2.get_user_id().await;
                let bobt_user_id = federated_bob.get_user_id().await;

                // Finds both Alice's devices
                let alice_user_id = alice_1.get_user_id().await;
                let alice_identities = conversation_guard
                    .get_user_identities(&[alice_user_id.clone()])
                    .await
                    .unwrap();
                assert_eq!(alice_identities.len(), 1);
                let identities = alice_identities.get(&alice_user_id).unwrap();
                assert_eq!(identities.len(), 2);

                // Finds Bob only device
                let bob_user_id = bob.get_user_id().await;
                let bob_identities = conversation_guard
                    .get_user_identities(&[bob_user_id.clone()])
                    .await
                    .unwrap();
                assert_eq!(bob_identities.len(), 1);
                let identities = bob_identities.get(&bob_user_id).unwrap();
                assert_eq!(identities.len(), 1);

                // Finds all devices
                let user_ids = [alice_user_id, bob_user_id, alicem_user_id, bobt_user_id];
                let expected_sizes = [2, 1, 2, 1];

                for session in sessions {
                    all_identities_check(&conversation.guard_of(session).await, &user_ids, expected_sizes).await;
                }
            })
            .await
        }

        #[async_std::test]
        async fn should_read_users() {
            let case = TestContext::default_x509();
            let [alice_android, alice_ios] = case.x509_client_ids_for_user(&uuid::Uuid::new_v4());
            let [bob_android] = case.x509_client_ids();

            let sessions = case
                .sessions_x509_with_client_ids([alice_android, alice_ios, bob_android])
                .await;

            Box::pin(async move {
                let conversation = case.create_conversation(&sessions).await;

                let nb_members = conversation.member_count().await;
                assert_eq!(nb_members, 3);

                let [alice_android, alice_ios, bob_android] = &sessions;
                assert_eq!(alice_android.get_user_id().await, alice_ios.get_user_id().await);

                // Finds both Alice's devices
                let alice_user_id = alice_android.get_user_id().await;
                let alice_identities = conversation
                    .guard()
                    .await
                    .get_user_identities(&[alice_user_id.clone()])
                    .await
                    .unwrap();
                assert_eq!(alice_identities.len(), 1);
                let identities = alice_identities.get(&alice_user_id).unwrap();
                assert_eq!(identities.len(), 2);

                // Finds Bob only device
                let bob_user_id = bob_android.get_user_id().await;
                let bob_identities = conversation
                    .guard()
                    .await
                    .get_user_identities(&[bob_user_id.clone()])
                    .await
                    .unwrap();
                assert_eq!(bob_identities.len(), 1);
                let identities = bob_identities.get(&bob_user_id).unwrap();
                assert_eq!(identities.len(), 1);

                let user_ids = [alice_user_id, bob_user_id];
                let expected_sizes = [2, 1];

                for session in &sessions {
                    all_identities_check(&conversation.guard_of(session).await, &user_ids, expected_sizes).await;
                }
            })
            .await
        }

        #[async_std::test]
        async fn should_exchange_messages_cross_signed() {
            let case = TestContext::default_x509();
            let sessions = case.sessions_x509_cross_signed::<3, 3>().await;
            Box::pin(async move {
                let sessions = sessions.0.iter().chain(sessions.1.iter());
                let conversation = case.create_conversation(sessions.clone()).await;

                assert_eq!(conversation.member_count().await, 6);

                assert!(conversation.is_functional_and_contains(sessions).await);
            })
            .await;
        }
    }

    mod export_secret {
        use super::*;
        use crate::MlsErrorKind;
        use openmls::prelude::ExportSecretError;

        #[apply(all_cred_cipher)]
        pub async fn can_export_secret_key(case: TestContext) {
            let [alice] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice]).await;

                let key_length = 128;
                let result = conversation.guard().await.export_secret_key(key_length).await;
                assert!(result.is_ok());
                assert_eq!(result.unwrap().len(), key_length);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn cannot_export_secret_key_invalid_length(case: TestContext) {
            let [alice] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice]).await;

                let result = conversation.guard().await.export_secret_key(usize::MAX).await;
                let error = result.unwrap_err();
                assert!(innermost_source_matches!(
                    error,
                    MlsErrorKind::MlsExportSecretError(ExportSecretError::KeyLengthTooLong)
                ));
            })
            .await
        }
    }

    mod get_client_ids {
        use super::*;

        #[apply(all_cred_cipher)]
        pub async fn can_get_client_ids(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice]).await;

                assert_eq!(conversation.guard().await.get_client_ids().await.len(), 1);

                let conversation = conversation.invite_notify([&bob]).await;

                assert_eq!(conversation.guard().await.get_client_ids().await.len(), 2);
            })
            .await
        }
    }

    mod external_sender {
        use super::*;

        #[apply(all_cred_cipher)]
        pub async fn should_fetch_ext_sender(mut case: TestContext) {
            let [alice, external_sender] = case.sessions().await;
            Box::pin(async move {
                let conversation = case
                    .create_conversation_with_external_sender(&external_sender, [&alice])
                    .await;

                let alice_ext_sender = conversation.guard().await.get_external_sender().await.unwrap();
                assert!(!alice_ext_sender.is_empty());
                assert_eq!(
                    alice_ext_sender,
                    external_sender.client_signature_key(&case).await.as_slice().to_vec()
                );
            })
            .await
        }
    }
}
