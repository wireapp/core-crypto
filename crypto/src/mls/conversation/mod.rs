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
    prelude::{ClientId, E2eiConversationState, HistorySecret, MlsCiphersuite, MlsCredentialType, WireIdentity},
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
mod leaf_node_validation;
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

    /// Generate a new [`HistorySecret`].
    ///
    /// This is useful when it's this client's turn to generate a new history client.
    ///
    /// The generated secret is cryptographically unrelated to the current CoreCrypto client.
    async fn generate_history_secret(&'a self) -> Result<HistorySecret> {
        crate::ephemeral::generate_history_secret(self)
            .await
            .map_err(RecursiveError::root("generating history secret"))
            .map_err(Into::into)
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
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn create_self_conversation_should_succeed(case: TestContext) {
        run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .transaction
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
                let alice_can_send_message = alice_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .encrypt_message(b"me")
                    .await;
                assert!(alice_can_send_message.is_ok());
            })
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn create_1_1_conversation_should_succeed(case: TestContext) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();

                alice_central
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();

                let bob = bob_central.rand_key_package(&case).await;
                alice_central
                    .transaction
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

                let welcome = alice_central.mls_transport.latest_welcome_message().await;
                bob_central
                    .transaction
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
    pub async fn create_many_people_conversation(case: TestContext) {
        use crate::e2e_identity::enrollment::test_utils::failsafe_ctx;

        run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
            Box::pin(async move {
                let x509_test_chain_arc = failsafe_ctx(&mut [&mut alice_central], case.signature_scheme()).await;
                let x509_test_chain = x509_test_chain_arc.as_ref().as_ref().unwrap();

                let id = conversation_id();
                alice_central
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                let bob_and_friends = case.sessions_x509::<GROUP_SAMPLE_SIZE>(Some(x509_test_chain)).await;

                let mut bob_and_friends_kps = vec![];
                for c in &bob_and_friends {
                    bob_and_friends_kps.push(c.rand_key_package(&case).await);
                }

                alice_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .add_members(bob_and_friends_kps)
                    .await
                    .unwrap();
                let welcome = alice_central.mls_transport.latest_welcome_message().await;

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
                    1 + GROUP_SAMPLE_SIZE
                );

                let mut bob_and_friends_groups = Vec::with_capacity(bob_and_friends.len());
                // TODO: Do things in parallel, this is waaaaay too slow (takes around 5 minutes). Tracking issue: WPB-9624
                for c in bob_and_friends {
                    c.transaction
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

    mod wire_identity_getters {
        use wasm_bindgen_test::*;

        use super::Error;
        use crate::mls::conversation::Conversation as _;
        use crate::prelude::{ClientId, ConversationId, MlsCredentialType};
        use crate::transaction_context::TransactionContext;
        use crate::{
            prelude::{DeviceStatus, E2eiConversationState},
            test_utils::*,
        };

        wasm_bindgen_test_configure!(run_in_browser);

        async fn all_identities_check<const N: usize>(
            central: &TransactionContext,
            id: &ConversationId,
            user_ids: &[String; N],
            expected_sizes: [usize; N],
        ) {
            let all_identities = central
                .conversation(id)
                .await
                .unwrap()
                .get_user_identities(user_ids)
                .await
                .unwrap();
            assert_eq!(all_identities.len(), N);
            for (expected_size, user_id) in expected_sizes.into_iter().zip(user_ids.iter()) {
                let alice_identities = all_identities.get(user_id).unwrap();
                assert_eq!(alice_identities.len(), expected_size);
            }
            // Not found
            let not_found = central
                .conversation(id)
                .await
                .unwrap()
                .get_user_identities(&["aaaaaaaaaaaaa".to_string()])
                .await
                .unwrap();
            assert!(not_found.is_empty());

            // Invalid usage
            let invalid = central.conversation(id).await.unwrap().get_user_identities(&[]).await;
            assert!(matches!(invalid.unwrap_err(), Error::CallerError(_)));
        }

        async fn check_identities_device_status<const N: usize>(
            central: &TransactionContext,
            id: &ConversationId,
            client_ids: &[ClientId; N],
            name_status: &[(&'static str, DeviceStatus); N],
        ) {
            let mut identities = central
                .conversation(id)
                .await
                .unwrap()
                .get_device_identities(client_ids)
                .await
                .unwrap();

            for j in 0..N {
                let client_identity = identities.remove(
                    identities
                        .iter()
                        .position(|i| i.x509_identity.as_ref().unwrap().display_name == name_status[j].0)
                        .unwrap(),
                );
                assert_eq!(client_identity.status, name_status[j].1);
            }
            assert!(identities.is_empty());

            assert_eq!(
                central
                    .conversation(id)
                    .await
                    .unwrap()
                    .e2ei_conversation_state()
                    .await
                    .unwrap(),
                E2eiConversationState::NotVerified
            );
        }

        #[async_std::test]
        #[wasm_bindgen_test]
        async fn should_read_device_identities() {
            let case = TestContext::default_x509();
            run_test_with_client_ids(
                case.clone(),
                ["alice_android", "alice_ios"],
                move |[alice_android_central, alice_ios_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_android_central
                            .transaction
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_android_central
                            .invite_all(&case, &id, [&alice_ios_central])
                            .await
                            .unwrap();

                        let (android_id, ios_id) = (
                            alice_android_central.get_client_id().await,
                            alice_ios_central.get_client_id().await,
                        );

                        let mut android_ids = alice_android_central
                            .transaction
                            .conversation(&id)
                            .await
                            .unwrap()
                            .get_device_identities(&[android_id.clone(), ios_id.clone()])
                            .await
                            .unwrap();
                        android_ids.sort_by(|a, b| a.client_id.cmp(&b.client_id));
                        assert_eq!(android_ids.len(), 2);
                        let mut ios_ids = alice_ios_central
                            .transaction
                            .conversation(&id)
                            .await
                            .unwrap()
                            .get_device_identities(&[android_id.clone(), ios_id.clone()])
                            .await
                            .unwrap();
                        ios_ids.sort_by(|a, b| a.client_id.cmp(&b.client_id));
                        assert_eq!(ios_ids.len(), 2);

                        assert_eq!(android_ids, ios_ids);

                        let android_identities = alice_android_central
                            .transaction
                            .conversation(&id)
                            .await
                            .unwrap()
                            .get_device_identities(&[android_id])
                            .await
                            .unwrap();
                        let android_id = android_identities.first().unwrap();
                        assert_eq!(
                            android_id.client_id.as_bytes(),
                            alice_android_central
                                .transaction
                                .client_id()
                                .await
                                .unwrap()
                                .0
                                .as_slice()
                        );

                        let ios_identities = alice_android_central
                            .transaction
                            .conversation(&id)
                            .await
                            .unwrap()
                            .get_device_identities(&[ios_id])
                            .await
                            .unwrap();
                        let ios_id = ios_identities.first().unwrap();
                        assert_eq!(
                            ios_id.client_id.as_bytes(),
                            alice_ios_central.transaction.client_id().await.unwrap().0.as_slice()
                        );

                        let invalid = alice_android_central
                            .transaction
                            .conversation(&id)
                            .await
                            .unwrap()
                            .get_device_identities(&[])
                            .await;
                        assert!(matches!(invalid.unwrap_err(), Error::CallerError(_)));
                    })
                },
            )
            .await
        }

        #[async_std::test]
        #[wasm_bindgen_test]
        async fn should_read_revoked_device_cross_signed() {
            let case = TestContext::default_x509();
            run_test_with_client_ids_and_revocation(
                case.clone(),
                ["alice", "bob", "rupert"],
                ["john", "dilbert"],
                &["rupert", "dilbert"],
                move |[mut alice, mut bob, mut rupert], [mut john, mut dilbert]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice
                            .transaction
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice
                            .invite_all(&case, &id, [&bob, &rupert, &dilbert, &john])
                            .await
                            .unwrap();

                        let (alice_id, bob_id, rupert_id, dilbert_id, john_id) = (
                            alice.get_client_id().await,
                            bob.get_client_id().await,
                            rupert.get_client_id().await,
                            dilbert.get_client_id().await,
                            john.get_client_id().await,
                        );

                        let client_ids = [alice_id, bob_id, rupert_id, dilbert_id, john_id];
                        let name_status = [
                            ("alice", DeviceStatus::Valid),
                            ("bob", DeviceStatus::Valid),
                            ("rupert", DeviceStatus::Revoked),
                            ("john", DeviceStatus::Valid),
                            ("dilbert", DeviceStatus::Revoked),
                        ];
                        // Do it a multiple times to avoid WPB-6904 happening again
                        for _ in 0..2 {
                            check_identities_device_status(&mut alice.transaction, &id, &client_ids, &name_status)
                                .await;
                            check_identities_device_status(&mut bob.transaction, &id, &client_ids, &name_status).await;
                            check_identities_device_status(&mut rupert.transaction, &id, &client_ids, &name_status)
                                .await;
                            check_identities_device_status(&mut john.transaction, &id, &client_ids, &name_status).await;
                            check_identities_device_status(&mut dilbert.transaction, &id, &client_ids, &name_status)
                                .await;
                        }
                    })
                },
            )
            .await
        }

        #[async_std::test]
        #[wasm_bindgen_test]
        async fn should_read_revoked_device() {
            let case = TestContext::default_x509();
            run_test_with_client_ids_and_revocation(
                case.clone(),
                ["alice", "bob", "rupert"],
                [],
                &["rupert"],
                move |[mut alice, mut bob, mut rupert], []| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice
                            .transaction
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice.invite_all(&case, &id, [&bob, &rupert]).await.unwrap();

                        let (alice_id, bob_id, rupert_id) = (
                            alice.get_client_id().await,
                            bob.get_client_id().await,
                            rupert.get_client_id().await,
                        );

                        let client_ids = [alice_id, bob_id, rupert_id];
                        let name_status = [
                            ("alice", DeviceStatus::Valid),
                            ("bob", DeviceStatus::Valid),
                            ("rupert", DeviceStatus::Revoked),
                        ];

                        // Do it a multiple times to avoid WPB-6904 happening again
                        for _ in 0..2 {
                            check_identities_device_status(&mut alice.transaction, &id, &client_ids, &name_status)
                                .await;
                            check_identities_device_status(&mut bob.transaction, &id, &client_ids, &name_status).await;
                            check_identities_device_status(&mut rupert.transaction, &id, &client_ids, &name_status)
                                .await;
                        }
                    })
                },
            )
            .await
        }

        #[async_std::test]
        #[wasm_bindgen_test]
        async fn should_not_fail_when_basic() {
            let case = TestContext::default();
            run_test_with_client_ids(
                case.clone(),
                ["alice_android", "alice_ios"],
                move |[alice_android_central, alice_ios_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_android_central
                            .transaction
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_android_central
                            .invite_all(&case, &id, [&alice_ios_central])
                            .await
                            .unwrap();

                        let (android_id, ios_id) = (
                            alice_android_central.get_client_id().await,
                            alice_ios_central.get_client_id().await,
                        );

                        let mut android_ids = alice_android_central
                            .transaction
                            .conversation(&id)
                            .await
                            .unwrap()
                            .get_device_identities(&[android_id.clone(), ios_id.clone()])
                            .await
                            .unwrap();
                        android_ids.sort();

                        let mut ios_ids = alice_ios_central
                            .transaction
                            .conversation(&id)
                            .await
                            .unwrap()
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
                },
            )
            .await
        }

        // this test is a duplicate of its counterpart but taking federation into account
        // The heavy lifting of cross-signing the certificates is being done by the test utils.
        #[async_std::test]
        #[wasm_bindgen_test]
        async fn should_read_users_cross_signed() {
            let case = TestContext::default_x509();

            let (alice_android, alice_ios) = (
                "satICT30SbiIpjj1n-XQtA:7684f3f95a5e6848@world.com",
                "satICT30SbiIpjj1n-XQtA:7dfd976fc672c899@world.com",
            );
            let (alicem_android, alicem_ios) = (
                "8h2PRVj_Qyi7p1XLGmdulw:a7c5ac4446bf@world.com",
                "8h2PRVj_Qyi7p1XLGmdulw:10c6f7a0b5ed@world.com",
            );
            let bob_android = "I_7X5oRAToKy9z_kvhDKKQ:8b1fd601510d102a@world.com";
            let bobt_android = "HSLU78bpQCOYwh4FWCac5g:68db8bac6a65d@world.com";

            run_test_with_deterministic_client_ids_and_revocation(
                case.clone(),
                [
                    [alice_android, "alice_wire", "Alice Smith"],
                    [alice_ios, "alice_wire", "Alice Smith"],
                    [bob_android, "bob_wire", "Bob Doe"],
                ],
                [
                    [alicem_android, "alice_zeta", "Alice Muller"],
                    [alicem_ios, "alice_zeta", "Alice Muller"],
                    [bobt_android, "bob_zeta", "Bob Tables"],
                ],
                &[],
                move |[alice_android_central, alice_ios_central, bob_android_central],
                      [alicem_android_central, alicem_ios_central, bobt_android_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_android_central
                            .transaction
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_android_central
                            .invite_all(
                                &case,
                                &id,
                                [
                                    &alice_ios_central,
                                    &bob_android_central,
                                    &bobt_android_central,
                                    &alicem_ios_central,
                                    &alicem_android_central,
                                ],
                            )
                            .await
                            .unwrap();

                        let nb_members = alice_android_central
                            .get_conversation_unchecked(&id)
                            .await
                            .members()
                            .len();
                        assert_eq!(nb_members, 6);

                        assert_eq!(
                            alice_android_central.get_user_id().await,
                            alice_ios_central.get_user_id().await
                        );

                        let alicem_user_id = alicem_ios_central.get_user_id().await;
                        let bobt_user_id = bobt_android_central.get_user_id().await;

                        // Finds both Alice's devices
                        let alice_user_id = alice_android_central.get_user_id().await;
                        let alice_identities = alice_android_central
                            .transaction
                            .conversation(&id)
                            .await
                            .unwrap()
                            .get_user_identities(&[alice_user_id.clone()])
                            .await
                            .unwrap();
                        assert_eq!(alice_identities.len(), 1);
                        let identities = alice_identities.get(&alice_user_id).unwrap();
                        assert_eq!(identities.len(), 2);

                        // Finds Bob only device
                        let bob_user_id = bob_android_central.get_user_id().await;
                        let bob_identities = alice_android_central
                            .transaction
                            .conversation(&id)
                            .await
                            .unwrap()
                            .get_user_identities(&[bob_user_id.clone()])
                            .await
                            .unwrap();
                        assert_eq!(bob_identities.len(), 1);
                        let identities = bob_identities.get(&bob_user_id).unwrap();
                        assert_eq!(identities.len(), 1);

                        // Finds all devices
                        let user_ids = [alice_user_id, bob_user_id, alicem_user_id, bobt_user_id];
                        let expected_sizes = [2, 1, 2, 1];

                        all_identities_check(&alice_android_central.transaction, &id, &user_ids, expected_sizes).await;
                        all_identities_check(&alicem_android_central.transaction, &id, &user_ids, expected_sizes).await;
                        all_identities_check(&alice_ios_central.transaction, &id, &user_ids, expected_sizes).await;
                        all_identities_check(&alicem_ios_central.transaction, &id, &user_ids, expected_sizes).await;
                        all_identities_check(&bob_android_central.transaction, &id, &user_ids, expected_sizes).await;
                        all_identities_check(&bobt_android_central.transaction, &id, &user_ids, expected_sizes).await;
                    })
                },
            )
            .await
        }

        #[async_std::test]
        #[wasm_bindgen_test]
        async fn should_read_users() {
            let case = TestContext::default_x509();

            let (alice_android, alice_ios) = (
                "satICT30SbiIpjj1n-XQtA:7684f3f95a5e6848@world.com",
                "satICT30SbiIpjj1n-XQtA:7dfd976fc672c899@world.com",
            );
            let bob_android = "I_7X5oRAToKy9z_kvhDKKQ:8b1fd601510d102a@world.com";

            run_test_with_deterministic_client_ids(
                case.clone(),
                [
                    [alice_android, "alice_wire", "Alice Smith"],
                    [alice_ios, "alice_wire", "Alice Smith"],
                    [bob_android, "bob_wire", "Bob Doe"],
                ],
                move |[
                    mut alice_android_central,
                    mut alice_ios_central,
                    mut bob_android_central,
                ]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_android_central
                            .transaction
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_android_central
                            .invite_all(&case, &id, [&alice_ios_central, &bob_android_central])
                            .await
                            .unwrap();

                        let nb_members = alice_android_central
                            .get_conversation_unchecked(&id)
                            .await
                            .members()
                            .len();
                        assert_eq!(nb_members, 3);

                        assert_eq!(
                            alice_android_central.get_user_id().await,
                            alice_ios_central.get_user_id().await
                        );

                        // Finds both Alice's devices
                        let alice_user_id = alice_android_central.get_user_id().await;
                        let alice_identities = alice_android_central
                            .transaction
                            .conversation(&id)
                            .await
                            .unwrap()
                            .get_user_identities(&[alice_user_id.clone()])
                            .await
                            .unwrap();
                        assert_eq!(alice_identities.len(), 1);
                        let identities = alice_identities.get(&alice_user_id).unwrap();
                        assert_eq!(identities.len(), 2);

                        // Finds Bob only device
                        let bob_user_id = bob_android_central.get_user_id().await;
                        let bob_identities = alice_android_central
                            .transaction
                            .conversation(&id)
                            .await
                            .unwrap()
                            .get_user_identities(&[bob_user_id.clone()])
                            .await
                            .unwrap();
                        assert_eq!(bob_identities.len(), 1);
                        let identities = bob_identities.get(&bob_user_id).unwrap();
                        assert_eq!(identities.len(), 1);

                        let user_ids = [alice_user_id, bob_user_id];
                        let expected_sizes = [2, 1];

                        all_identities_check(&mut alice_android_central.transaction, &id, &user_ids, expected_sizes)
                            .await;
                        all_identities_check(&mut alice_ios_central.transaction, &id, &user_ids, expected_sizes).await;
                        all_identities_check(&mut bob_android_central.transaction, &id, &user_ids, expected_sizes)
                            .await;
                    })
                },
            )
            .await
        }

        #[async_std::test]
        #[wasm_bindgen_test]
        async fn should_exchange_messages_cross_signed() {
            let (alice_android, alice_ios) = (
                "satICT30SbiIpjj1n-XQtA:7684f3f95a5e6848@wire.com",
                "satICT30SbiIpjj1n-XQtA:7dfd976fc672c899@wire.com",
            );
            let (alicem_android, alicem_ios) = (
                "8h2PRVj_Qyi7p1XLGmdulw:a7c5ac4446bf@zeta.com",
                "8h2PRVj_Qyi7p1XLGmdulw:10c6f7a0b5ed@zeta.com",
            );
            let bob_android = "I_7X5oRAToKy9z_kvhDKKQ:8b1fd601510d102a@wire.com";
            let bobt_android = "HSLU78bpQCOYwh4FWCac5g:68db8bac6a65d@zeta.com";

            let case = TestContext::default_x509();

            run_cross_signed_tests_with_client_ids(
                case.clone(),
                [
                    [alice_android, "alice_wire", "Alice Smith"],
                    [alice_ios, "alice_wire", "Alice Smith"],
                    [bob_android, "bob_wire", "Bob Doe"],
                ],
                [
                    [alicem_android, "alice_zeta", "Alice Muller"],
                    [alicem_ios, "alice_zeta", "Alice Muller"],
                    [bobt_android, "bob_zeta", "Bob Tables"],
                ],
                ("wire.com", "zeta.com"),
                move |[mut alices_android_central, alices_ios_central, mut bob_android_central],
                      [
                    mut alicem_android_central,
                    mut alicem_ios_central,
                    mut bobt_android_central,
                ]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alices_ios_central
                            .transaction
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();

                        alices_ios_central
                            .invite_all(
                                &case,
                                &id,
                                [
                                    &mut alices_android_central,
                                    &mut bob_android_central,
                                    &mut alicem_android_central,
                                    &mut alicem_ios_central,
                                    &mut bobt_android_central,
                                ],
                            )
                            .await
                            .unwrap();

                        let nb_members = alices_android_central
                            .get_conversation_unchecked(&id)
                            .await
                            .members()
                            .len();
                        assert_eq!(nb_members, 6);

                        assert_eq!(
                            alicem_android_central.get_user_id().await,
                            alicem_ios_central.get_user_id().await
                        );

                        // cross server communication
                        bobt_android_central
                            .try_talk_to(&id, &alices_ios_central)
                            .await
                            .unwrap();

                        // same server communication
                        bob_android_central.try_talk_to(&id, &alices_ios_central).await.unwrap();
                    })
                },
            )
            .await;
        }
    }

    mod export_secret {
        use super::*;
        use crate::MlsErrorKind;
        use openmls::prelude::ExportSecretError;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_export_secret_key(case: TestContext) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .transaction
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let key_length = 128;
                    let result = alice_central
                        .transaction
                        .conversation(&id)
                        .await
                        .unwrap()
                        .export_secret_key(key_length)
                        .await;
                    assert!(result.is_ok());
                    assert_eq!(result.unwrap().len(), key_length);
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn cannot_export_secret_key_invalid_length(case: TestContext) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .transaction
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let result = alice_central
                        .transaction
                        .conversation(&id)
                        .await
                        .unwrap()
                        .export_secret_key(usize::MAX)
                        .await;
                    let error = result.unwrap_err();
                    assert!(innermost_source_matches!(
                        error,
                        MlsErrorKind::MlsExportSecretError(ExportSecretError::KeyLengthTooLong)
                    ));
                })
            })
            .await
        }
    }

    mod get_client_ids {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_get_client_ids(case: TestContext) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .transaction
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    assert_eq!(
                        alice_central
                            .transaction
                            .conversation(&id)
                            .await
                            .unwrap()
                            .get_client_ids()
                            .await
                            .len(),
                        1
                    );

                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();
                    assert_eq!(
                        alice_central
                            .transaction
                            .conversation(&id)
                            .await
                            .unwrap()
                            .get_client_ids()
                            .await
                            .len(),
                        2
                    );
                })
            })
            .await
        }
    }

    mod external_sender {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fetch_ext_sender(case: TestContext) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();

                    // by default in test no external sender is set. Let's add one
                    let mut cfg = case.cfg.clone();
                    let external_sender = alice_central.rand_external_sender(&case).await;
                    cfg.external_senders = vec![external_sender.clone()];

                    alice_central
                        .transaction
                        .new_conversation(&id, case.credential_type, cfg)
                        .await
                        .unwrap();

                    let alice_ext_sender = alice_central
                        .transaction
                        .conversation(&id)
                        .await
                        .unwrap()
                        .get_external_sender()
                        .await
                        .unwrap();
                    assert!(!alice_ext_sender.is_empty());
                    assert_eq!(alice_ext_sender, external_sender.signature_key().as_slice().to_vec());
                })
            })
            .await
        }
    }
}
