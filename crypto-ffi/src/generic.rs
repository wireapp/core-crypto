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

use futures_lite::future;
use std::collections::HashMap;

use core_crypto::prelude::*;
pub use core_crypto::prelude::{
    tls_codec::Serialize, CiphersuiteName, ClientId, ConversationId, CryptoError, E2eIdentityError, E2eIdentityResult,
    MemberId, MlsPublicGroupStateBundle, MlsPublicGroupStateEncryptionType, MlsRatchetTreeType, MlsWirePolicy,
    PublicGroupStatePayload,
};

cfg_if::cfg_if! {
    if #[cfg(feature = "mobile")] {
        mod uniffi_support;
        pub use self::uniffi_support::*;
    }
}

#[derive(Debug)]
/// see [core_crypto::prelude::MlsConversationCreationMessage]
pub struct MemberAddedMessages {
    pub welcome: Vec<u8>,
    pub commit: Vec<u8>,
    pub public_group_state: PublicGroupStateBundle,
}

impl TryFrom<MlsConversationCreationMessage> for MemberAddedMessages {
    type Error = CryptoError;

    fn try_from(msg: MlsConversationCreationMessage) -> Result<Self, Self::Error> {
        let (welcome, commit, pgs) = msg.to_bytes_triple()?;
        Ok(Self {
            welcome,
            commit,
            public_group_state: pgs.into(),
        })
    }
}

#[derive(Debug)]
pub struct CommitBundle {
    pub welcome: Option<Vec<u8>>,
    pub commit: Vec<u8>,
    pub public_group_state: PublicGroupStateBundle,
}

impl TryFrom<MlsCommitBundle> for CommitBundle {
    type Error = CryptoError;

    fn try_from(msg: MlsCommitBundle) -> Result<Self, Self::Error> {
        let (welcome, commit, pgs) = msg.to_bytes_triple()?;
        Ok(Self {
            welcome,
            commit,
            public_group_state: pgs.into(),
        })
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PublicGroupStateBundle {
    pub encryption_type: MlsPublicGroupStateEncryptionType,
    pub ratchet_tree_type: MlsRatchetTreeType,
    pub payload: Vec<u8>,
}

impl From<MlsPublicGroupStateBundle> for PublicGroupStateBundle {
    fn from(pgs: MlsPublicGroupStateBundle) -> Self {
        Self {
            encryption_type: pgs.encryption_type,
            ratchet_tree_type: pgs.ratchet_tree_type,
            payload: pgs.payload.bytes(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Invitee {
    pub id: ClientId,
    pub kp: Vec<u8>,
}

#[derive(Debug)]
pub struct ProposalBundle {
    pub proposal: Vec<u8>,
    pub proposal_ref: Vec<u8>,
}

impl TryFrom<MlsProposalBundle> for ProposalBundle {
    type Error = CryptoError;

    fn try_from(msg: MlsProposalBundle) -> Result<Self, Self::Error> {
        let (proposal, proposal_ref) = msg.to_bytes_pair()?;
        Ok(Self { proposal, proposal_ref })
    }
}

#[derive(Debug)]
pub struct ConversationInitBundle {
    pub conversation_id: ConversationId,
    pub commit: Vec<u8>,
    pub public_group_state: PublicGroupStateBundle,
}

impl TryFrom<MlsConversationInitBundle> for ConversationInitBundle {
    type Error = CryptoError;

    fn try_from(mut from: MlsConversationInitBundle) -> Result<Self, Self::Error> {
        let conversation_id = std::mem::take(&mut from.conversation_id);
        let (commit, pgs) = from.to_bytes_pair()?;
        Ok(Self {
            conversation_id,
            commit,
            public_group_state: pgs.into(),
        })
    }
}

#[derive(Debug)]
/// See [core_crypto::prelude::decrypt::MlsConversationDecryptMessage]
pub struct DecryptedMessage {
    pub message: Option<Vec<u8>>,
    pub proposals: Vec<ProposalBundle>,
    pub is_active: bool,
    pub commit_delay: Option<u64>,
    pub sender_client_id: Option<ClientId>,
    pub has_epoch_changed: bool,
}

impl TryFrom<MlsConversationDecryptMessage> for DecryptedMessage {
    type Error = CryptoError;

    fn try_from(from: MlsConversationDecryptMessage) -> Result<Self, Self::Error> {
        let proposals = from
            .proposals
            .into_iter()
            .map(ProposalBundle::try_from)
            .collect::<CryptoResult<Vec<_>>>()?;

        Ok(Self {
            message: from.app_msg,
            proposals,
            is_active: from.is_active,
            commit_delay: from.delay,
            sender_client_id: from.sender_client_id,
            has_epoch_changed: from.has_epoch_changed,
        })
    }
}

impl Invitee {
    #[inline(always)]
    fn group_to_conversation_member(clients: Vec<Self>) -> CryptoResult<Vec<ConversationMember>> {
        Ok(clients
            .into_iter()
            .try_fold(
                HashMap::new(),
                |mut acc, c| -> CryptoResult<HashMap<ClientId, ConversationMember>> {
                    if let Some(member) = acc.get_mut(&c.id) {
                        member.add_keypackage(c.kp)?;
                    } else {
                        acc.insert(c.id.clone(), ConversationMember::new_raw(c.id, c.kp)?);
                    }
                    Ok(acc)
                },
            )?
            .into_values()
            .collect::<Vec<ConversationMember>>())
    }
}

impl TryInto<ConversationMember> for Invitee {
    type Error = CryptoError;

    fn try_into(self) -> Result<ConversationMember, Self::Error> {
        ConversationMember::new_raw(self.id, self.kp)
    }
}

#[derive(Debug, Clone)]
/// See [core_crypto::prelude::MlsConversationConfiguration]
pub struct ConversationConfiguration {
    pub ciphersuite: Option<CiphersuiteName>,
    pub external_senders: Vec<Vec<u8>>,
    pub custom: CustomConfiguration,
}

impl TryInto<MlsConversationConfiguration> for ConversationConfiguration {
    type Error = CryptoError;
    fn try_into(mut self) -> CryptoResult<MlsConversationConfiguration> {
        let mut cfg = MlsConversationConfiguration {
            custom: self.custom.into(),
            ..Default::default()
        };

        cfg.set_raw_external_senders(self.external_senders);

        if let Some(ciphersuite) = self.ciphersuite.take() {
            cfg.ciphersuite = ciphersuite.into();
        }

        Ok(cfg)
    }
}

#[derive(Debug, Clone)]
/// See [core_crypto::prelude::MlsCustomConfiguration]
pub struct CustomConfiguration {
    pub key_rotation_span: Option<std::time::Duration>,
    pub wire_policy: Option<MlsWirePolicy>,
}

impl From<CustomConfiguration> for MlsCustomConfiguration {
    fn from(cfg: CustomConfiguration) -> Self {
        Self {
            key_rotation_span: cfg.key_rotation_span,
            wire_policy: cfg.wire_policy.unwrap_or_default(),
            ..Default::default()
        }
    }
}

#[derive(Debug)]
struct CoreCryptoCallbacksWrapper(Box<dyn CoreCryptoCallbacks>);

#[async_trait::async_trait(?Send)]
impl core_crypto::prelude::CoreCryptoCallbacks for CoreCryptoCallbacksWrapper {
    async fn authorize(&self, conversation_id: ConversationId, client_id: ClientId) -> bool {
        self.0.authorize(conversation_id, client_id)
    }
    async fn user_authorize(
        &self,
        conversation_id: ConversationId,
        external_client_id: ClientId,
        existing_clients: Vec<ClientId>,
    ) -> bool {
        self.0
            .user_authorize(conversation_id, external_client_id, existing_clients)
    }
    async fn client_is_existing_group_user(
        &self,
        conversation_id: ConversationId,
        client_id: ClientId,
        existing_clients: Vec<ClientId>,
    ) -> bool {
        self.0
            .client_is_existing_group_user(conversation_id, client_id, existing_clients)
    }
}

/// This only exists to create a sync interface to our internal async callback interface
pub trait CoreCryptoCallbacks: std::fmt::Debug + Send + Sync {
    fn authorize(&self, conversation_id: ConversationId, client_id: ClientId) -> bool;
    fn user_authorize(
        &self,
        conversation_id: ConversationId,
        external_client_id: ClientId,
        existing_clients: Vec<ClientId>,
    ) -> bool;
    fn client_is_existing_group_user(
        &self,
        conversation_id: ConversationId,
        client_id: ClientId,
        existing_clients: Vec<ClientId>,
    ) -> bool;
}

#[derive(Debug)]
pub struct CoreCrypto<'a> {
    central: std::sync::Arc<std::sync::Mutex<core_crypto::CoreCrypto>>,
    executor: std::sync::Arc<std::sync::Mutex<async_executor::Executor<'a>>>,
    proteus_last_error_code: std::sync::atomic::AtomicU32,
}

#[allow(dead_code, unused_variables)]
impl CoreCrypto<'_> {
    /// See [core_crypto::MlsCentral::try_new]
    pub fn new<'s>(
        path: &'s str,
        key: &'s str,
        client_id: &'s ClientId,
        entropy_seed: Option<Vec<u8>>,
    ) -> CryptoResult<Self> {
        let executor = async_executor::Executor::new();
        let ciphersuites = vec![MlsCiphersuite::default()];
        let mut configuration =
            MlsCentralConfiguration::try_new(path.into(), key.into(), Some(client_id.clone()), ciphersuites)?;

        if let Some(seed) = entropy_seed {
            let owned_seed = EntropySeed::try_from_slice(&seed[..EntropySeed::EXPECTED_LEN])?;
            configuration.set_entropy(owned_seed);
        }
        // TODO: not exposing certificate bundle ATM. Pending e2e identity solution to be defined
        let certificate_bundle = None;
        let central = future::block_on(executor.run(MlsCentral::try_new(configuration, certificate_bundle)))?;
        let central = std::sync::Arc::new(core_crypto::CoreCrypto::from(central).into());
        Ok(Self {
            central,
            executor: std::sync::Arc::new(executor.into()),
            proteus_last_error_code: std::sync::atomic::AtomicU32::new(0),
        })
    }

    /// Similar to [CoreCrypto::new] but defers MLS initialization. It can be initialized later
    /// with [CoreCrypto::init_mls].
    /// This should stay as long as proteus is supported. Then it should be removed.
    pub fn deferred_init<'s>(path: &'s str, key: &'s str, entropy_seed: Option<Vec<u8>>) -> CryptoResult<Self> {
        let executor = async_executor::Executor::new();
        let ciphersuites = vec![MlsCiphersuite::default()];
        let mut configuration = MlsCentralConfiguration::try_new(path.into(), key.into(), None, ciphersuites)?;

        if let Some(seed) = entropy_seed {
            let owned_seed = EntropySeed::try_from_slice(&seed[..EntropySeed::EXPECTED_LEN])?;
            configuration.set_entropy(owned_seed);
        }
        // TODO: not exposing certificate bundle ATM. Pending e2e identity solution to be defined
        let certificate_bundle = None;
        let central = future::block_on(executor.run(MlsCentral::try_new(configuration, certificate_bundle)))?;
        let central = std::sync::Arc::new(core_crypto::CoreCrypto::from(central).into());
        Ok(Self {
            central,
            executor: std::sync::Arc::new(executor.into()),
            proteus_last_error_code: std::sync::atomic::AtomicU32::new(0),
        })
    }

    /// See [core_crypto::MlsCentral::init_mls]
    pub fn mls_init(&self, client_id: &ClientId) -> CryptoResult<()> {
        let ciphersuites = vec![MlsCiphersuite::default()];
        // TODO: not exposing certificate bundle ATM. Pending e2e identity solution to be defined
        let certificate_bundle = None;
        future::block_on(self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
            self.central.lock().map_err(|_| CryptoError::LockPoisonError)?.mls_init(
                client_id.clone(),
                ciphersuites,
                certificate_bundle,
            ),
        ))
    }

    /// See [core_crypto::MlsCentral::mls_generate_keypair]
    pub fn mls_generate_keypair(&self) -> CryptoResult<Vec<u8>> {
        let ciphersuites = vec![MlsCiphersuite::default()];
        // TODO: not exposing certificate bundle ATM. Pending e2e identity solution to be defined
        let certificate_bundle = None;
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .mls_generate_keypair(ciphersuites, certificate_bundle),
            ),
        )
    }

    /// See [core_crypto::MlsCentral::mls_init_with_client_id]
    pub fn mls_init_with_client_id(&self, client_id: &ClientId, signature_public_key: &[u8]) -> CryptoResult<()> {
        let ciphersuites = vec![MlsCiphersuite::default()];
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .mls_init_with_client_id(client_id.clone(), signature_public_key, ciphersuites),
            ),
        )
    }

    /// See [core_crypto::MlsCentral::restore_from_disk]
    pub fn restore_from_disk(&self) -> CryptoResult<()> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .restore_from_disk(),
            ),
        )
    }

    /// See [core_crypto::MlsCentral::close]
    pub fn close(self) -> CryptoResult<()> {
        if let Ok(central_lock) = std::sync::Arc::try_unwrap(self.central) {
            let central = central_lock.into_inner().map_err(|_| CryptoError::LockPoisonError)?;
            future::block_on(central.take().close())?;
            Ok(())
        } else {
            Err(CryptoError::LockPoisonError)
        }
    }

    /// See [core_crypto::MlsCentral::wipe]
    pub fn wipe(self) -> CryptoResult<()> {
        if let Ok(central_lock) = std::sync::Arc::try_unwrap(self.central) {
            let central = central_lock.into_inner().map_err(|_| CryptoError::LockPoisonError)?;
            future::block_on(central.take().wipe())?;
            Ok(())
        } else {
            Err(CryptoError::LockPoisonError)
        }
    }

    #[cfg(feature = "mobile")]
    /// See [core_crypto::MlsCentral::callbacks]
    pub fn set_callbacks(&self, callbacks: Box<dyn CoreCryptoCallbacks>) -> CryptoResult<()> {
        self.central
            .lock()
            .map_err(|_| CryptoError::LockPoisonError)?
            .callbacks(Box::new(CoreCryptoCallbacksWrapper(callbacks)));
        Ok(())
    }

    /// See [core_crypto::MlsCentral::client_public_key]
    pub fn client_public_key(&self) -> CryptoResult<Vec<u8>> {
        self.central
            .lock()
            .map_err(|_| CryptoError::LockPoisonError)?
            .client_public_key()
    }

    /// See [core_crypto::MlsCentral::client_keypackages]
    pub fn client_keypackages(&self, amount_requested: u32) -> CryptoResult<Vec<Vec<u8>>> {
        let kps = future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .client_keypackages(amount_requested as usize),
            ),
        )?;

        kps.into_iter()
            .map(|kpb| {
                kpb.key_package()
                    .tls_serialize_detached()
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
            })
            .collect::<CryptoResult<Vec<Vec<u8>>>>()
    }

    /// See [core_crypto::MlsCentral::client_valid_keypackages_count]
    pub fn client_valid_keypackages_count(&self) -> CryptoResult<u64> {
        let count = future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .client_valid_keypackages_count(),
            ),
        )?;

        Ok(count.try_into()?)
    }

    /// See [core_crypto::MlsCentral::new_conversation]
    pub fn create_conversation(
        &self,
        conversation_id: ConversationId,
        config: ConversationConfiguration,
    ) -> CryptoResult<()> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .new_conversation(conversation_id, config.try_into()?),
            ),
        )
    }

    /// See [core_crypto::MlsCentral::conversation_epoch]
    pub fn conversation_epoch(&self, conversation_id: ConversationId) -> CryptoResult<u64> {
        self.central
            .lock()
            .map_err(|_| CryptoError::LockPoisonError)?
            .conversation_epoch(&conversation_id)
    }

    /// See [core_crypto::MlsCentral::process_raw_welcome_message]
    pub fn process_welcome_message(
        &self,
        welcome_message: &[u8],
        custom_configuration: CustomConfiguration,
    ) -> CryptoResult<ConversationId> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .process_raw_welcome_message(welcome_message.into(), custom_configuration.into()),
            ),
        )
    }

    /// See [core_crypto::MlsCentral::add_members_to_conversation]
    pub fn add_clients_to_conversation(
        &self,
        conversation_id: ConversationId,
        clients: Vec<Invitee>,
    ) -> CryptoResult<MemberAddedMessages> {
        let mut members = Invitee::group_to_conversation_member(clients)?;

        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .add_members_to_conversation(&conversation_id, &mut members),
            ),
        )?
        .try_into()
    }

    /// See [core_crypto::MlsCentral::remove_members_from_conversation]
    pub fn remove_clients_from_conversation(
        &self,
        conversation_id: ConversationId,
        clients: Vec<ClientId>,
    ) -> CryptoResult<CommitBundle> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .remove_members_from_conversation(&conversation_id, &clients),
            ),
        )?
        .try_into()
    }

    /// See [core_crypto::MlsCentral::update_keying_material]
    pub fn update_keying_material(&self, conversation_id: ConversationId) -> CryptoResult<CommitBundle> {
        future::block_on({
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .update_keying_material(&conversation_id),
            )
        })?
        .try_into()
    }

    /// See [core_crypto::MlsCentral::commit_pending_proposals]
    pub fn commit_pending_proposals(&self, conversation_id: ConversationId) -> CryptoResult<Option<CommitBundle>> {
        future::block_on({
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .commit_pending_proposals(&conversation_id),
            )
        })
        .transpose()
        .map(|r| r.and_then(|b| b.try_into()))
        .transpose()
    }

    /// see [core_crypto::MlsCentral::wipe_conversation]
    pub fn wipe_conversation(&self, conversation_id: ConversationId) -> CryptoResult<()> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .wipe_conversation(&conversation_id),
            ),
        )
    }

    /// See [core_crypto::MlsCentral::decrypt_message]
    pub fn decrypt_message(&self, conversation_id: ConversationId, payload: &[u8]) -> CryptoResult<DecryptedMessage> {
        let raw_decrypted_message = future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .decrypt_message(&conversation_id, payload),
            ),
        )?;

        let decrypted_message: DecryptedMessage = raw_decrypted_message.try_into()?;

        Ok(decrypted_message)
    }

    /// See [core_crypto::MlsCentral::encrypt_message]
    pub fn encrypt_message(&self, conversation_id: ConversationId, message: &[u8]) -> CryptoResult<Vec<u8>> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .encrypt_message(&conversation_id, message),
            ),
        )
    }

    /// See [core_crypto::MlsCentral::conversation_exists]
    pub fn conversation_exists(&self, conversation_id: ConversationId) -> bool {
        let mut central = self.central.lock().map_err(|_| CryptoError::LockPoisonError).ok();

        if let Some(central) = central.take() {
            central.conversation_exists(&conversation_id)
        } else {
            false
        }
    }

    /// See [core_crypto::MlsCentral::new_proposal]
    pub fn new_add_proposal(
        &self,
        conversation_id: ConversationId,
        keypackage: Vec<u8>,
    ) -> CryptoResult<ProposalBundle> {
        let kp = KeyPackage::try_from(&keypackage[..]).map_err(MlsError::from)?;
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .new_proposal(&conversation_id, MlsProposal::Add(kp)),
            ),
        )?
        .try_into()
    }

    /// See [core_crypto::MlsCentral::new_proposal]
    pub fn new_update_proposal(&self, conversation_id: ConversationId) -> CryptoResult<ProposalBundle> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .new_proposal(&conversation_id, MlsProposal::Update),
            ),
        )?
        .try_into()
    }

    /// See [core_crypto::MlsCentral::new_proposal]
    pub fn new_remove_proposal(
        &self,
        conversation_id: ConversationId,
        client_id: ClientId,
    ) -> CryptoResult<ProposalBundle> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .new_proposal(&conversation_id, MlsProposal::Remove(client_id)),
            ),
        )?
        .try_into()
    }

    /// See [core_crypto::MlsCentral::new_external_add_proposal]
    pub fn new_external_add_proposal(&self, conversation_id: ConversationId, epoch: u64) -> CryptoResult<Vec<u8>> {
        Ok(future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .new_external_add_proposal(conversation_id, epoch.into()),
            ),
        )?
        .to_bytes()
        .map_err(MlsError::from)?)
    }

    /// See [core_crypto::MlsCentral::new_external_remove_proposal]
    pub fn new_external_remove_proposal(
        &self,
        conversation_id: ConversationId,
        epoch: u64,
        keypackage_ref: Vec<u8>,
    ) -> CryptoResult<Vec<u8>> {
        let value: [u8; 16] = keypackage_ref
            .try_into()
            .map_err(|_| CryptoError::InvalidByteArrayError(16))?;
        let kpr = KeyPackageRef::from(value);
        Ok(future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .new_external_remove_proposal(conversation_id, epoch.into(), kpr),
            ),
        )?
        .to_bytes()
        .map_err(MlsError::from)?)
    }

    /// See [core_crypto::MlsCentral::export_public_group_state]
    pub fn export_group_state(&self, conversation_id: ConversationId) -> CryptoResult<Vec<u8>> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .export_public_group_state(&conversation_id),
            ),
        )
    }

    /// See [core_crypto::MlsCentral::join_by_external_commit]
    pub fn join_by_external_commit(
        &self,
        public_group_state: Vec<u8>,
        custom_configuration: CustomConfiguration,
    ) -> CryptoResult<ConversationInitBundle> {
        use core_crypto::prelude::tls_codec::Deserialize as _;

        let group_state =
            VerifiablePublicGroupState::tls_deserialize(&mut &public_group_state[..]).map_err(MlsError::from)?;
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .join_by_external_commit(group_state, custom_configuration.into()),
            ),
        )?
        .try_into()
    }

    /// See [core_crypto::MlsCentral::merge_pending_group_from_external_commit]
    pub fn merge_pending_group_from_external_commit(&self, conversation_id: ConversationId) -> CryptoResult<()> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .merge_pending_group_from_external_commit(&conversation_id),
            ),
        )?;

        Ok(())
    }

    /// See [core_crypto::MlsCentral::clear_pending_group_from_external_commit]
    pub fn clear_pending_group_from_external_commit(&self, conversation_id: ConversationId) -> CryptoResult<()> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .clear_pending_group_from_external_commit(&conversation_id),
            ),
        )?;

        Ok(())
    }

    /// See [core_crypto::MlsCentral::random_bytes]
    pub fn random_bytes(&self, len: u32) -> CryptoResult<Vec<u8>> {
        self.central
            .lock()
            .map_err(|_| CryptoError::LockPoisonError)?
            .random_bytes(len.try_into()?)
    }

    /// see [mls_crypto_provider::MlsCryptoProvider::reseed]
    pub fn reseed_rng(&self, seed: Vec<u8>) -> CryptoResult<()> {
        let seed = EntropySeed::try_from_slice(&seed)?;
        self.central
            .lock()
            .map_err(|_| CryptoError::LockPoisonError)?
            .provider_mut()
            .reseed(Some(seed));

        Ok(())
    }

    /// See [core_crypto::MlsCentral::commit_accepted]
    pub fn commit_accepted(&self, conversation_id: ConversationId) -> CryptoResult<()> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .commit_accepted(&conversation_id),
            ),
        )
    }

    /// See [core_crypto::MlsCentral::clear_pending_proposal]
    pub fn clear_pending_proposal(&self, conversation_id: ConversationId, proposal_ref: Vec<u8>) -> CryptoResult<()> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .clear_pending_proposal(&conversation_id, proposal_ref),
            ),
        )
    }

    /// See [core_crypto::MlsCentral::clear_pending_commit]
    pub fn clear_pending_commit(&self, conversation_id: ConversationId) -> CryptoResult<()> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .clear_pending_commit(&conversation_id),
            ),
        )
    }

    /// See [core_crypto::MlsCentral::get_client_ids]
    pub fn get_client_ids(&self, conversation_id: ConversationId) -> CryptoResult<Vec<ClientId>> {
        self.central
            .lock()
            .map_err(|_| CryptoError::LockPoisonError)?
            .get_client_ids(&conversation_id)
    }

    /// See [core_crypto::MlsCentral::export_secret_key]
    pub fn export_secret_key(&self, conversation_id: ConversationId, key_length: u32) -> CryptoResult<Vec<u8>> {
        self.central
            .lock()
            .map_err(|_| CryptoError::LockPoisonError)?
            .export_secret_key(&conversation_id, key_length as usize)
    }

    /// See [core_crypto::MlsCentral::new_acme_enrollment]
    pub fn new_acme_enrollment(&self, ciphersuite: CiphersuiteName) -> CryptoResult<std::sync::Arc<WireE2eIdentity>> {
        self.central
            .lock()
            .map_err(|_| CryptoError::LockPoisonError)?
            .new_acme_enrollment(ciphersuite.into())
            .map(WireE2eIdentity)
            .map(std::sync::Arc::new)
            .map_err(|_| CryptoError::ImplementationError)
    }
}

#[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
impl CoreCrypto<'_> {
    /// See [core_crypto::proteus::ProteusCentral::try_new]
    pub fn proteus_init(&self) -> CryptoResult<()> {
        proteus_impl! { self.proteus_last_error_code => {
            future::block_on(
                self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                    self.central
                        .lock()
                        .map_err(|_| CryptoError::LockPoisonError)?
                        .proteus_init(),
                ),
            )
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::session_from_prekey]
    pub fn proteus_session_from_prekey(&self, session_id: &str, prekey: &[u8]) -> CryptoResult<()> {
        proteus_impl! { self.proteus_last_error_code => {
            let _ = future::block_on(
                self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                    self.central
                        .lock()
                        .map_err(|_| CryptoError::LockPoisonError)?
                        .proteus_session_from_prekey(session_id, prekey),
                ),
            )?;

            CryptoResult::Ok(())
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::session_from_message]
    pub fn proteus_session_from_message(&self, session_id: &str, envelope: &[u8]) -> CryptoResult<Vec<u8>> {
        proteus_impl! { self.proteus_last_error_code => {
            let (_, payload) = future::block_on(
                self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                    self.central
                        .lock()
                        .map_err(|_| CryptoError::LockPoisonError)?
                        .proteus_session_from_message(session_id, envelope),
                ),
            )?;

            CryptoResult::Ok(payload)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::session_save]
    /// **Note**: This isn't usually needed as persisting sessions happens automatically when decrypting/encrypting messages and initializing Sessions
    pub fn proteus_session_save(&self, session_id: &str) -> CryptoResult<()> {
        proteus_impl! { self.proteus_last_error_code => {
            future::block_on(
                self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                    self.central
                        .lock()
                        .map_err(|_| CryptoError::LockPoisonError)?
                        .proteus_session_save(session_id),
                ),
            )
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::session_delete]
    pub fn proteus_session_delete(&self, session_id: &str) -> CryptoResult<()> {
        proteus_impl! { self.proteus_last_error_code => {
            future::block_on(
                self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                    self.central
                        .lock()
                        .map_err(|_| CryptoError::LockPoisonError)?
                        .proteus_session_delete(session_id),
                ),
            )
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::session_exists]
    pub fn proteus_session_exists(&self, session_id: &str) -> CryptoResult<bool> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .map_err(|_| CryptoError::LockPoisonError)?
                .proteus_session_exists(session_id)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::decrypt]
    pub fn proteus_decrypt(&self, session_id: &str, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        proteus_impl! { self.proteus_last_error_code => {
            future::block_on(
                self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                    self.central
                        .lock()
                        .map_err(|_| CryptoError::LockPoisonError)?
                        .proteus_decrypt(session_id, ciphertext),
                ),
            )
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::encrypt]
    pub fn proteus_encrypt(&self, session_id: &str, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        proteus_impl! { self.proteus_last_error_code => {
            future::block_on(
                self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                    self.central
                        .lock()
                        .map_err(|_| CryptoError::LockPoisonError)?
                        .proteus_encrypt(session_id, plaintext)
                ),
            )
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::encrypt_batched]
    pub fn proteus_encrypt_batched(
        &self,
        sessions: Vec<String>,
        plaintext: &[u8],
    ) -> CryptoResult<std::collections::HashMap<String, Vec<u8>>> {
        proteus_impl! { self.proteus_last_error_code => {
            future::block_on(
                self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                    self.central
                        .lock()
                        .map_err(|_| CryptoError::LockPoisonError)?
                        .proteus_encrypt_batched(sessions.as_slice(), plaintext)
                )
            )
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::new_prekey]
    pub fn proteus_new_prekey(&self, prekey_id: u16) -> CryptoResult<Vec<u8>> {
        proteus_impl! { self.proteus_last_error_code => {
            future::block_on(
                self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                    self.central
                        .lock()
                        .map_err(|_| CryptoError::LockPoisonError)?
                        .proteus_new_prekey(prekey_id),
                ),
            )
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::new_prekey_auto]
    pub fn proteus_new_prekey_auto(&self) -> CryptoResult<Vec<u8>> {
        proteus_impl! { self.proteus_last_error_code => {
            future::block_on(
                self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                    self.central
                        .lock()
                        .map_err(|_| CryptoError::LockPoisonError)?
                        .proteus_new_prekey_auto(),
                ),
            )
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint]
    pub fn proteus_fingerprint(&self) -> CryptoResult<String> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .map_err(|_| CryptoError::LockPoisonError)?
                .proteus_fingerprint()
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_local]
    pub fn proteus_fingerprint_local(&self, session_id: &str) -> CryptoResult<String> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .map_err(|_| CryptoError::LockPoisonError)?
                .proteus_fingerprint_local(session_id)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_remote]
    pub fn proteus_fingerprint_remote(&self, session_id: &str) -> CryptoResult<String> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .map_err(|_| CryptoError::LockPoisonError)?
                .proteus_fingerprint_remote(session_id)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle]
    /// NOTE: uniffi doesn't support associated functions, so we have to have the self here
    pub fn proteus_fingerprint_prekeybundle(&self, prekey: &[u8]) -> CryptoResult<String> {
        proteus_impl! { self.proteus_last_error_code => {
            core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle(prekey)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::cryptobox_migrate]
    pub fn proteus_cryptobox_migrate(&self, path: &str) -> CryptoResult<()> {
        proteus_impl! { self.proteus_last_error_code => {
            future::block_on(
                self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                    self.central
                        .lock()
                        .map_err(|_| CryptoError::LockPoisonError)?
                        .proteus_cryptobox_migrate(path)
                ),
            )
        }}
    }

    /// Returns the latest proteus error code. If 0, no error has occured
    ///
    /// NOTE: This will clear the last error code.
    pub fn proteus_last_error_code(&self) -> u32 {
        self.proteus_last_error_code
            .swap(0, std::sync::atomic::Ordering::SeqCst)
    }
}

#[derive(Debug)]
/// See [core_crypto::e2e_identity::WireE2eIdentity]
pub struct WireE2eIdentity(core_crypto::prelude::WireE2eIdentity);

impl WireE2eIdentity {
    /// See [core_crypto::e2e_identity::WireE2eIdentity::directory_response]
    pub fn directory_response(&self, directory: JsonRawData) -> E2eIdentityResult<AcmeDirectory> {
        self.0.directory_response(directory).map(AcmeDirectory::from)
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_account_request]
    pub fn new_account_request(
        &self,
        directory: AcmeDirectory,
        previous_nonce: String,
    ) -> E2eIdentityResult<JsonRawData> {
        self.0.new_account_request(directory.into(), previous_nonce)
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_account_response]
    pub fn new_account_response(&self, account: JsonRawData) -> E2eIdentityResult<JsonRawData> {
        Ok(self.0.new_account_response(account)?.into())
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_order_request]
    pub fn new_order_request(
        &self,
        handle: String,
        client_id: String,
        expiry_days: u32,
        directory: AcmeDirectory,
        account: AcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<JsonRawData> {
        self.0.new_order_request(
            handle,
            client_id,
            expiry_days,
            directory.into(),
            account.into(),
            previous_nonce,
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_order_response]
    pub fn new_order_response(&self, order: JsonRawData) -> E2eIdentityResult<NewAcmeOrder> {
        Ok(self.0.new_order_response(order)?.into())
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_authz_request]
    pub fn new_authz_request(
        &self,
        url: String,
        account: AcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<JsonRawData> {
        self.0.new_authz_request(url, account.into(), previous_nonce)
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_authz_response]
    pub fn new_authz_response(&self, authz: JsonRawData) -> E2eIdentityResult<NewAcmeAuthz> {
        Ok(self.0.new_authz_response(authz)?.into())
    }

    #[allow(clippy::too_many_arguments)]
    /// See [core_crypto::e2e_identity::WireE2eIdentity::create_dpop_token]
    pub fn create_dpop_token(
        &self,
        access_token_url: String,
        user_id: String,
        client_id: u64,
        domain: String,
        client_id_challenge: AcmeChallenge,
        backend_nonce: String,
        expiry_days: u32,
    ) -> E2eIdentityResult<String> {
        self.0.create_dpop_token(
            access_token_url,
            user_id,
            client_id,
            domain,
            client_id_challenge.into(),
            backend_nonce,
            expiry_days,
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_challenge_request]
    pub fn new_challenge_request(
        &self,
        handle: AcmeChallenge,
        account: AcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<JsonRawData> {
        self.0
            .new_challenge_request(handle.into(), account.into(), previous_nonce)
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_challenge_response]
    pub fn new_challenge_response(&self, challenge: JsonRawData) -> E2eIdentityResult<()> {
        self.0.new_challenge_response(challenge)
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::check_order_request]
    pub fn check_order_request(
        &self,
        order_url: String,
        account: AcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<JsonRawData> {
        self.0.check_order_request(order_url, account.into(), previous_nonce)
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::check_order_response]
    pub fn check_order_response(&self, order: JsonRawData) -> E2eIdentityResult<JsonRawData> {
        Ok(self.0.check_order_response(order)?.into())
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::finalize_request]
    pub fn finalize_request(
        &self,
        domains: Vec<String>,
        order: AcmeOrder,
        account: AcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<JsonRawData> {
        self.0
            .finalize_request(domains, order.into(), account.into(), previous_nonce)
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::finalize_response]
    pub fn finalize_response(&self, finalize: JsonRawData) -> E2eIdentityResult<AcmeFinalize> {
        Ok(self.0.finalize_response(finalize)?.into())
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::certificate_request]
    pub fn certificate_request(
        &self,
        finalize: AcmeFinalize,
        account: AcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<JsonRawData> {
        self.0
            .certificate_request(finalize.into(), account.into(), previous_nonce)
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::certificate_response]
    pub fn certificate_response(&self, certificate_chain: String) -> E2eIdentityResult<Vec<String>> {
        self.0.certificate_response(certificate_chain)
    }
}

pub type JsonRawData = Vec<u8>;
pub type AcmeAccount = JsonRawData;
pub type AcmeOrder = JsonRawData;

#[derive(Debug)]
/// See [core_crypto::e2e_identity::types::E2eiAcmeDirectory]
pub struct AcmeDirectory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
}

impl From<core_crypto::prelude::E2eiAcmeDirectory> for AcmeDirectory {
    fn from(directory: core_crypto::prelude::E2eiAcmeDirectory) -> Self {
        Self {
            new_nonce: directory.new_nonce,
            new_account: directory.new_account,
            new_order: directory.new_order,
        }
    }
}

impl From<AcmeDirectory> for core_crypto::prelude::E2eiAcmeDirectory {
    fn from(directory: AcmeDirectory) -> Self {
        Self {
            new_nonce: directory.new_nonce,
            new_account: directory.new_account,
            new_order: directory.new_order,
        }
    }
}

#[derive(Debug)]
/// See [core_crypto::e2e_identity::types::E2eiNewAcmeOrder]
pub struct NewAcmeOrder {
    pub delegate: JsonRawData,
    pub authorizations: Vec<String>,
}

impl From<core_crypto::prelude::E2eiNewAcmeOrder> for NewAcmeOrder {
    fn from(new_order: core_crypto::prelude::E2eiNewAcmeOrder) -> Self {
        Self {
            delegate: new_order.delegate,
            authorizations: new_order.authorizations,
        }
    }
}

impl From<NewAcmeOrder> for core_crypto::prelude::E2eiNewAcmeOrder {
    fn from(new_order: NewAcmeOrder) -> Self {
        Self {
            delegate: new_order.delegate,
            authorizations: new_order.authorizations,
        }
    }
}

#[derive(Debug)]
/// See [core_crypto::e2e_identity::types::E2eiNewAcmeAuthz]
pub struct NewAcmeAuthz {
    pub identifier: String,
    pub wire_http_challenge: Option<AcmeChallenge>,
    pub wire_oidc_challenge: Option<AcmeChallenge>,
}

impl From<core_crypto::prelude::E2eiNewAcmeAuthz> for NewAcmeAuthz {
    fn from(new_authz: core_crypto::prelude::E2eiNewAcmeAuthz) -> Self {
        Self {
            identifier: new_authz.identifier,
            wire_http_challenge: new_authz.wire_http_challenge.map(Into::into),
            wire_oidc_challenge: new_authz.wire_oidc_challenge.map(Into::into),
        }
    }
}

impl From<NewAcmeAuthz> for core_crypto::prelude::E2eiNewAcmeAuthz {
    fn from(new_authz: NewAcmeAuthz) -> Self {
        Self {
            identifier: new_authz.identifier,
            wire_http_challenge: new_authz.wire_http_challenge.map(Into::into),
            wire_oidc_challenge: new_authz.wire_oidc_challenge.map(Into::into),
        }
    }
}

#[derive(Debug)]
/// See [core_crypto::e2e_identity::types::E2eiAcmeChallenge]
pub struct AcmeChallenge {
    pub delegate: JsonRawData,
    pub url: String,
}

impl From<core_crypto::prelude::E2eiAcmeChallenge> for AcmeChallenge {
    fn from(chall: core_crypto::prelude::E2eiAcmeChallenge) -> Self {
        Self {
            delegate: chall.delegate,
            url: chall.url,
        }
    }
}

impl From<AcmeChallenge> for core_crypto::prelude::E2eiAcmeChallenge {
    fn from(chall: AcmeChallenge) -> Self {
        Self {
            delegate: chall.delegate,
            url: chall.url,
        }
    }
}

#[derive(Debug)]
/// See [core_crypto::e2e_identity::types::E2eiAcmeFinalize]
pub struct AcmeFinalize {
    pub delegate: JsonRawData,
    pub certificate_url: String,
}

impl From<core_crypto::prelude::E2eiAcmeFinalize> for AcmeFinalize {
    fn from(finalize: core_crypto::prelude::E2eiAcmeFinalize) -> Self {
        Self {
            certificate_url: finalize.certificate_url,
            delegate: finalize.delegate,
        }
    }
}

impl From<AcmeFinalize> for core_crypto::prelude::E2eiAcmeFinalize {
    fn from(finalize: AcmeFinalize) -> Self {
        Self {
            certificate_url: finalize.certificate_url,
            delegate: finalize.delegate,
        }
    }
}
