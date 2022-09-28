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

use std::collections::HashMap;

use futures_lite::future;

use core_crypto::prelude::*;
pub use core_crypto::prelude::{
    tls_codec::Serialize, CiphersuiteName, ClientId, ConversationId, CoreCryptoCallbacks, CryptoError, MemberId,
};

cfg_if::cfg_if! {
    if #[cfg(feature = "mobile")] {
        mod uniffi_support;
        pub use self::uniffi_support::*;
    }
    // else if #[cfg(feature = "c-api")] {
    //     mod c_api;
    //     pub use self::c_api::*;
    // }
}

#[cfg_attr(feature = "c-api", repr(C))]
#[derive(Debug)]
/// see [core_crypto::prelude::MlsConversationCreationMessage]
pub struct MemberAddedMessages {
    pub welcome: Vec<u8>,
    pub commit: Vec<u8>,
    pub public_group_state: Vec<u8>,
}

impl TryFrom<MlsConversationCreationMessage> for MemberAddedMessages {
    type Error = CryptoError;

    fn try_from(msg: MlsConversationCreationMessage) -> Result<Self, Self::Error> {
        let (welcome, commit, public_group_state) = msg.to_bytes_triple()?;
        Ok(Self {
            welcome,
            commit,
            public_group_state,
        })
    }
}

/// For final version. Requires to be implemented in the Delivery Service
/// see [CommitBundle]
pub type TlsCommitBundle = Vec<u8>;

#[cfg_attr(feature = "c-api", repr(C))]
#[derive(Debug)]
pub struct CommitBundle {
    pub welcome: Option<Vec<u8>>,
    pub commit: Vec<u8>,
    pub public_group_state: Vec<u8>,
}

impl TryFrom<MlsCommitBundle> for CommitBundle {
    type Error = CryptoError;

    fn try_from(msg: MlsCommitBundle) -> Result<Self, Self::Error> {
        let (welcome, commit, public_group_state) = msg.to_bytes_triple()?;
        Ok(Self {
            welcome,
            commit,
            public_group_state,
        })
    }
}

#[cfg_attr(feature = "c-api", repr(C))]
#[derive(Debug, Clone)]
pub struct Invitee {
    pub id: ClientId,
    pub kp: Vec<u8>,
}

#[cfg_attr(feature = "c-api", repr(C))]
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

#[cfg_attr(feature = "c-api", repr(C))]
#[derive(Debug)]
pub struct MlsConversationInitMessage {
    pub conversation_id: Vec<u8>,
    pub commit: Vec<u8>,
}

#[cfg_attr(feature = "c-api", repr(C))]
#[derive(Debug)]
/// See [core_crypto::prelude::decrypt::MlsConversationDecryptMessage]
pub struct DecryptedMessage {
    pub message: Option<Vec<u8>>,
    pub proposals: Vec<ProposalBundle>,
    pub is_active: bool,
    pub commit_delay: Option<u64>,
    pub sender_client_id: Option<ClientId>,
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

#[cfg_attr(feature = "c-api", repr(C))]
#[derive(Debug, Clone)]
/// See [core_crypto::prelude::MlsConversationConfiguration]
pub struct ConversationConfiguration {
    pub admins: Vec<MemberId>,
    pub ciphersuite: Option<CiphersuiteName>,
    pub key_rotation_span: Option<std::time::Duration>,
    pub external_senders: Vec<Vec<u8>>,
}

impl TryInto<MlsConversationConfiguration> for ConversationConfiguration {
    type Error = CryptoError;
    fn try_into(mut self) -> CryptoResult<MlsConversationConfiguration> {
        let mut cfg = MlsConversationConfiguration {
            admins: self.admins,
            key_rotation_span: self.key_rotation_span,
            external_senders: self.external_senders,
            ..Default::default()
        };

        if let Some(ciphersuite) = self.ciphersuite.take() {
            cfg.ciphersuite = ciphersuite.into();
        }

        Ok(cfg)
    }
}

#[derive(Debug)]
pub struct CoreCrypto<'a> {
    central: std::sync::Arc<std::sync::Mutex<MlsCentral>>,
    executor: std::sync::Arc<std::sync::Mutex<async_executor::Executor<'a>>>,
}

#[allow(dead_code, unused_variables)]
impl CoreCrypto<'_> {
    /// See [core_crypto::MlsCentral::try_new]
    pub fn new<'s>(
        path: &'s str,
        key: &'s str,
        client_id: &'s str,
        entropy_seed: Option<Vec<u8>>,
    ) -> CryptoResult<Self> {
        let mut configuration = MlsCentralConfiguration::try_new(path.into(), key.into(), client_id.into())?;

        if let Some(seed) = entropy_seed {
            let owned_seed = EntropySeed::try_from_slice(&seed[..EntropySeed::EXPECTED_LEN])?;
            configuration.set_entropy(owned_seed);
        }

        let executor = async_executor::Executor::new();

        // TODO: not exposing certificate bundle ATM. Pending e2e identity solution to be defined
        let central = future::block_on(executor.run(MlsCentral::try_new(configuration, None)))?;
        let central = std::sync::Arc::new(central.into());
        Ok(CoreCrypto {
            central,
            executor: std::sync::Arc::new(executor.into()),
        })
    }

    /// See [core_crypto::MlsCentral::close]
    pub fn close(self) -> CryptoResult<()> {
        if let Ok(central_lock) = std::sync::Arc::try_unwrap(self.central) {
            let central = central_lock.into_inner().map_err(|_| CryptoError::LockPoisonError)?;
            future::block_on(central.close())?;
            Ok(())
        } else {
            Err(CryptoError::LockPoisonError)
        }
    }

    /// See [core_crypto::MlsCentral::wipe]
    pub fn wipe(self) -> CryptoResult<()> {
        if let Ok(central_lock) = std::sync::Arc::try_unwrap(self.central) {
            let central = central_lock.into_inner().map_err(|_| CryptoError::LockPoisonError)?;
            future::block_on(central.wipe())?;
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
            .callbacks(callbacks);
        Ok(())
    }

    /// See [core_crypto::MlsCentral::client_public_key]
    pub fn client_public_key(&self) -> CryptoResult<Vec<u8>> {
        Ok(self
            .central
            .lock()
            .map_err(|_| CryptoError::LockPoisonError)?
            .client_public_key())
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
    pub fn process_welcome_message(&self, welcome_message: &[u8]) -> CryptoResult<ConversationId> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .process_raw_welcome_message(welcome_message.into()),
            ),
        )
    }

    /// See [core_crypto::MlsCentral::add_members_to_conversation]
    pub fn add_clients_to_conversation(
        &self,
        conversation_id: ConversationId,
        clients: Vec<Invitee>,
    ) -> CryptoResult<MemberAddedMessages> {
        self._add_clients_to_conversation(conversation_id, clients)?.try_into()
    }

    /// See [core_crypto::MlsCentral::remove_members_from_conversation]
    pub fn remove_clients_from_conversation(
        &self,
        conversation_id: ConversationId,
        clients: Vec<ClientId>,
    ) -> CryptoResult<CommitBundle> {
        self._remove_clients_from_conversation(conversation_id, clients)?
            .try_into()
    }

    /// See [core_crypto::MlsCentral::update_keying_material]
    pub fn update_keying_material(&self, conversation_id: ConversationId) -> CryptoResult<CommitBundle> {
        self._update_keying_material(conversation_id)?.try_into()
    }

    /// See [core_crypto::MlsCentral::commit_pending_proposals]
    pub fn commit_pending_proposals(&self, conversation_id: ConversationId) -> CryptoResult<Option<CommitBundle>> {
        self._commit_pending_proposals(conversation_id)
            .transpose()
            .map(|r| r.and_then(|b| b.try_into()))
            .transpose()
    }

    /// See [core_crypto::MlsCentral::add_members_to_conversation]
    pub fn final_add_clients_to_conversation(
        &self,
        conversation_id: ConversationId,
        clients: Vec<Invitee>,
    ) -> CryptoResult<TlsCommitBundle> {
        self._add_clients_to_conversation(conversation_id, clients)?
            .tls_serialize_detached()
            .map_err(MlsError::from)
            .map_err(CryptoError::from)
    }

    /// See [core_crypto::MlsCentral::remove_members_from_conversation]
    pub fn final_remove_clients_from_conversation(
        &self,
        conversation_id: ConversationId,
        clients: Vec<ClientId>,
    ) -> CryptoResult<TlsCommitBundle> {
        self._remove_clients_from_conversation(conversation_id, clients)?
            .tls_serialize_detached()
            .map_err(MlsError::from)
            .map_err(CryptoError::from)
    }

    /// See [core_crypto::MlsCentral::update_keying_material]
    pub fn final_update_keying_material(&self, conversation_id: ConversationId) -> CryptoResult<TlsCommitBundle> {
        self._update_keying_material(conversation_id)?
            .tls_serialize_detached()
            .map_err(MlsError::from)
            .map_err(CryptoError::from)
    }

    /// See [core_crypto::MlsCentral::commit_pending_proposals]
    pub fn final_commit_pending_proposals(
        &self,
        conversation_id: ConversationId,
    ) -> CryptoResult<Option<TlsCommitBundle>> {
        self._commit_pending_proposals(conversation_id)
            .transpose()
            .map(|r| {
                r.and_then(|b| {
                    b.tls_serialize_detached()
                        .map_err(MlsError::from)
                        .map_err(CryptoError::from)
                })
            })
            .transpose()
    }

    fn _add_clients_to_conversation(
        &self,
        conversation_id: ConversationId,
        clients: Vec<Invitee>,
    ) -> CryptoResult<MlsConversationCreationMessage> {
        let mut members = Invitee::group_to_conversation_member(clients)?;

        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .add_members_to_conversation(&conversation_id, &mut members),
            ),
        )
    }

    fn _remove_clients_from_conversation(
        &self,
        conversation_id: ConversationId,
        clients: Vec<ClientId>,
    ) -> CryptoResult<MlsCommitBundle> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .remove_members_from_conversation(&conversation_id, &clients),
            ),
        )
    }

    fn _update_keying_material(&self, conversation_id: ConversationId) -> CryptoResult<MlsCommitBundle> {
        future::block_on({
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .update_keying_material(&conversation_id),
            )
        })
    }

    fn _commit_pending_proposals(&self, conversation_id: ConversationId) -> CryptoResult<Option<MlsCommitBundle>> {
        future::block_on({
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .commit_pending_proposals(&conversation_id),
            )
        })
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
    pub fn join_by_external_commit(&self, group_state: Vec<u8>) -> CryptoResult<MlsConversationInitMessage> {
        use core_crypto::prelude::tls_codec::Deserialize as _;

        let group_state = VerifiablePublicGroupState::tls_deserialize(&mut &group_state[..]).map_err(MlsError::from)?;
        let (conversation_id, commit) = future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .join_by_external_commit(group_state),
            ),
        )?;
        Ok(MlsConversationInitMessage {
            conversation_id,
            commit: commit.tls_serialize_detached().map_err(MlsError::from)?,
        })
    }

    /// See [core_crypto::MlsCentral::merge_pending_group_from_external_commit]
    pub fn merge_pending_group_from_external_commit(
        &self,
        conversation_id: ConversationId,
        configuration: ConversationConfiguration,
    ) -> CryptoResult<()> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .merge_pending_group_from_external_commit(&conversation_id, configuration.try_into()?),
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
}
