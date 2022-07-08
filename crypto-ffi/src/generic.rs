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

cfg_if::cfg_if! {
    if #[cfg(feature = "mobile")] {
        mod uniffi_support;
        pub use self::uniffi_support::*;
    } else if #[cfg(feature = "c-api")] {
        mod c_api;
        pub use self::c_api::*;
    }
}

use std::collections::HashMap;

use core_crypto::prelude::*;
pub use core_crypto::prelude::{CiphersuiteName, ClientId, ConversationId, CoreCryptoCallbacks, MemberId};
pub use core_crypto::CryptoError;

use futures_lite::future;

#[cfg_attr(feature = "c-api", repr(C))]
#[derive(Debug)]
pub struct MemberAddedMessages {
    pub welcome: Vec<u8>,
    pub message: Vec<u8>,
}

impl TryFrom<MlsConversationCreationMessage> for MemberAddedMessages {
    type Error = CryptoError;

    fn try_from(msg: MlsConversationCreationMessage) -> Result<Self, Self::Error> {
        let (welcome, message) = msg.to_bytes_pairs()?;
        Ok(Self { welcome, message })
    }
}

#[cfg_attr(feature = "c-api", repr(C))]
#[derive(Debug)]
pub struct ConversationLeaveMessages {
    pub self_removal_proposal: Vec<u8>,
    pub other_clients_removal_commit: Option<Vec<u8>>,
}

#[cfg_attr(feature = "c-api", repr(C))]
#[derive(Debug, Clone)]
pub struct Invitee {
    pub id: ClientId,
    pub kp: Vec<u8>,
}

#[cfg_attr(feature = "c-api", repr(C))]
#[derive(Debug)]
pub struct CommitBundle {
    pub welcome: Option<Vec<u8>>,
    pub message: Vec<u8>,
}

#[cfg_attr(feature = "c-api", repr(C))]
#[derive(Debug)]
pub struct MlsConversationInitMessage {
    pub group: Vec<u8>,
    pub message: Vec<u8>,
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
pub struct ConversationConfiguration {
    pub admins: Vec<MemberId>,
    pub ciphersuite: Option<CiphersuiteName>,
    pub key_rotation_span: Option<std::time::Duration>,
    pub external_senders: Vec<Vec<u8>>,
}

impl TryInto<MlsConversationConfiguration> for ConversationConfiguration {
    type Error = CryptoError;
    fn try_into(mut self) -> CryptoResult<MlsConversationConfiguration> {
        use tls_codec::Deserialize as _;
        let external_senders = self
            .external_senders
            .into_iter()
            .map(|s| Ok(Credential::tls_deserialize(&mut &s[..]).map_err(MlsError::from)?))
            .filter_map(|r: CryptoResult<Credential>| r.ok())
            .collect();
        let mut cfg = MlsConversationConfiguration {
            admins: self.admins,
            key_rotation_span: self.key_rotation_span,
            external_senders,
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
    pub fn new<'s>(path: &'s str, key: &'s str, client_id: &'s str) -> CryptoResult<Self> {
        let configuration = MlsCentralConfiguration::try_new(path.into(), key.into(), client_id.into())?;

        let executor = async_executor::Executor::new();

        // TODO: not exposing certificate bundle ATM. Pending e2e identity solution to be defined
        let central = future::block_on(executor.run(MlsCentral::try_new(configuration, None)))?;
        let central = std::sync::Arc::new(central.into());
        Ok(CoreCrypto {
            central,
            executor: std::sync::Arc::new(executor.into()),
        })
    }

    pub fn close(self) -> CryptoResult<()> {
        if let Ok(central_lock) = std::sync::Arc::try_unwrap(self.central) {
            let central = central_lock.into_inner().map_err(|_| CryptoError::LockPoisonError)?;
            future::block_on(central.close())?;
            Ok(())
        } else {
            Err(CryptoError::LockPoisonError)
        }
    }

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
    pub fn set_callbacks(&self, callbacks: Box<dyn CoreCryptoCallbacks>) -> CryptoResult<()> {
        self.central
            .lock()
            .map_err(|_| CryptoError::LockPoisonError)?
            .callbacks(callbacks)
    }

    pub fn client_public_key(&self) -> CryptoResult<Vec<u8>> {
        self.central
            .lock()
            .map_err(|_| CryptoError::LockPoisonError)?
            .client_public_key()
    }

    pub fn client_keypackages(&self, amount_requested: u32) -> CryptoResult<Vec<Vec<u8>>> {
        use core_crypto::prelude::tls_codec::Serialize as _;
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

    pub fn update_keying_material(&self, conversation_id: ConversationId) -> CryptoResult<CommitBundle> {
        use core_crypto::prelude::tls_codec::Serialize as _;

        let result = future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .update_keying_material(conversation_id),
            ),
        )?;
        Ok(CommitBundle {
            message: result.0.tls_serialize_detached().map_err(MlsError::from)?,
            welcome: result
                .1
                .map(|v| v.tls_serialize_detached())
                .transpose()
                .map_err(MlsError::from)?,
        })
    }

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

    pub fn add_clients_to_conversation(
        &self,
        conversation_id: ConversationId,
        clients: Vec<Invitee>,
    ) -> CryptoResult<Option<MemberAddedMessages>> {
        let mut members = Invitee::group_to_conversation_member(clients)?;

        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .add_members_to_conversation(&conversation_id, &mut members),
            ),
        )?
        .map(TryInto::try_into)
        .transpose()
    }

    /// Returns a MLS commit message serialized as TLS
    pub fn remove_clients_from_conversation(
        &self,
        conversation_id: ConversationId,
        clients: Vec<ClientId>,
    ) -> CryptoResult<Option<Vec<u8>>> {
        Ok(future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .remove_members_from_conversation(&conversation_id, &clients),
            ),
        )?
        .map(|m| m.to_bytes().map_err(MlsError::from))
        .transpose()?)
    }

    pub fn leave_conversation(
        &self,
        conversation_id: ConversationId,
        other_clients: &[ClientId],
    ) -> CryptoResult<ConversationLeaveMessages> {
        let messages = future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .leave_conversation(conversation_id, other_clients),
            ),
        )?;
        let ret = ConversationLeaveMessages {
            other_clients_removal_commit: messages.other_clients_removal_commit.and_then(|c| c.to_bytes().ok()),
            self_removal_proposal: messages.self_removal_proposal.to_bytes().map_err(MlsError::from)?,
        };

        Ok(ret)
    }

    pub fn decrypt_message(&self, conversation_id: ConversationId, payload: &[u8]) -> CryptoResult<Option<Vec<u8>>> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .decrypt_message(conversation_id, payload),
            ),
        )
    }

    pub fn encrypt_message(&self, conversation_id: ConversationId, message: &[u8]) -> CryptoResult<Vec<u8>> {
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .encrypt_message(conversation_id, message),
            ),
        )
    }

    pub fn conversation_exists(&self, conversation_id: ConversationId) -> bool {
        let mut central = self.central.lock().map_err(|_| CryptoError::LockPoisonError).ok();

        if let Some(central) = central.take() {
            central.conversation_exists(&conversation_id)
        } else {
            false
        }
    }

    pub fn new_add_proposal(&self, conversation_id: ConversationId, keypackage: Vec<u8>) -> CryptoResult<Vec<u8>> {
        let kp = KeyPackage::try_from(&keypackage[..]).map_err(MlsError::from)?;
        Ok(future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .new_proposal(conversation_id, MlsProposal::Add(kp)),
            ),
        )?
        .to_bytes()
        .map_err(MlsError::from)?)
    }

    pub fn new_update_proposal(&self, conversation_id: ConversationId) -> CryptoResult<Vec<u8>> {
        Ok(future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .new_proposal(conversation_id, MlsProposal::Update),
            ),
        )?
        .to_bytes()
        .map_err(MlsError::from)?)
    }

    pub fn new_remove_proposal(&self, conversation_id: ConversationId, client_id: ClientId) -> CryptoResult<Vec<u8>> {
        Ok(future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .new_proposal(conversation_id, MlsProposal::Remove(client_id)),
            ),
        )?
        .to_bytes()
        .map_err(MlsError::from)?)
    }

    pub fn new_external_add_proposal(
        &self,
        conversation_id: ConversationId,
        epoch: u64,
        keypackage: Vec<u8>,
    ) -> CryptoResult<Vec<u8>> {
        let kp = KeyPackage::try_from(&keypackage[..]).map_err(MlsError::from)?;
        Ok(future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .new_external_add_proposal(conversation_id, epoch.into(), kp),
            ),
        )?
        .to_bytes()
        .map_err(MlsError::from)?)
    }

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

    pub fn export_group_state(&self, conversation_id: ConversationId) -> CryptoResult<Vec<u8>> {
        use core_crypto::prelude::tls_codec::Serialize as _;
        future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .export_group_state(&conversation_id),
            ),
        )
        .map(|state| {
            state
                .tls_serialize_detached()
                .map_err(MlsError::from)
                .map_err(CryptoError::from)
        })?
    }

    pub fn join_by_external_commit(&self, group_state: Vec<u8>) -> CryptoResult<MlsConversationInitMessage> {
        use core_crypto::prelude::tls_codec::Deserialize as _;
        use core_crypto::prelude::tls_codec::Serialize as _;

        let group_state = VerifiablePublicGroupState::tls_deserialize(&mut &group_state[..]).map_err(MlsError::from)?;
        let (group, message) = future::block_on(
            self.executor.lock().map_err(|_| CryptoError::LockPoisonError)?.run(
                self.central
                    .lock()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .join_by_external_commit(group_state),
            ),
        )?;
        Ok(MlsConversationInitMessage {
            message: message
                .tls_serialize_detached()
                .map_err(MlsError::from)
                .map_err(CryptoError::from)?,
            group: group
                .tls_serialize_detached()
                .map_err(MlsError::from)
                .map_err(CryptoError::from)?,
        })
    }

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
}
