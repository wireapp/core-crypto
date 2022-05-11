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

#[cfg(feature = "mobile")]
uniffi_macros::include_scaffolding!("CoreCrypto");

#[cfg(feature = "mobile")]
mod uniffi_support;

use std::collections::HashMap;

use core_crypto::prelude::*;
pub use core_crypto::CryptoError;

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

#[derive(Debug, Clone)]
pub struct Invitee {
    pub id: ClientId,
    pub kp: Vec<u8>,
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
pub struct ConversationConfiguration {
    pub extra_members: Vec<Invitee>,
    pub admins: Vec<MemberId>,
    pub ciphersuite: Option<CiphersuiteName>,
    pub key_rotation_span: Option<std::time::Duration>,
}

impl TryInto<MlsConversationConfiguration> for ConversationConfiguration {
    type Error = CryptoError;
    fn try_into(mut self) -> CryptoResult<MlsConversationConfiguration> {
        let mut cfg = MlsConversationConfiguration::builder();
        let extra_members = self
            .extra_members
            .into_iter()
            .map(TryInto::try_into)
            .collect::<CryptoResult<Vec<ConversationMember>>>()?;

        cfg.extra_members(extra_members);
        cfg.admins(self.admins);
        cfg.key_rotation_span(self.key_rotation_span);

        if let Some(ciphersuite) = self.ciphersuite.take() {
            cfg.ciphersuite(ciphersuite.into());
        }

        Ok(cfg.build()?)
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct CoreCrypto(MlsCentral);

#[allow(dead_code, unused_variables)]
impl CoreCrypto {
    pub fn new(path: &str, key: &str, client_id: &str) -> CryptoResult<Self> {
        let configuration = MlsCentralConfiguration::try_new(path.into(), key.into(), client_id.into())?;
        MlsCentral::try_new(configuration).map(Self)
    }

    #[cfg(feature = "mobile")]
    pub fn set_callbacks(&self, callbacks: Box<dyn CoreCryptoCallbacks>) -> CryptoResult<()> {
        self.0.callbacks(callbacks)
    }

    pub fn client_public_key(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.0.client()?.public_key().into())
    }

    pub fn client_keypackages(&self, amount_requested: u32) -> CryptoResult<Vec<Vec<u8>>> {
        use core_crypto::prelude::tls_codec::Serialize as _;
        Ok(self
            .0
            .client_mut()?
            .request_keying_material(amount_requested as usize, self.0.backend())?
            .into_iter()
            .map(|kpb| {
                kpb.key_package()
                    .tls_serialize_detached()
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
            })
            .collect::<CryptoResult<Vec<Vec<u8>>>>()?)
    }

    pub fn client_prune_keypackages(&self, refs: Vec<Vec<u8>>) -> CryptoResult<()> {
        let refs = refs.into_iter().try_fold(vec![], |mut acc, href| -> CryptoResult<_> {
            use tls_codec::Deserialize as _;
            acc.push(KeyPackageRef::tls_deserialize(&mut &href[..]).map_err(MlsError::from)?);
            Ok(acc)
        })?;

        Ok(self.0.client_mut()?.prune_keypackages(&refs, self.0.backend())?)
    }

    pub fn create_conversation(
        &self,
        conversation_id: ConversationId,
        config: ConversationConfiguration,
    ) -> CryptoResult<Option<MemberAddedMessages>> {
        self.0
            .new_conversation(conversation_id, config.try_into()?)?
            .map(TryInto::try_into)
            .transpose()
    }

    pub fn process_welcome_message(
        &self,
        welcome_message: &[u8],
        config: ConversationConfiguration,
    ) -> CryptoResult<ConversationId> {
        self.0
            .process_raw_welcome_message(welcome_message.into(), config.try_into()?)
    }

    pub fn add_clients_to_conversation(
        &self,
        conversation_id: ConversationId,
        clients: Vec<Invitee>,
    ) -> CryptoResult<Option<MemberAddedMessages>> {
        let mut members = Invitee::group_to_conversation_member(clients)?;

        self.0
            .add_members_to_conversation(&conversation_id, &mut members)?
            .map(TryInto::try_into)
            .transpose()
    }

    /// Returns a MLS commit message serialized as TLS
    pub fn remove_clients_from_conversation(
        &self,
        conversation_id: ConversationId,
        clients: Vec<Invitee>,
    ) -> CryptoResult<Option<Vec<u8>>> {
        let members = Invitee::group_to_conversation_member(clients)?;

        Ok(self
            .0
            .remove_members_from_conversation(&conversation_id, &members)?
            .map(|m| m.to_bytes().map_err(MlsError::from))
            .transpose()?)
    }

    pub fn decrypt_message(&self, conversation_id: ConversationId, payload: &[u8]) -> CryptoResult<Option<Vec<u8>>> {
        self.0.decrypt_message(conversation_id, payload)
    }

    pub fn encrypt_message(&self, conversation_id: ConversationId, message: &[u8]) -> CryptoResult<Vec<u8>> {
        self.0.encrypt_message(conversation_id, message)
    }

    pub fn new_add_proposal(&self, conversation_id: ConversationId, key_package: Vec<u8>) -> CryptoResult<Vec<u8>> {
        use core_crypto::prelude::tls_codec::Serialize as _;
        let kp = KeyPackage::try_from(&key_package[..]).map_err(MlsError::from)?;
        self.0
            .new_proposal(conversation_id, MlsProposal::Add(kp))?
            .tls_serialize_detached()
            .map_err(MlsError::from)
            .map_err(CryptoError::from)
    }

    pub fn new_update_proposal(&self, conversation_id: ConversationId) -> CryptoResult<Vec<u8>> {
        use core_crypto::prelude::tls_codec::Serialize as _;
        self.0
            .new_proposal(conversation_id, MlsProposal::Update)?
            .tls_serialize_detached()
            .map_err(MlsError::from)
            .map_err(CryptoError::from)
    }

    pub fn new_remove_proposal(&self, conversation_id: ConversationId, client_id: ClientId) -> CryptoResult<Vec<u8>> {
        use core_crypto::prelude::tls_codec::Serialize as _;
        self.0
            .new_proposal(conversation_id, MlsProposal::Remove(client_id))?
            .tls_serialize_detached()
            .map_err(MlsError::from)
            .map_err(CryptoError::from)
    }

    pub fn conversation_exists(&self, conversation_id: ConversationId) -> bool {
        self.0.conversation_exists(&conversation_id)
    }
}

// #[cfg(not(wasm))]
#[no_mangle]
pub fn init_with_path_and_key(path: &str, key: &str, client_id: &str) -> CryptoResult<std::sync::Arc<CoreCrypto>> {
    Ok(std::sync::Arc::new(CoreCrypto::new(path, key, client_id)?))
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[no_mangle]
pub fn version() -> String {
    VERSION.to_string()
}
