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

use core_crypto::prelude::{
    ClientIdentifier, ConversationMember, EntropySeed, KeyPackageIn, KeyPackageRef, MlsCentral,
    MlsCentralConfiguration, MlsCiphersuite, MlsCommitBundle, MlsConversationConfiguration,
    MlsConversationCreationMessage, MlsConversationDecryptMessage, MlsConversationInitBundle, MlsCryptoProvider,
    MlsCustomConfiguration, MlsGroupInfoBundle, MlsProposalBundle, MlsRotateBundle, VerifiableGroupInfo,
};
use core_crypto::{CryptoResult, MlsError};
use std::collections::HashMap;
use tls_codec::{Deserialize, Serialize};

pub use core_crypto::prelude::{
    CiphersuiteName, ConversationId, CryptoError, E2eIdentityError, E2eIdentityResult, E2eiConversationState, MemberId,
    MlsCredentialType, MlsGroupInfoEncryptionType, MlsRatchetTreeType, MlsWirePolicy,
};

mod uniffi_support;
pub use self::uniffi_support::*;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct ClientId(core_crypto::prelude::ClientId);

#[derive(Debug, Clone)]
pub struct Ciphersuite(CiphersuiteName);

impl From<CiphersuiteName> for Ciphersuite {
    fn from(cs: CiphersuiteName) -> Self {
        Self(cs)
    }
}

impl From<Ciphersuite> for CiphersuiteName {
    fn from(cs: Ciphersuite) -> Self {
        cs.0
    }
}

impl From<Ciphersuite> for MlsCiphersuite {
    fn from(cs: Ciphersuite) -> Self {
        cs.0.into()
    }
}

#[derive(Debug, Clone)]
pub struct Ciphersuites(Vec<CiphersuiteName>);

impl From<Vec<CiphersuiteName>> for Ciphersuites {
    fn from(cs: Vec<CiphersuiteName>) -> Self {
        Self(cs)
    }
}

impl From<Ciphersuites> for Vec<CiphersuiteName> {
    fn from(cs: Ciphersuites) -> Self {
        cs.0
    }
}

impl<'a> From<&'a Ciphersuites> for Vec<MlsCiphersuite> {
    fn from(cs: &'a Ciphersuites) -> Self {
        cs.0.iter().fold(Vec::with_capacity(cs.0.len()), |mut acc, c| {
            acc.push((*c).into());
            acc
        })
    }
}

#[derive(Debug, Clone)]
pub struct ProteusAutoPrekeyBundle {
    pub id: u16,
    pub pkb: Vec<u8>,
}

#[derive(Debug)]
/// see [core_crypto::prelude::MlsConversationCreationMessage]
pub struct MemberAddedMessages {
    pub welcome: Vec<u8>,
    pub commit: Vec<u8>,
    pub group_info: GroupInfoBundle,
}

impl TryFrom<MlsConversationCreationMessage> for MemberAddedMessages {
    type Error = CryptoError;

    fn try_from(msg: MlsConversationCreationMessage) -> Result<Self, Self::Error> {
        let (welcome, commit, group_info) = msg.to_bytes_triple()?;
        Ok(Self {
            welcome,
            commit,
            group_info: group_info.into(),
        })
    }
}

#[derive(Debug)]
pub struct CommitBundle {
    pub welcome: Option<Vec<u8>>,
    pub commit: Vec<u8>,
    pub group_info: GroupInfoBundle,
}

impl TryFrom<MlsCommitBundle> for CommitBundle {
    type Error = CryptoError;

    fn try_from(msg: MlsCommitBundle) -> Result<Self, Self::Error> {
        let (welcome, commit, group_info) = msg.to_bytes_triple()?;
        Ok(Self {
            welcome,
            commit,
            group_info: group_info.into(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct GroupInfoBundle {
    pub encryption_type: MlsGroupInfoEncryptionType,
    pub ratchet_tree_type: MlsRatchetTreeType,
    pub payload: Vec<u8>,
}

impl From<MlsGroupInfoBundle> for GroupInfoBundle {
    fn from(gi: MlsGroupInfoBundle) -> Self {
        Self {
            encryption_type: gi.encryption_type,
            ratchet_tree_type: gi.ratchet_tree_type,
            payload: gi.payload.bytes(),
        }
    }
}

#[derive(Debug)]
pub struct RotateBundle {
    pub commits: Vec<CommitBundle>,
    pub new_key_packages: Vec<Vec<u8>>,
    pub key_package_refs_to_remove: Vec<Vec<u8>>,
}

impl TryFrom<MlsRotateBundle> for RotateBundle {
    type Error = CryptoError;

    fn try_from(bundle: MlsRotateBundle) -> Result<Self, Self::Error> {
        let (commits, new_key_packages, key_package_refs_to_remove) = bundle.to_bytes()?;
        let commits_size = commits.len();
        let commits = commits
            .into_iter()
            .try_fold(Vec::with_capacity(commits_size), |mut acc, c| {
                acc.push(c.try_into()?);
                CryptoResult::Ok(acc)
            })?;
        Ok(Self {
            commits,
            new_key_packages,
            key_package_refs_to_remove,
        })
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
    pub conversation_id: Vec<u8>,
    pub commit: Vec<u8>,
    pub group_info: GroupInfoBundle,
}

impl TryFrom<MlsConversationInitBundle> for ConversationInitBundle {
    type Error = CryptoError;

    fn try_from(mut from: MlsConversationInitBundle) -> Result<Self, Self::Error> {
        let conversation_id = std::mem::take(&mut from.conversation_id);
        let (commit, gi) = from.to_bytes_pair()?;
        Ok(Self {
            conversation_id,
            commit,
            group_info: gi.into(),
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
    pub identity: Option<WireIdentity>,
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
            sender_client_id: from.sender_client_id.map(ClientId),
            has_epoch_changed: from.has_epoch_changed,
            identity: from.identity.map(Into::into),
        })
    }
}

#[derive(Debug)]
/// See [core_crypto::prelude::WireIdentity]
pub struct WireIdentity {
    pub client_id: String,
    pub handle: String,
    pub display_name: String,
    pub domain: String,
}

impl From<core_crypto::prelude::WireIdentity> for WireIdentity {
    fn from(i: core_crypto::prelude::WireIdentity) -> Self {
        Self {
            client_id: i.client_id,
            handle: i.handle,
            display_name: i.display_name,
            domain: i.domain,
        }
    }
}

impl Invitee {
    #[inline(always)]
    fn group_to_conversation_member(
        clients: Vec<Self>,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Vec<ConversationMember>> {
        Ok(clients
            .into_iter()
            .try_fold(
                HashMap::new(),
                |mut acc, c| -> CryptoResult<HashMap<ClientId, ConversationMember>> {
                    if let Some(member) = acc.get_mut(&c.id) {
                        member.add_keypackage(c.kp, backend)?;
                    } else {
                        acc.insert(c.id.clone(), ConversationMember::new_raw(c.id.0, c.kp, backend)?);
                    }
                    Ok(acc)
                },
            )?
            .into_values()
            .collect::<Vec<ConversationMember>>())
    }
}

#[derive(Debug, Clone)]
/// See [core_crypto::prelude::MlsConversationConfiguration]
pub struct ConversationConfiguration {
    pub ciphersuite: Ciphersuite,
    pub external_senders: Vec<Vec<u8>>,
    pub custom: CustomConfiguration,
    pub per_domain_trust_anchors: Vec<PerDomainTrustAnchor>,
}

#[derive(Debug, Clone)]
/// See [core_crypto::prelude::PerDomainTrustAnchor]
pub struct PerDomainTrustAnchor {
    pub domain_name: String,
    pub intermediate_certificate_chain: String,
}

impl TryInto<MlsConversationConfiguration> for ConversationConfiguration {
    type Error = CryptoError;
    fn try_into(self) -> CryptoResult<MlsConversationConfiguration> {
        let mut cfg = MlsConversationConfiguration {
            custom: self.custom.into(),
            ciphersuite: self.ciphersuite.into(),
            ..Default::default()
        };

        cfg.set_raw_external_senders(self.external_senders);

        cfg.per_domain_trust_anchors = self.per_domain_trust_anchors.into_iter().map(|a| a.into()).collect();

        Ok(cfg)
    }
}

impl From<PerDomainTrustAnchor> for core_crypto::prelude::PerDomainTrustAnchor {
    fn from(cfg: PerDomainTrustAnchor) -> Self {
        Self {
            domain_name: cfg.domain_name,
            intermediate_certificate_chain: cfg.intermediate_certificate_chain,
        }
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

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl core_crypto::prelude::CoreCryptoCallbacks for CoreCryptoCallbacksWrapper {
    async fn authorize(&self, conversation_id: Vec<u8>, client_id: core_crypto::prelude::ClientId) -> bool {
        self.0.authorize(conversation_id, ClientId(client_id))
    }
    async fn user_authorize(
        &self,
        conversation_id: Vec<u8>,
        external_client_id: core_crypto::prelude::ClientId,
        existing_clients: Vec<core_crypto::prelude::ClientId>,
    ) -> bool {
        self.0.user_authorize(
            conversation_id,
            ClientId(external_client_id),
            existing_clients.into_iter().map(ClientId).collect(),
        )
    }
    async fn client_is_existing_group_user(
        &self,
        conversation_id: Vec<u8>,
        client_id: core_crypto::prelude::ClientId,
        existing_clients: Vec<core_crypto::prelude::ClientId>,
        parent_conversation_clients: Option<Vec<core_crypto::prelude::ClientId>>,
    ) -> bool {
        self.0.client_is_existing_group_user(
            conversation_id,
            ClientId(client_id),
            existing_clients.into_iter().map(ClientId).collect(),
            parent_conversation_clients.map(|pccs| pccs.into_iter().map(ClientId).collect()),
        )
    }
}

/// This only exists to create a sync interface to our internal async callback interface
// TODO: Remove this once UniFFI supports async callbacks
pub trait CoreCryptoCallbacks: std::fmt::Debug + Send + Sync {
    fn authorize(&self, conversation_id: Vec<u8>, client_id: ClientId) -> bool;
    fn user_authorize(
        &self,
        conversation_id: Vec<u8>,
        external_client_id: ClientId,
        existing_clients: Vec<ClientId>,
    ) -> bool;
    fn client_is_existing_group_user(
        &self,
        conversation_id: Vec<u8>,
        client_id: ClientId,
        existing_clients: Vec<ClientId>,
        parent_conversation_clients: Option<Vec<ClientId>>,
    ) -> bool;
}

#[derive(Debug, uniffi::Object)]
pub struct CoreCrypto {
    central: async_lock::Mutex<core_crypto::CoreCrypto>,
    proteus_last_error_code: std::sync::atomic::AtomicU32,
}

#[uniffi::export]
/// See [core_crypto::mls::MlsCentral::try_new]
pub async fn core_crypto_new(
    path: String,
    key: String,
    client_id: ClientId,
    ciphersuites: Ciphersuites,
) -> CryptoResult<std::sync::Arc<CoreCrypto>> {
    let configuration =
        MlsCentralConfiguration::try_new(path, key, Some(client_id.0.clone()), (&ciphersuites).into(), None)?;

    let central = MlsCentral::try_new(configuration).await?;
    let central = core_crypto::CoreCrypto::from(central).into();
    Ok(CoreCrypto {
        central,
        proteus_last_error_code: std::sync::atomic::AtomicU32::new(0),
    }
    .into())
}

#[uniffi::export]
/// Similar to [CoreCrypto::new] but defers MLS initialization. It can be initialized later
/// with [CoreCrypto::mls_init].
pub async fn core_crypto_deferred_init(
    path: String,
    key: String,
    ciphersuites: Ciphersuites,
) -> CryptoResult<std::sync::Arc<CoreCrypto>> {
    let configuration = MlsCentralConfiguration::try_new(path, key, None, (&ciphersuites).into(), None)?;

    let central = MlsCentral::try_new(configuration).await?;
    let central = core_crypto::CoreCrypto::from(central).into();
    Ok(CoreCrypto {
        central,
        proteus_last_error_code: std::sync::atomic::AtomicU32::new(0),
    }
    .into())
}

#[allow(dead_code, unused_variables)]
#[uniffi::export]
impl CoreCrypto {
    /// See [core_crypto::mls::MlsCentral::mls_init]
    pub async fn mls_init(&self, client_id: ClientId, ciphersuites: Ciphersuites) -> CryptoResult<()> {
        self.central
            .lock()
            .await
            .mls_init(ClientIdentifier::Basic(client_id.0), (&ciphersuites).into())
            .await
    }

    /// See [core_crypto::mls::MlsCentral::mls_generate_keypairs]
    pub async fn mls_generate_keypairs(&self, ciphersuites: Ciphersuites) -> CryptoResult<Vec<ClientId>> {
        self.central
            .lock()
            .await
            .mls_generate_keypairs((&ciphersuites).into())
            .await
            .map(|cids| cids.into_iter().map(ClientId).collect())
    }

    /// See [core_crypto::mls::MlsCentral::mls_init_with_client_id]
    pub async fn mls_init_with_client_id(
        &self,
        client_id: ClientId,
        tmp_client_ids: Vec<ClientId>,
        ciphersuites: Ciphersuites,
    ) -> CryptoResult<()> {
        self.central
            .lock()
            .await
            .mls_init_with_client_id(
                client_id.0,
                tmp_client_ids.into_iter().map(|cid| cid.0).collect(),
                (&ciphersuites).into(),
            )
            .await
    }

    /// See [core_crypto::mls::MlsCentral::restore_from_disk]
    pub async fn restore_from_disk(&self) -> CryptoResult<()> {
        let mut central = self.central.lock().await;

        central.restore_from_disk().await?;
        cfg_if::cfg_if! {
            if #[cfg(feature = "proteus")] {
                central.proteus_reload_sessions().await.map_err(|e|{
                    let errcode = e.proteus_error_code();
                    if errcode > 0 {
                        self.proteus_last_error_code.store(errcode, std::sync::atomic::Ordering::SeqCst);
                    }
                    e
                })?;
            }
        }

        Ok(())
    }

    /// See [core_crypto::mls::MlsCentral::close]
    pub async fn unload(self: std::sync::Arc<Self>) -> CryptoResult<()> {
        if let Some(cc) = std::sync::Arc::into_inner(self) {
            let central = cc.central.into_inner();
            central.take().close().await?;
            Ok(())
        } else {
            Err(CryptoError::LockPoisonError)
        }
    }

    /// See [core_crypto::mls::MlsCentral::wipe]
    pub async fn wipe(self: std::sync::Arc<Self>) -> CryptoResult<()> {
        if let Some(cc) = std::sync::Arc::into_inner(self) {
            let central = cc.central.into_inner();
            central.take().wipe().await?;
            Ok(())
        } else {
            Err(CryptoError::LockPoisonError)
        }
    }

    /// See [core_crypto::mls::MlsCentral::callbacks]
    pub async fn set_callbacks(&self, callbacks: Box<dyn CoreCryptoCallbacks>) -> CryptoResult<()> {
        self.central
            .lock()
            .await
            .callbacks(Box::new(CoreCryptoCallbacksWrapper(callbacks)));
        Ok(())
    }

    /// See [core_crypto::mls::MlsCentral::client_public_key]
    pub async fn client_public_key(&self, ciphersuite: Ciphersuite) -> CryptoResult<Vec<u8>> {
        self.central.lock().await.client_public_key(ciphersuite.into())
    }

    /// See [core_crypto::mls::MlsCentral::get_or_create_client_keypackages]
    pub async fn client_keypackages(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: MlsCredentialType,
        amount_requested: u32,
    ) -> CryptoResult<Vec<Vec<u8>>> {
        let kps = self
            .central
            .lock()
            .await
            .get_or_create_client_keypackages(ciphersuite.into(), credential_type, amount_requested as usize)
            .await?;

        kps.into_iter()
            .map(|kp| {
                kp.tls_serialize_detached()
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
            })
            .collect::<CryptoResult<Vec<Vec<u8>>>>()
    }

    /// See [core_crypto::mls::MlsCentral::client_valid_key_packages_count]
    pub async fn client_valid_keypackages_count(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: MlsCredentialType,
    ) -> CryptoResult<u64> {
        let count = self
            .central
            .lock()
            .await
            .client_valid_key_packages_count(ciphersuite.into(), credential_type)
            .await?;

        Ok(count.try_into().unwrap_or(0))
    }

    /// See [core_crypto::mls::MlsCentral::delete_keypackages]
    pub async fn delete_keypackages(&self, refs: Vec<Vec<u8>>) -> CryptoResult<()> {
        let refs = refs
            .into_iter()
            .map(|r| KeyPackageRef::from_slice(&r))
            .collect::<Vec<_>>();

        self.central.lock().await.delete_keypackages(&refs[..]).await
    }

    /// See [core_crypto::mls::MlsCentral::new_conversation]
    pub async fn create_conversation(
        &self,
        conversation_id: Vec<u8>,
        creator_credential_type: MlsCredentialType,
        config: ConversationConfiguration,
    ) -> CryptoResult<()> {
        self.central
            .lock()
            .await
            .new_conversation(conversation_id, creator_credential_type, config.try_into()?)
            .await
    }

    /// See [core_crypto::mls::MlsCentral::conversation_epoch]
    pub async fn conversation_epoch(&self, conversation_id: Vec<u8>) -> CryptoResult<u64> {
        self.central.lock().await.conversation_epoch(&conversation_id).await
    }

    /// See [core_crypto::mls::MlsCentral::process_raw_welcome_message]
    pub async fn process_welcome_message(
        &self,
        welcome_message: Vec<u8>,
        custom_configuration: CustomConfiguration,
    ) -> CryptoResult<Vec<u8>> {
        self.central
            .lock()
            .await
            .process_raw_welcome_message(welcome_message, custom_configuration.into())
            .await
    }

    /// See [core_crypto::mls::MlsCentral::add_members_to_conversation]
    pub async fn add_clients_to_conversation(
        &self,
        conversation_id: Vec<u8>,
        clients: Vec<Invitee>,
    ) -> CryptoResult<MemberAddedMessages> {
        let mut members = Invitee::group_to_conversation_member(clients, self.central.lock().await.provider())?;

        self.central
            .lock()
            .await
            .add_members_to_conversation(&conversation_id, &mut members)
            .await?
            .try_into()
    }

    /// See [core_crypto::mls::MlsCentral::remove_members_from_conversation]
    pub async fn remove_clients_from_conversation(
        &self,
        conversation_id: Vec<u8>,
        clients: Vec<ClientId>,
    ) -> CryptoResult<CommitBundle> {
        let clients: Vec<core_crypto::prelude::ClientId> = clients.into_iter().map(|c| c.0).collect();
        self.central
            .lock()
            .await
            .remove_members_from_conversation(&conversation_id, &clients)
            .await?
            .try_into()
    }

    /// See [core_crypto::mls::MlsCentral::mark_conversation_as_child_of]
    pub async fn mark_conversation_as_child_of(&self, child_id: Vec<u8>, parent_id: Vec<u8>) -> CryptoResult<()> {
        self.central
            .lock()
            .await
            .mark_conversation_as_child_of(&child_id, &parent_id)
            .await
    }

    /// See [core_crypto::mls::MlsCentral::update_keying_material]
    pub async fn update_keying_material(&self, conversation_id: Vec<u8>) -> CryptoResult<CommitBundle> {
        self.central
            .lock()
            .await
            .update_keying_material(&conversation_id)
            .await?
            .try_into()
    }

    /// See [core_crypto::mls::MlsCentral::commit_pending_proposals]
    pub async fn commit_pending_proposals(&self, conversation_id: Vec<u8>) -> CryptoResult<Option<CommitBundle>> {
        self.central
            .lock()
            .await
            .commit_pending_proposals(&conversation_id)
            .await
            .transpose()
            .map(|r| r.and_then(|b| b.try_into()))
            .transpose()
    }

    /// see [core_crypto::mls::MlsCentral::wipe_conversation]
    pub async fn wipe_conversation(&self, conversation_id: Vec<u8>) -> CryptoResult<()> {
        self.central.lock().await.wipe_conversation(&conversation_id).await
    }

    /// See [core_crypto::mls::MlsCentral::decrypt_message]
    pub async fn decrypt_message(&self, conversation_id: Vec<u8>, payload: Vec<u8>) -> CryptoResult<DecryptedMessage> {
        let raw_decrypted_message = self
            .central
            .lock()
            .await
            .decrypt_message(&conversation_id, payload)
            .await?;

        let decrypted_message: DecryptedMessage = raw_decrypted_message.try_into()?;

        Ok(decrypted_message)
    }

    /// See [core_crypto::mls::MlsCentral::encrypt_message]
    pub async fn encrypt_message(&self, conversation_id: Vec<u8>, message: Vec<u8>) -> CryptoResult<Vec<u8>> {
        self.central
            .lock()
            .await
            .encrypt_message(&conversation_id, message)
            .await
    }

    /// See [core_crypto::mls::MlsCentral::update_trust_anchors_from_conversation]
    pub async fn update_trust_anchors_from_conversation(
        &self,
        id: ConversationId,
        remove_domain_names: Vec<String>,
        add_trust_anchors: Vec<PerDomainTrustAnchor>,
    ) -> CryptoResult<CommitBundle> {
        self.central
            .lock()
            .await
            .update_trust_anchors_from_conversation(
                &id,
                remove_domain_names,
                add_trust_anchors.into_iter().map(|a| a.into()).collect(),
            )
            .await?
            .try_into()
    }

    /// See [core_crypto::mls::MlsCentral::conversation_exists]
    pub async fn conversation_exists(&self, conversation_id: Vec<u8>) -> bool {
        self.central.lock().await.conversation_exists(&conversation_id).await
    }

    /// See [core_crypto::mls::MlsCentral::new_add_proposal]
    pub async fn new_add_proposal(
        &self,
        conversation_id: Vec<u8>,
        keypackage: Vec<u8>,
    ) -> CryptoResult<ProposalBundle> {
        let kp = KeyPackageIn::tls_deserialize_bytes(keypackage).map_err(MlsError::from)?;
        self.central
            .lock()
            .await
            .new_add_proposal(&conversation_id, kp.into())
            .await?
            .try_into()
    }

    /// See [core_crypto::mls::MlsCentral::new_update_proposal]
    pub async fn new_update_proposal(&self, conversation_id: Vec<u8>) -> CryptoResult<ProposalBundle> {
        self.central
            .lock()
            .await
            .new_update_proposal(&conversation_id)
            .await?
            .try_into()
    }

    /// See [core_crypto::mls::MlsCentral::new_remove_proposal]
    pub async fn new_remove_proposal(
        &self,
        conversation_id: Vec<u8>,
        client_id: ClientId,
    ) -> CryptoResult<ProposalBundle> {
        self.central
            .lock()
            .await
            .new_remove_proposal(&conversation_id, client_id.0)
            .await?
            .try_into()
    }

    /// See [core_crypto::mls::MlsCentral::new_external_add_proposal]
    pub async fn new_external_add_proposal(
        &self,
        conversation_id: Vec<u8>,
        epoch: u64,
        ciphersuite: Ciphersuite,
        credential_type: MlsCredentialType,
    ) -> CryptoResult<Vec<u8>> {
        Ok(self
            .central
            .lock()
            .await
            .new_external_add_proposal(conversation_id, epoch.into(), ciphersuite.into(), credential_type)
            .await?
            .to_bytes()
            .map_err(MlsError::from)?)
    }

    /// See [core_crypto::mls::MlsCentral::join_by_external_commit]
    pub async fn join_by_external_commit(
        &self,
        group_info: Vec<u8>,
        custom_configuration: CustomConfiguration,
        credential_type: MlsCredentialType,
    ) -> CryptoResult<ConversationInitBundle> {
        let group_info = VerifiableGroupInfo::tls_deserialize_bytes(group_info).map_err(MlsError::from)?;
        self.central
            .lock()
            .await
            .join_by_external_commit(group_info, custom_configuration.into(), credential_type)
            .await?
            .try_into()
    }

    /// See [core_crypto::mls::MlsCentral::merge_pending_group_from_external_commit]
    pub async fn merge_pending_group_from_external_commit(
        &self,
        conversation_id: Vec<u8>,
    ) -> CryptoResult<Option<Vec<DecryptedMessage>>> {
        if let Some(decrypted_messages) = self
            .central
            .lock()
            .await
            .merge_pending_group_from_external_commit(&conversation_id)
            .await?
        {
            return Ok(Some(
                decrypted_messages
                    .into_iter()
                    .map(DecryptedMessage::try_from)
                    .collect::<CryptoResult<Vec<_>>>()?,
            ));
        }

        Ok(None)
    }

    /// See [core_crypto::mls::MlsCentral::clear_pending_group_from_external_commit]
    pub async fn clear_pending_group_from_external_commit(&self, conversation_id: Vec<u8>) -> CryptoResult<()> {
        self.central
            .lock()
            .await
            .clear_pending_group_from_external_commit(&conversation_id)
            .await?;

        Ok(())
    }

    /// See [core_crypto::mls::MlsCentral::random_bytes]
    pub async fn random_bytes(&self, len: u32) -> CryptoResult<Vec<u8>> {
        self.central.lock().await.random_bytes(len.try_into()?)
    }

    /// see [MlsCryptoProvider::reseed]
    pub async fn reseed_rng(&self, seed: Vec<u8>) -> CryptoResult<()> {
        let seed = EntropySeed::try_from_slice(&seed)?;
        self.central.lock().await.provider_mut().reseed(Some(seed));

        Ok(())
    }

    /// See [core_crypto::mls::MlsCentral::commit_accepted]
    pub async fn commit_accepted(&self, conversation_id: Vec<u8>) -> CryptoResult<()> {
        self.central.lock().await.commit_accepted(&conversation_id).await
    }

    /// See [core_crypto::mls::MlsCentral::clear_pending_proposal]
    pub async fn clear_pending_proposal(&self, conversation_id: Vec<u8>, proposal_ref: Vec<u8>) -> CryptoResult<()> {
        self.central
            .lock()
            .await
            .clear_pending_proposal(&conversation_id, proposal_ref)
            .await
    }

    /// See [core_crypto::mls::MlsCentral::clear_pending_commit]
    pub async fn clear_pending_commit(&self, conversation_id: Vec<u8>) -> CryptoResult<()> {
        self.central.lock().await.clear_pending_commit(&conversation_id).await
    }

    /// See [core_crypto::mls::MlsCentral::get_client_ids]
    pub async fn get_client_ids(&self, conversation_id: Vec<u8>) -> CryptoResult<Vec<ClientId>> {
        self.central
            .lock()
            .await
            .get_client_ids(&conversation_id)
            .await
            .map(|cids| cids.into_iter().map(ClientId).collect())
    }

    /// See [core_crypto::mls::MlsCentral::export_secret_key]
    pub async fn export_secret_key(&self, conversation_id: Vec<u8>, key_length: u32) -> CryptoResult<Vec<u8>> {
        self.central
            .lock()
            .await
            .export_secret_key(&conversation_id, key_length as usize)
            .await
    }
}

// End-to-end identity methods
#[allow(dead_code, unused_variables)]
#[uniffi::export]
impl CoreCrypto {
    /// See [core_crypto::mls::MlsCentral::e2ei_new_enrollment]
    pub async fn e2ei_new_enrollment(
        &self,
        client_id: String,
        display_name: String,
        handle: String,
        expiry_days: u32,
        ciphersuite: Ciphersuite,
    ) -> CryptoResult<std::sync::Arc<WireE2eIdentity>> {
        self.central
            .lock()
            .await
            .e2ei_new_enrollment(
                client_id.into_bytes().into(),
                display_name,
                handle,
                expiry_days,
                ciphersuite.into(),
            )
            .map(async_lock::Mutex::new)
            .map(std::sync::Arc::new)
            .map(WireE2eIdentity)
            .map(std::sync::Arc::new)
            .map_err(|_| CryptoError::ImplementationError)
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_new_activation_enrollment]
    pub async fn e2ei_new_activation_enrollment(
        &self,
        client_id: String,
        display_name: String,
        handle: String,
        expiry_days: u32,
        ciphersuite: Ciphersuite,
    ) -> CryptoResult<std::sync::Arc<WireE2eIdentity>> {
        self.central
            .lock()
            .await
            .e2ei_new_activation_enrollment(
                client_id.into_bytes().into(),
                display_name,
                handle,
                expiry_days,
                ciphersuite.into(),
            )
            .map(async_lock::Mutex::new)
            .map(std::sync::Arc::new)
            .map(WireE2eIdentity)
            .map(std::sync::Arc::new)
            .map_err(|_| CryptoError::ImplementationError)
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_new_rotate_enrollment]
    pub async fn e2ei_new_rotate_enrollment(
        &self,
        client_id: String,
        display_name: Option<String>,
        handle: Option<String>,
        expiry_days: u32,
        ciphersuite: Ciphersuite,
    ) -> CryptoResult<std::sync::Arc<WireE2eIdentity>> {
        self.central
            .lock()
            .await
            .e2ei_new_rotate_enrollment(
                client_id.into_bytes().into(),
                display_name,
                handle,
                expiry_days,
                ciphersuite.into(),
            )
            .map(async_lock::Mutex::new)
            .map(std::sync::Arc::new)
            .map(WireE2eIdentity)
            .map(std::sync::Arc::new)
            .map_err(|_| CryptoError::ImplementationError)
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_mls_init_only]
    pub async fn e2ei_mls_init_only(
        &self,
        enrollment: std::sync::Arc<WireE2eIdentity>,
        certificate_chain: String,
    ) -> CryptoResult<()> {
        if std::sync::Arc::strong_count(&enrollment) > 1 {
            unsafe {
                // it is required because in order to pass the enrollment to Rust, uniffi lowers it by cloning the Arc
                // hence here the Arc has a strong_count of 2. We decrement it manually then drop it with `try_unwrap`.
                // We have to do this since this instance contains private keys that have to be zeroed once dropped.
                std::sync::Arc::decrement_strong_count(std::sync::Arc::as_ptr(&enrollment));
            }
        }
        let e2ei = std::sync::Arc::into_inner(enrollment).ok_or_else(|| CryptoError::LockPoisonError)?;
        let e2ei = std::sync::Arc::into_inner(e2ei.0)
            .ok_or_else(|| CryptoError::LockPoisonError)?
            .into_inner();

        self.central
            .lock()
            .await
            .e2ei_mls_init_only(e2ei, certificate_chain)
            .await
            .map_err(|_| CryptoError::ImplementationError)
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_rotate_all]
    pub async fn e2ei_rotate_all(
        &self,
        enrollment: std::sync::Arc<WireE2eIdentity>,
        certificate_chain: String,
        new_key_packages_count: u32,
    ) -> CryptoResult<RotateBundle> {
        if std::sync::Arc::strong_count(&enrollment) > 1 {
            unsafe {
                // it is required because in order to pass the enrollment to Rust, uniffi lowers it by cloning the Arc
                // hence here the Arc has a strong_count of 2. We decrement it manually then drop it with `try_unwrap`.
                // We have to do this since this instance contains private keys that have to be zeroed once dropped.
                std::sync::Arc::decrement_strong_count(std::sync::Arc::as_ptr(&enrollment));
            }
        }
        let e2ei = std::sync::Arc::into_inner(enrollment).ok_or_else(|| CryptoError::LockPoisonError)?;
        let e2ei = std::sync::Arc::into_inner(e2ei.0)
            .ok_or_else(|| CryptoError::LockPoisonError)?
            .into_inner();

        self.central
            .lock()
            .await
            .e2ei_rotate_all(e2ei, certificate_chain, new_key_packages_count as usize)
            .await
            .map_err(|_| CryptoError::ImplementationError)?
            .try_into()
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_enrollment_stash]
    pub async fn e2ei_enrollment_stash(&self, enrollment: std::sync::Arc<WireE2eIdentity>) -> CryptoResult<Vec<u8>> {
        let enrollment = std::sync::Arc::into_inner(enrollment).ok_or_else(|| CryptoError::LockPoisonError)?;
        let enrollment = std::sync::Arc::into_inner(enrollment.0)
            .ok_or_else(|| CryptoError::LockPoisonError)?
            .into_inner();

        self.central
            .lock()
            .await
            .e2ei_enrollment_stash(enrollment)
            .await
            .map_err(|_| CryptoError::ImplementationError)
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_enrollment_stash_pop]
    pub async fn e2ei_enrollment_stash_pop(&self, handle: Vec<u8>) -> CryptoResult<std::sync::Arc<WireE2eIdentity>> {
        self.central
            .lock()
            .await
            .e2ei_enrollment_stash_pop(handle)
            .await
            .map(async_lock::Mutex::new)
            .map(std::sync::Arc::new)
            .map(WireE2eIdentity)
            .map(std::sync::Arc::new)
            .map_err(|_| CryptoError::ImplementationError)
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_conversation_state]
    pub async fn e2ei_conversation_state(&self, conversation_id: Vec<u8>) -> CryptoResult<E2eiConversationState> {
        self.central
            .lock()
            .await
            .e2ei_conversation_state(&conversation_id)
            .await
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> CryptoResult<bool> {
        let sc = MlsCiphersuite::from(ciphersuite).signature_algorithm();
        self.central.lock().await.e2ei_is_enabled(sc)
    }
}

#[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
#[uniffi::export]
impl CoreCrypto {
    /// See [core_crypto::proteus::ProteusCentral::try_new]
    pub async fn proteus_init(&self) -> CryptoResult<()> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .await
                .proteus_init()
                .await
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::session_from_prekey]
    pub async fn proteus_session_from_prekey(&self, session_id: String, prekey: Vec<u8>) -> CryptoResult<()> {
        proteus_impl! { self.proteus_last_error_code => {
            let _ = self.central
                .lock()
                .await
                .proteus_session_from_prekey(&session_id, &prekey)
                .await?;

            CryptoResult::Ok(())
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::session_from_message]
    pub async fn proteus_session_from_message(&self, session_id: String, envelope: Vec<u8>) -> CryptoResult<Vec<u8>> {
        proteus_impl! { self.proteus_last_error_code => {
            let (_, payload) = self.central
                .lock()
                .await
                .proteus_session_from_message(&session_id, &envelope)
                .await?;

            CryptoResult::Ok(payload)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::session_save]
    /// **Note**: This isn't usually needed as persisting sessions happens automatically when decrypting/encrypting messages and initializing Sessions
    pub async fn proteus_session_save(&self, session_id: String) -> CryptoResult<()> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .await
                .proteus_session_save(&session_id)
                .await
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::session_delete]
    pub async fn proteus_session_delete(&self, session_id: String) -> CryptoResult<()> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .await
                .proteus_session_delete(&session_id)
                .await
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::session_exists]
    pub async fn proteus_session_exists(&self, session_id: String) -> CryptoResult<bool> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .await
                .proteus_session_exists(&session_id)
                .await
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::decrypt]
    pub async fn proteus_decrypt(&self, session_id: String, ciphertext: Vec<u8>) -> CryptoResult<Vec<u8>> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .await
                .proteus_decrypt(&session_id, &ciphertext)
                .await
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::encrypt]
    pub async fn proteus_encrypt(&self, session_id: String, plaintext: Vec<u8>) -> CryptoResult<Vec<u8>> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .await
                .proteus_encrypt(&session_id, &plaintext)
                .await
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::encrypt_batched]
    pub async fn proteus_encrypt_batched(
        &self,
        sessions: Vec<String>,
        plaintext: Vec<u8>,
    ) -> CryptoResult<std::collections::HashMap<String, Vec<u8>>> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .await
                .proteus_encrypt_batched(sessions.as_slice(), &plaintext)
                .await
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::new_prekey]
    pub async fn proteus_new_prekey(&self, prekey_id: u16) -> CryptoResult<Vec<u8>> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .await
                .proteus_new_prekey(prekey_id)
                .await
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::new_prekey_auto]
    pub async fn proteus_new_prekey_auto(&self) -> CryptoResult<ProteusAutoPrekeyBundle> {
        proteus_impl! { self.proteus_last_error_code => {
            let (id, pkb) = self.central
                .lock()
                .await
                .proteus_new_prekey_auto()
                .await?;

            CryptoResult::Ok(ProteusAutoPrekeyBundle { id, pkb })
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::last_resort_prekey]
    pub async fn proteus_last_resort_prekey(&self) -> CryptoResult<Vec<u8>> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .await
                .proteus_last_resort_prekey()
                .await
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::last_resort_prekey_id]
    pub fn proteus_last_resort_prekey_id(&self) -> CryptoResult<u16> {
        proteus_impl!({ Ok(core_crypto::CoreCrypto::proteus_last_resort_prekey_id()) })
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint]
    pub async fn proteus_fingerprint(&self) -> CryptoResult<String> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .await
                .proteus_fingerprint()
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_local]
    pub async fn proteus_fingerprint_local(&self, session_id: String) -> CryptoResult<String> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .await
                .proteus_fingerprint_local(&session_id)
                .await
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_remote]
    pub async fn proteus_fingerprint_remote(&self, session_id: String) -> CryptoResult<String> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .await
                .proteus_fingerprint_remote(&session_id)
                .await
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle]
    /// NOTE: uniffi doesn't support associated functions, so we have to have the self here
    pub fn proteus_fingerprint_prekeybundle(&self, prekey: Vec<u8>) -> CryptoResult<String> {
        proteus_impl!({ core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle(&prekey) })
    }

    /// See [core_crypto::proteus::ProteusCentral::cryptobox_migrate]
    pub async fn proteus_cryptobox_migrate(&self, path: String) -> CryptoResult<()> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .await
                .proteus_cryptobox_migrate(&path)
                .await
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

#[derive(Debug, uniffi::Object)]
/// See [core_crypto::e2e_identity::WireE2eIdentity]
pub struct WireE2eIdentity(std::sync::Arc<async_lock::Mutex<core_crypto::prelude::E2eiEnrollment>>);

#[uniffi::export]
impl WireE2eIdentity {
    /// See [core_crypto::e2e_identity::E2eiEnrollment::directory_response]
    pub async fn directory_response(&self, directory: Vec<u8>) -> E2eIdentityResult<AcmeDirectory> {
        self.0
            .lock()
            .await
            .directory_response(directory)
            .map(AcmeDirectory::from)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_account_request]
    pub async fn new_account_request(&self, previous_nonce: String) -> E2eIdentityResult<Vec<u8>> {
        self.0.lock().await.new_account_request(previous_nonce)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_account_response]
    pub async fn new_account_response(&self, account: Vec<u8>) -> E2eIdentityResult<()> {
        self.0.lock().await.new_account_response(account)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_order_request]
    #[allow(clippy::too_many_arguments)]
    pub async fn new_order_request(&self, previous_nonce: String) -> E2eIdentityResult<Vec<u8>> {
        self.0.lock().await.new_order_request(previous_nonce)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_order_response]
    pub async fn new_order_response(&self, order: Vec<u8>) -> E2eIdentityResult<NewAcmeOrder> {
        Ok(self.0.lock().await.new_order_response(order)?.into())
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_authz_request]
    pub async fn new_authz_request(&self, url: String, previous_nonce: String) -> E2eIdentityResult<Vec<u8>> {
        self.0.lock().await.new_authz_request(url, previous_nonce)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_authz_response]
    pub async fn new_authz_response(&self, authz: Vec<u8>) -> E2eIdentityResult<NewAcmeAuthz> {
        Ok(self.0.lock().await.new_authz_response(authz)?.into())
    }

    #[allow(clippy::too_many_arguments)]
    /// See [core_crypto::e2e_identity::E2eiEnrollment::create_dpop_token]
    pub async fn create_dpop_token(&self, expiry_secs: u32, backend_nonce: String) -> E2eIdentityResult<String> {
        self.0.lock().await.create_dpop_token(expiry_secs, backend_nonce)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_dpop_challenge_request]
    pub async fn new_dpop_challenge_request(
        &self,
        access_token: String,
        previous_nonce: String,
    ) -> E2eIdentityResult<Vec<u8>> {
        self.0
            .lock()
            .await
            .new_dpop_challenge_request(access_token, previous_nonce)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_oidc_challenge_request]
    pub async fn new_oidc_challenge_request(
        &self,
        id_token: String,
        previous_nonce: String,
    ) -> E2eIdentityResult<Vec<u8>> {
        self.0.lock().await.new_oidc_challenge_request(id_token, previous_nonce)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_challenge_response]
    pub async fn new_challenge_response(&self, challenge: Vec<u8>) -> E2eIdentityResult<()> {
        self.0.lock().await.new_challenge_response(challenge)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::check_order_request]
    pub async fn check_order_request(&self, order_url: String, previous_nonce: String) -> E2eIdentityResult<Vec<u8>> {
        self.0.lock().await.check_order_request(order_url, previous_nonce)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::check_order_response]
    pub async fn check_order_response(&self, order: Vec<u8>) -> E2eIdentityResult<String> {
        self.0.lock().await.check_order_response(order)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::finalize_request]
    pub async fn finalize_request(&self, previous_nonce: String) -> E2eIdentityResult<Vec<u8>> {
        self.0.lock().await.finalize_request(previous_nonce)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::finalize_response]
    pub async fn finalize_response(&self, finalize: Vec<u8>) -> E2eIdentityResult<String> {
        self.0.lock().await.finalize_response(finalize)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::certificate_request]
    pub async fn certificate_request(&self, previous_nonce: String) -> E2eIdentityResult<Vec<u8>> {
        self.0.lock().await.certificate_request(previous_nonce)
    }
}

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
    pub delegate: Vec<u8>,
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
    pub wire_dpop_challenge: Option<AcmeChallenge>,
    pub wire_oidc_challenge: Option<AcmeChallenge>,
}

impl From<core_crypto::prelude::E2eiNewAcmeAuthz> for NewAcmeAuthz {
    fn from(new_authz: core_crypto::prelude::E2eiNewAcmeAuthz) -> Self {
        Self {
            identifier: new_authz.identifier,
            wire_dpop_challenge: new_authz.wire_dpop_challenge.map(Into::into),
            wire_oidc_challenge: new_authz.wire_oidc_challenge.map(Into::into),
        }
    }
}

impl From<NewAcmeAuthz> for core_crypto::prelude::E2eiNewAcmeAuthz {
    fn from(new_authz: NewAcmeAuthz) -> Self {
        Self {
            identifier: new_authz.identifier,
            wire_dpop_challenge: new_authz.wire_dpop_challenge.map(Into::into),
            wire_oidc_challenge: new_authz.wire_oidc_challenge.map(Into::into),
        }
    }
}

#[derive(Debug)]
/// See [core_crypto::e2e_identity::types::E2eiAcmeChallenge]
pub struct AcmeChallenge {
    pub delegate: Vec<u8>,
    pub url: String,
    pub target: String,
}

impl From<core_crypto::prelude::E2eiAcmeChallenge> for AcmeChallenge {
    fn from(chall: core_crypto::prelude::E2eiAcmeChallenge) -> Self {
        Self {
            delegate: chall.delegate,
            url: chall.url,
            target: chall.target,
        }
    }
}

impl From<AcmeChallenge> for core_crypto::prelude::E2eiAcmeChallenge {
    fn from(chall: AcmeChallenge) -> Self {
        Self {
            delegate: chall.delegate,
            url: chall.url,
            target: chall.target,
        }
    }
}
