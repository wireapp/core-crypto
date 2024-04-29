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
use std::ops::DerefMut;

use tls_codec::{Deserialize, Serialize};

pub use core_crypto::prelude::ConversationId;
use core_crypto::{
    prelude::{
        ClientIdentifier, CryptoError, E2eIdentityError, EntropySeed, KeyPackageIn, KeyPackageRef,
        MlsBufferedConversationDecryptMessage, MlsCentral, MlsCentralConfiguration, MlsCiphersuite, MlsCommitBundle,
        MlsConversationConfiguration, MlsConversationCreationMessage, MlsConversationDecryptMessage,
        MlsConversationInitBundle, MlsCustomConfiguration, MlsGroupInfoBundle, MlsProposalBundle, MlsRotateBundle,
        VerifiableGroupInfo,
    },
    MlsError,
};

use crate::UniffiCustomTypeConverter;

#[allow(dead_code)]
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

#[uniffi::export]
pub fn version() -> String {
    VERSION.to_string()
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreCryptoError {
    #[error(transparent)]
    CryptoError {
        #[from]
        error: CryptoError,
    },
    #[error(transparent)]
    E2eIdentityError {
        #[from]
        error: E2eIdentityError,
    },
}

type CoreCryptoResult<T> = Result<T, CoreCryptoError>;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct ClientId(core_crypto::prelude::ClientId);

uniffi::custom_type!(ClientId, Vec<u8>);

impl UniffiCustomTypeConverter for ClientId {
    type Builtin = Vec<u8>;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Ok(Self(core_crypto::prelude::ClientId::from(val)))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0.to_vec()
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
#[repr(u16)]
pub enum CiphersuiteName {
    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    /// DH KEM P256 | AES-GCM 128 | SHA2-256 | EcDSA P256
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    /// DH KEM x25519 | Chacha20Poly1305 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    /// DH KEM x448 | AES-GCM 256 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,
    /// DH KEM P521 | AES-GCM 256 | SHA2-512 | EcDSA P521
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
    /// DH KEM x448 | Chacha20Poly1305 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
    /// DH KEM P384 | AES-GCM 256 | SHA2-384 | EcDSA P384
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007,
    /// x25519Kyber768Draft00 Hybrid KEM | AES-GCM 128 | SHA2-256 | Ed25519
    MLS_128_X25519KYBER768DRAFT00_AES128GCM_SHA256_Ed25519 = 0xf031,
}

#[derive(Debug, Clone)]
pub struct Ciphersuite(core_crypto::prelude::CiphersuiteName);

uniffi::custom_type!(Ciphersuite, u16);

impl From<core_crypto::prelude::CiphersuiteName> for Ciphersuite {
    fn from(cs: core_crypto::prelude::CiphersuiteName) -> Self {
        Self(cs)
    }
}

impl From<Ciphersuite> for core_crypto::prelude::CiphersuiteName {
    fn from(cs: Ciphersuite) -> Self {
        cs.0
    }
}

impl From<Ciphersuite> for MlsCiphersuite {
    fn from(cs: Ciphersuite) -> Self {
        cs.0.into()
    }
}

impl UniffiCustomTypeConverter for Ciphersuite {
    type Builtin = u16;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        core_crypto::prelude::CiphersuiteName::try_from(val)
            .map(Into::into)
            .map_err(|_| CryptoError::ImplementationError.into())
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        (&obj.0).into()
    }
}

#[derive(Debug, Default, Clone)]
pub struct Ciphersuites(Vec<core_crypto::prelude::CiphersuiteName>);

impl From<Vec<core_crypto::prelude::CiphersuiteName>> for Ciphersuites {
    fn from(cs: Vec<core_crypto::prelude::CiphersuiteName>) -> Self {
        Self(cs)
    }
}

impl From<Ciphersuites> for Vec<core_crypto::prelude::CiphersuiteName> {
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

uniffi::custom_type!(Ciphersuites, Vec<u16>);

impl UniffiCustomTypeConverter for Ciphersuites {
    type Builtin = Vec<u16>;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        val.iter().try_fold(Self(vec![]), |mut acc, c| -> uniffi::Result<Self> {
            let cs = core_crypto::prelude::CiphersuiteName::try_from(*c)
                .map(Into::into)
                .map_err(|_| CryptoError::ImplementationError)?;
            acc.0.push(cs);
            Ok(acc)
        })
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0.into_iter().map(|c| (&c).into()).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
/// Supporting struct for CRL registration result
pub struct CrlRegistration {
    /// Whether this CRL modifies the old CRL (i.e. has a different revocated cert list)
    pub dirty: bool,
    /// Optional expiration timestamp
    pub expiration: Option<u64>,
}

impl From<core_crypto::e2e_identity::CrlRegistration> for CrlRegistration {
    fn from(value: core_crypto::e2e_identity::CrlRegistration) -> Self {
        Self {
            dirty: value.dirty,
            expiration: value.expiration,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ProteusAutoPrekeyBundle {
    pub id: u16,
    pub pkb: Vec<u8>,
}

#[derive(Debug, uniffi::Record)]
/// see [core_crypto::prelude::MlsConversationCreationMessage]
pub struct MemberAddedMessages {
    pub welcome: Vec<u8>,
    pub commit: Vec<u8>,
    pub group_info: GroupInfoBundle,
    pub crl_new_distribution_points: Option<Vec<String>>,
}

impl TryFrom<MlsConversationCreationMessage> for MemberAddedMessages {
    type Error = CoreCryptoError;

    fn try_from(msg: MlsConversationCreationMessage) -> Result<Self, Self::Error> {
        let (welcome, commit, group_info, crl_new_distribution_points) = msg.to_bytes()?;
        Ok(Self {
            welcome,
            commit,
            group_info: group_info.into(),
            crl_new_distribution_points: crl_new_distribution_points.into(),
        })
    }
}

#[derive(Debug, uniffi::Record)]
/// see [core_crypto::prelude::MlsConversationCreationMessage]
pub struct WelcomeBundle {
    pub id: ConversationId,
    pub crl_new_distribution_points: Option<Vec<String>>,
}

impl From<core_crypto::prelude::WelcomeBundle> for WelcomeBundle {
    fn from(w: core_crypto::prelude::WelcomeBundle) -> Self {
        Self {
            id: w.id,
            crl_new_distribution_points: w.crl_new_distribution_points.into(),
        }
    }
}

#[derive(Debug, uniffi::Record)]
pub struct CommitBundle {
    pub welcome: Option<Vec<u8>>,
    pub commit: Vec<u8>,
    pub group_info: GroupInfoBundle,
}

impl TryFrom<MlsCommitBundle> for CommitBundle {
    type Error = CoreCryptoError;

    fn try_from(msg: MlsCommitBundle) -> Result<Self, Self::Error> {
        let (welcome, commit, group_info) = msg.to_bytes_triple()?;
        Ok(Self {
            welcome,
            commit,
            group_info: group_info.into(),
        })
    }
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
#[repr(u8)]
pub enum MlsGroupInfoEncryptionType {
    /// Unencrypted `GroupInfo`
    Plaintext = 1,
    /// `GroupInfo` encrypted in a JWE
    JweEncrypted = 2,
}

impl From<core_crypto::prelude::MlsGroupInfoEncryptionType> for MlsGroupInfoEncryptionType {
    fn from(value: core_crypto::prelude::MlsGroupInfoEncryptionType) -> Self {
        match value {
            core_crypto::prelude::MlsGroupInfoEncryptionType::Plaintext => Self::Plaintext,
            core_crypto::prelude::MlsGroupInfoEncryptionType::JweEncrypted => Self::JweEncrypted,
        }
    }
}

impl From<MlsGroupInfoEncryptionType> for core_crypto::prelude::MlsGroupInfoEncryptionType {
    fn from(value: MlsGroupInfoEncryptionType) -> Self {
        match value {
            MlsGroupInfoEncryptionType::Plaintext => Self::Plaintext,
            MlsGroupInfoEncryptionType::JweEncrypted => Self::JweEncrypted,
        }
    }
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
#[repr(u8)]
pub enum MlsRatchetTreeType {
    /// Plain old and complete `GroupInfo`
    Full = 1,
    /// Contains `GroupInfo` changes since previous epoch (not yet implemented)
    /// (see [draft](https://github.com/rohan-wire/ietf-drafts/blob/main/mahy-mls-ratchet-tree-delta/draft-mahy-mls-ratchet-tree-delta.md))
    Delta = 2,
    /// TODO: to define
    ByRef = 3,
}

impl From<core_crypto::prelude::MlsRatchetTreeType> for MlsRatchetTreeType {
    fn from(value: core_crypto::prelude::MlsRatchetTreeType) -> Self {
        match value {
            core_crypto::prelude::MlsRatchetTreeType::Full => Self::Full,
            core_crypto::prelude::MlsRatchetTreeType::Delta => Self::Delta,
            core_crypto::prelude::MlsRatchetTreeType::ByRef => Self::ByRef,
        }
    }
}

impl From<MlsRatchetTreeType> for core_crypto::prelude::MlsRatchetTreeType {
    fn from(value: MlsRatchetTreeType) -> Self {
        match value {
            MlsRatchetTreeType::Full => Self::Full,
            MlsRatchetTreeType::Delta => Self::Delta,
            MlsRatchetTreeType::ByRef => Self::ByRef,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct GroupInfoBundle {
    pub encryption_type: MlsGroupInfoEncryptionType,
    pub ratchet_tree_type: MlsRatchetTreeType,
    pub payload: Vec<u8>,
}

impl From<MlsGroupInfoBundle> for GroupInfoBundle {
    fn from(gi: MlsGroupInfoBundle) -> Self {
        Self {
            encryption_type: gi.encryption_type.into(),
            ratchet_tree_type: gi.ratchet_tree_type.into(),
            payload: gi.payload.bytes(),
        }
    }
}

#[derive(Debug, uniffi::Record)]
pub struct RotateBundle {
    pub commits: HashMap<String, CommitBundle>,
    pub new_key_packages: Vec<Vec<u8>>,
    pub key_package_refs_to_remove: Vec<Vec<u8>>,
    pub crl_new_distribution_points: Option<Vec<String>>,
}

impl TryFrom<MlsRotateBundle> for RotateBundle {
    type Error = CoreCryptoError;

    fn try_from(bundle: MlsRotateBundle) -> Result<Self, Self::Error> {
        let (commits, new_key_packages, key_package_refs_to_remove, crl_new_distribution_points) = bundle.to_bytes()?;
        let commits_size = commits.len();
        let commits = commits
            .into_iter()
            .try_fold(HashMap::with_capacity(commits_size), |mut acc, (id, c)| {
                let _ = acc.insert(id, c.try_into()?);
                CoreCryptoResult::Ok(acc)
            })?;
        Ok(Self {
            commits,
            new_key_packages,
            key_package_refs_to_remove,
            crl_new_distribution_points: crl_new_distribution_points.into(),
        })
    }
}

#[derive(Debug, uniffi::Record)]
pub struct ProposalBundle {
    pub proposal: Vec<u8>,
    pub proposal_ref: Vec<u8>,
    pub crl_new_distribution_points: Option<Vec<String>>,
}

impl TryFrom<MlsProposalBundle> for ProposalBundle {
    type Error = CoreCryptoError;

    fn try_from(msg: MlsProposalBundle) -> Result<Self, Self::Error> {
        let (proposal, proposal_ref, crl_new_distribution_points) = msg.to_bytes()?;
        Ok(Self {
            proposal,
            proposal_ref,
            crl_new_distribution_points: crl_new_distribution_points.into(),
        })
    }
}

#[derive(Debug, uniffi::Record)]
pub struct ConversationInitBundle {
    pub conversation_id: Vec<u8>,
    pub commit: Vec<u8>,
    pub group_info: GroupInfoBundle,
    pub crl_new_distribution_points: Option<Vec<String>>,
}

impl TryFrom<MlsConversationInitBundle> for ConversationInitBundle {
    type Error = CoreCryptoError;

    fn try_from(mut from: MlsConversationInitBundle) -> Result<Self, Self::Error> {
        let conversation_id = std::mem::take(&mut from.conversation_id);
        let (commit, gi, crl_new_distribution_points) = from.to_bytes()?;
        Ok(Self {
            conversation_id,
            commit,
            group_info: gi.into(),
            crl_new_distribution_points: crl_new_distribution_points.into(),
        })
    }
}

#[derive(Debug, uniffi::Record)]
/// See [core_crypto::prelude::decrypt::MlsConversationDecryptMessage]
pub struct DecryptedMessage {
    pub message: Option<Vec<u8>>,
    pub proposals: Vec<ProposalBundle>,
    pub is_active: bool,
    pub commit_delay: Option<u64>,
    pub sender_client_id: Option<ClientId>,
    pub has_epoch_changed: bool,
    pub identity: WireIdentity,
    pub buffered_messages: Option<Vec<BufferedDecryptedMessage>>,
    pub crl_new_distribution_points: Option<Vec<String>>,
}

#[derive(Debug, uniffi::Record)]
/// because Uniffi does not support recursive structs
pub struct BufferedDecryptedMessage {
    pub message: Option<Vec<u8>>,
    pub proposals: Vec<ProposalBundle>,
    pub is_active: bool,
    pub commit_delay: Option<u64>,
    pub sender_client_id: Option<ClientId>,
    pub has_epoch_changed: bool,
    pub identity: WireIdentity,
    pub crl_new_distribution_points: Option<Vec<String>>,
}

impl TryFrom<MlsConversationDecryptMessage> for DecryptedMessage {
    type Error = CoreCryptoError;

    fn try_from(from: MlsConversationDecryptMessage) -> Result<Self, Self::Error> {
        let proposals = from
            .proposals
            .into_iter()
            .map(ProposalBundle::try_from)
            .collect::<CoreCryptoResult<Vec<_>>>()?;

        let buffered_messages = if let Some(bm) = from.buffered_messages {
            let bm = bm
                .into_iter()
                .map(TryInto::try_into)
                .collect::<CoreCryptoResult<Vec<_>>>()?;
            Some(bm)
        } else {
            None
        };

        Ok(Self {
            message: from.app_msg,
            proposals,
            is_active: from.is_active,
            commit_delay: from.delay,
            sender_client_id: from.sender_client_id.map(ClientId),
            has_epoch_changed: from.has_epoch_changed,
            identity: from.identity.into(),
            buffered_messages,
            crl_new_distribution_points: from.crl_new_distribution_points.into(),
        })
    }
}

impl TryFrom<MlsBufferedConversationDecryptMessage> for BufferedDecryptedMessage {
    type Error = CoreCryptoError;

    fn try_from(from: MlsBufferedConversationDecryptMessage) -> Result<Self, Self::Error> {
        let proposals = from
            .proposals
            .into_iter()
            .map(ProposalBundle::try_from)
            .collect::<CoreCryptoResult<Vec<_>>>()?;

        Ok(Self {
            message: from.app_msg,
            proposals,
            is_active: from.is_active,
            commit_delay: from.delay,
            sender_client_id: from.sender_client_id.map(ClientId),
            has_epoch_changed: from.has_epoch_changed,
            identity: from.identity.into(),
            crl_new_distribution_points: from.crl_new_distribution_points.into(),
        })
    }
}

#[derive(Debug, uniffi::Record)]
/// See [core_crypto::prelude::WireIdentity]
pub struct WireIdentity {
    pub client_id: String,
    pub status: DeviceStatus,
    pub thumbprint: String,
    pub credential_type: MlsCredentialType,
    pub x509_identity: Option<X509Identity>,
}

impl From<core_crypto::prelude::WireIdentity> for WireIdentity {
    fn from(i: core_crypto::prelude::WireIdentity) -> Self {
        Self {
            client_id: i.client_id,
            status: i.status.into(),
            thumbprint: i.thumbprint,
            credential_type: i.credential_type.into(),
            x509_identity: i.x509_identity.map(Into::into),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, uniffi::Enum)]
#[repr(u8)]
pub enum DeviceStatus {
    /// All is fine
    Valid = 1,
    /// The Credential's certificate is expired
    Expired = 2,
    /// The Credential's certificate is revoked (not implemented yet)
    Revoked = 3,
}

impl From<core_crypto::prelude::DeviceStatus> for DeviceStatus {
    fn from(value: core_crypto::prelude::DeviceStatus) -> Self {
        match value {
            core_crypto::prelude::DeviceStatus::Valid => Self::Valid,
            core_crypto::prelude::DeviceStatus::Expired => Self::Expired,
            core_crypto::prelude::DeviceStatus::Revoked => Self::Revoked,
        }
    }
}

#[derive(Debug, uniffi::Record)]
/// See [core_crypto::prelude::X509Identity]
pub struct X509Identity {
    pub handle: String,
    pub display_name: String,
    pub domain: String,
    pub certificate: String,
    pub serial_number: String,
    pub not_before: u64,
    pub not_after: u64,
}

impl From<core_crypto::prelude::X509Identity> for X509Identity {
    fn from(i: core_crypto::prelude::X509Identity) -> Self {
        Self {
            handle: i.handle,
            display_name: i.display_name,
            domain: i.domain,
            certificate: i.certificate,
            serial_number: i.serial_number,
            not_before: i.not_before,
            not_after: i.not_after,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
/// See [core_crypto::prelude::MlsConversationConfiguration]
pub struct ConversationConfiguration {
    pub ciphersuite: Ciphersuite,
    pub external_senders: Vec<Vec<u8>>,
    pub custom: CustomConfiguration,
}

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, uniffi::Enum)]
#[repr(u8)]
pub enum MlsWirePolicy {
    /// Handshake messages are never encrypted
    #[default]
    Plaintext = 1,
    /// Handshake messages are always encrypted
    Ciphertext = 2,
}

impl From<core_crypto::prelude::MlsWirePolicy> for MlsWirePolicy {
    fn from(value: core_crypto::prelude::MlsWirePolicy) -> Self {
        match value {
            core_crypto::prelude::MlsWirePolicy::Plaintext => Self::Plaintext,
            core_crypto::prelude::MlsWirePolicy::Ciphertext => Self::Ciphertext,
        }
    }
}

impl From<MlsWirePolicy> for core_crypto::prelude::MlsWirePolicy {
    fn from(value: MlsWirePolicy) -> core_crypto::prelude::MlsWirePolicy {
        match value {
            MlsWirePolicy::Plaintext => core_crypto::prelude::MlsWirePolicy::Plaintext,
            MlsWirePolicy::Ciphertext => core_crypto::prelude::MlsWirePolicy::Ciphertext,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
/// See [core_crypto::prelude::MlsCustomConfiguration]
pub struct CustomConfiguration {
    pub key_rotation_span: Option<std::time::Duration>,
    pub wire_policy: Option<MlsWirePolicy>,
}

impl From<CustomConfiguration> for MlsCustomConfiguration {
    fn from(cfg: CustomConfiguration) -> Self {
        Self {
            key_rotation_span: cfg.key_rotation_span,
            wire_policy: cfg.wire_policy.unwrap_or_default().into(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
/// Dummy comment
pub struct E2eiDumpedPkiEnv {
    pub root_ca: String,
    pub intermediates: Vec<String>,
    pub crls: Vec<String>,
}

impl From<core_crypto::e2e_identity::E2eiDumpedPkiEnv> for E2eiDumpedPkiEnv {
    fn from(value: core_crypto::e2e_identity::E2eiDumpedPkiEnv) -> Self {
        Self {
            root_ca: value.root_ca,
            intermediates: value.intermediates,
            crls: value.crls,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, uniffi::Enum)]
#[repr(u8)]
pub enum MlsCredentialType {
    /// Basic credential i.e. a KeyPair
    #[default]
    Basic = 0x01,
    /// A x509 certificate generally obtained through e2e identity enrollment process
    X509 = 0x02,
}

impl From<core_crypto::prelude::MlsCredentialType> for MlsCredentialType {
    fn from(value: core_crypto::prelude::MlsCredentialType) -> Self {
        match value {
            core_crypto::prelude::MlsCredentialType::Basic => Self::Basic,
            core_crypto::prelude::MlsCredentialType::X509 => Self::X509,
        }
    }
}

impl From<MlsCredentialType> for core_crypto::prelude::MlsCredentialType {
    fn from(value: MlsCredentialType) -> core_crypto::prelude::MlsCredentialType {
        match value {
            MlsCredentialType::Basic => core_crypto::prelude::MlsCredentialType::Basic,
            MlsCredentialType::X509 => core_crypto::prelude::MlsCredentialType::X509,
        }
    }
}

#[derive(Debug)]
struct CoreCryptoCallbacksWrapper(std::sync::Arc<dyn CoreCryptoCallbacks>);

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl core_crypto::prelude::CoreCryptoCallbacks for CoreCryptoCallbacksWrapper {
    async fn authorize(&self, conversation_id: Vec<u8>, client_id: core_crypto::prelude::ClientId) -> bool {
        self.0.authorize(conversation_id, ClientId(client_id)).await
    }
    async fn user_authorize(
        &self,
        conversation_id: Vec<u8>,
        external_client_id: core_crypto::prelude::ClientId,
        existing_clients: Vec<core_crypto::prelude::ClientId>,
    ) -> bool {
        self.0
            .user_authorize(
                conversation_id,
                ClientId(external_client_id),
                existing_clients.into_iter().map(ClientId).collect(),
            )
            .await
    }
    async fn client_is_existing_group_user(
        &self,
        conversation_id: Vec<u8>,
        client_id: core_crypto::prelude::ClientId,
        existing_clients: Vec<core_crypto::prelude::ClientId>,
        parent_conversation_clients: Option<Vec<core_crypto::prelude::ClientId>>,
    ) -> bool {
        self.0
            .client_is_existing_group_user(
                conversation_id,
                ClientId(client_id),
                existing_clients.into_iter().map(ClientId).collect(),
                parent_conversation_clients.map(|pccs| pccs.into_iter().map(ClientId).collect()),
            )
            .await
    }
}

/// This only exists to create a sync interface to our internal async callback interface
// TODO: Remove this once UniFFI supports async callbacks
#[uniffi::export(with_foreign)]
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait CoreCryptoCallbacks: std::fmt::Debug + Send + Sync {
    async fn authorize(&self, conversation_id: Vec<u8>, client_id: ClientId) -> bool;
    async fn user_authorize(
        &self,
        conversation_id: Vec<u8>,
        external_client_id: ClientId,
        existing_clients: Vec<ClientId>,
    ) -> bool;
    async fn client_is_existing_group_user(
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
    nb_key_package: Option<u32>,
) -> CoreCryptoResult<CoreCrypto> {
    CoreCrypto::new(path, key, Some(client_id), Some(ciphersuites), nb_key_package).await
}

#[uniffi::export]
/// Similar to [core_crypto_new] but defers MLS initialization. It can be initialized later
/// with [CoreCrypto::mls_init].
pub async fn core_crypto_deferred_init(path: String, key: String) -> CoreCryptoResult<CoreCrypto> {
    CoreCrypto::new(path, key, None, None, None).await
}

#[allow(dead_code, unused_variables)]
#[uniffi::export]
impl CoreCrypto {
    #[uniffi::constructor]
    pub async fn new(
        path: String,
        key: String,
        client_id: Option<ClientId>,
        ciphersuites: Option<Ciphersuites>,
        nb_key_package: Option<u32>,
    ) -> CoreCryptoResult<Self> {
        #[cfg(feature = "debug-logging")]
        femme::with_level(femme::LevelFilter::Debug);

        let nb_key_package = nb_key_package
            .map(usize::try_from)
            .transpose()
            .map_err(CryptoError::from)?;
        let configuration = MlsCentralConfiguration::try_new(
            path,
            key,
            client_id.map(|cid| cid.0.clone()),
            (&ciphersuites.unwrap_or_default()).into(),
            None,
            nb_key_package,
        )?;

        let central = MlsCentral::try_new(configuration).await?;
        let central = core_crypto::CoreCrypto::from(central).into();

        Ok(CoreCrypto {
            central,
            proteus_last_error_code: std::sync::atomic::AtomicU32::new(0),
        })
    }

    /// See [core_crypto::mls::MlsCentral::mls_init]
    pub async fn mls_init(
        &self,
        client_id: ClientId,
        ciphersuites: Ciphersuites,
        nb_key_package: Option<u32>,
    ) -> CoreCryptoResult<()> {
        let nb_key_package = nb_key_package
            .map(usize::try_from)
            .transpose()
            .map_err(CryptoError::from)?;
        Ok(self
            .central
            .lock()
            .await
            .mls_init(
                ClientIdentifier::Basic(client_id.0),
                (&ciphersuites).into(),
                nb_key_package,
            )
            .await?)
    }

    /// See [core_crypto::mls::MlsCentral::mls_generate_keypairs]
    pub async fn mls_generate_keypairs(&self, ciphersuites: Ciphersuites) -> CoreCryptoResult<Vec<ClientId>> {
        Ok(self
            .central
            .lock()
            .await
            .mls_generate_keypairs((&ciphersuites).into())
            .await
            .map(|cids| cids.into_iter().map(ClientId).collect())?)
    }

    /// See [core_crypto::mls::MlsCentral::mls_init_with_client_id]
    pub async fn mls_init_with_client_id(
        &self,
        client_id: ClientId,
        tmp_client_ids: Vec<ClientId>,
        ciphersuites: Ciphersuites,
    ) -> CoreCryptoResult<()> {
        Ok(self
            .central
            .lock()
            .await
            .mls_init_with_client_id(
                client_id.0,
                tmp_client_ids.into_iter().map(|cid| cid.0).collect(),
                (&ciphersuites).into(),
            )
            .await?)
    }

    /// See [core_crypto::mls::MlsCentral::restore_from_disk]
    pub async fn restore_from_disk(&self) -> CoreCryptoResult<()> {
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
    pub async fn unload(self: std::sync::Arc<Self>) -> CoreCryptoResult<()> {
        if let Some(cc) = std::sync::Arc::into_inner(self) {
            let central = cc.central.into_inner();
            central.take().close().await?;
            Ok(())
        } else {
            Err(CryptoError::LockPoisonError.into())
        }
    }

    /// See [core_crypto::mls::MlsCentral::wipe]
    pub async fn wipe(self: std::sync::Arc<Self>) -> CoreCryptoResult<()> {
        if let Some(cc) = std::sync::Arc::into_inner(self) {
            let central = cc.central.into_inner();
            central.take().wipe().await?;
            Ok(())
        } else {
            Err(CryptoError::LockPoisonError.into())
        }
    }

    /// See [core_crypto::mls::MlsCentral::callbacks]
    pub async fn set_callbacks(&self, callbacks: std::sync::Arc<dyn CoreCryptoCallbacks>) -> CoreCryptoResult<()> {
        self.central
            .lock()
            .await
            .callbacks(std::sync::Arc::new(CoreCryptoCallbacksWrapper(callbacks)));
        Ok(())
    }

    /// See [core_crypto::mls::MlsCentral::client_public_key]
    pub async fn client_public_key(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: MlsCredentialType,
    ) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .central
            .lock()
            .await
            .client_public_key(ciphersuite.into(), credential_type.into())?)
    }

    /// See [core_crypto::mls::MlsCentral::get_or_create_client_keypackages]
    pub async fn client_keypackages(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: MlsCredentialType,
        amount_requested: u32,
    ) -> CoreCryptoResult<Vec<Vec<u8>>> {
        let kps = self
            .central
            .lock()
            .await
            .get_or_create_client_keypackages(ciphersuite.into(), credential_type.into(), amount_requested as usize)
            .await?;

        kps.into_iter()
            .map(|kp| {
                Ok(kp
                    .tls_serialize_detached()
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)?)
            })
            .collect::<CoreCryptoResult<Vec<Vec<u8>>>>()
    }

    /// See [core_crypto::mls::MlsCentral::client_valid_key_packages_count]
    pub async fn client_valid_keypackages_count(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: MlsCredentialType,
    ) -> CoreCryptoResult<u64> {
        let count = self
            .central
            .lock()
            .await
            .client_valid_key_packages_count(ciphersuite.into(), credential_type.into())
            .await?;

        Ok(count.try_into().unwrap_or(0))
    }

    /// See [core_crypto::mls::MlsCentral::delete_keypackages]
    pub async fn delete_keypackages(&self, refs: Vec<Vec<u8>>) -> CoreCryptoResult<()> {
        let refs = refs
            .into_iter()
            .map(|r| KeyPackageRef::from_slice(&r))
            .collect::<Vec<_>>();

        Ok(self.central.lock().await.delete_keypackages(&refs[..]).await?)
    }

    /// See [core_crypto::mls::MlsCentral::new_conversation]
    pub async fn create_conversation(
        &self,
        conversation_id: Vec<u8>,
        creator_credential_type: MlsCredentialType,
        config: ConversationConfiguration,
    ) -> CoreCryptoResult<()> {
        let mut central = self.central.lock().await;
        let mut lower_cfg = MlsConversationConfiguration {
            custom: config.custom.into(),
            ciphersuite: config.ciphersuite.into(),
            ..Default::default()
        };

        central.set_raw_external_senders(&mut lower_cfg, config.external_senders)?;

        Ok(central
            .new_conversation(&conversation_id, creator_credential_type.into(), lower_cfg)
            .await?)
    }

    /// See [core_crypto::mls::MlsCentral::conversation_epoch]
    pub async fn conversation_epoch(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<u64> {
        Ok(self.central.lock().await.conversation_epoch(&conversation_id).await?)
    }

    /// See [core_crypto::mls::MlsCentral::process_raw_welcome_message]
    pub async fn process_welcome_message(
        &self,
        welcome_message: Vec<u8>,
        custom_configuration: CustomConfiguration,
    ) -> CoreCryptoResult<WelcomeBundle> {
        Ok(self
            .central
            .lock()
            .await
            .process_raw_welcome_message(welcome_message, custom_configuration.into())
            .await?
            .into())
    }

    /// See [core_crypto::mls::MlsCentral::add_members_to_conversation]
    pub async fn add_clients_to_conversation(
        &self,
        conversation_id: Vec<u8>,
        key_packages: Vec<Vec<u8>>,
    ) -> CoreCryptoResult<MemberAddedMessages> {
        let key_packages = key_packages
            .into_iter()
            .map(|kp| {
                KeyPackageIn::tls_deserialize(&mut kp.as_slice()).map_err(|e| CoreCryptoError::CryptoError {
                    error: CryptoError::MlsError(e.into()),
                })
            })
            .collect::<CoreCryptoResult<Vec<_>>>()?;

        self.central
            .lock()
            .await
            .add_members_to_conversation(&conversation_id, key_packages)
            .await?
            .try_into()
    }

    /// See [core_crypto::mls::MlsCentral::remove_members_from_conversation]
    pub async fn remove_clients_from_conversation(
        &self,
        conversation_id: Vec<u8>,
        clients: Vec<ClientId>,
    ) -> CoreCryptoResult<CommitBundle> {
        let clients: Vec<core_crypto::prelude::ClientId> = clients.into_iter().map(|c| c.0).collect();
        self.central
            .lock()
            .await
            .remove_members_from_conversation(&conversation_id, &clients)
            .await?
            .try_into()
    }

    /// See [core_crypto::mls::MlsCentral::mark_conversation_as_child_of]
    pub async fn mark_conversation_as_child_of(&self, child_id: Vec<u8>, parent_id: Vec<u8>) -> CoreCryptoResult<()> {
        Ok(self
            .central
            .lock()
            .await
            .mark_conversation_as_child_of(&child_id, &parent_id)
            .await?)
    }

    /// See [core_crypto::mls::MlsCentral::update_keying_material]
    pub async fn update_keying_material(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<CommitBundle> {
        self.central
            .lock()
            .await
            .update_keying_material(&conversation_id)
            .await?
            .try_into()
    }

    /// See [core_crypto::mls::MlsCentral::commit_pending_proposals]
    pub async fn commit_pending_proposals(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<Option<CommitBundle>> {
        self.central
            .lock()
            .await
            .commit_pending_proposals(&conversation_id)
            .await
            .transpose()
            .map(|r| r?.try_into())
            .transpose()
    }

    /// see [core_crypto::mls::MlsCentral::wipe_conversation]
    pub async fn wipe_conversation(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<()> {
        Ok(self.central.lock().await.wipe_conversation(&conversation_id).await?)
    }

    /// See [core_crypto::mls::MlsCentral::decrypt_message]
    pub async fn decrypt_message(
        &self,
        conversation_id: Vec<u8>,
        payload: Vec<u8>,
    ) -> CoreCryptoResult<DecryptedMessage> {
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
    pub async fn encrypt_message(&self, conversation_id: Vec<u8>, message: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .central
            .lock()
            .await
            .encrypt_message(&conversation_id, message)
            .await?)
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
    ) -> CoreCryptoResult<ProposalBundle> {
        let kp = KeyPackageIn::tls_deserialize(&mut keypackage.as_slice())
            .map_err(MlsError::from)
            .map_err(CryptoError::from)?;
        self.central
            .lock()
            .await
            .new_add_proposal(&conversation_id, kp.into())
            .await?
            .try_into()
    }

    /// See [core_crypto::mls::MlsCentral::new_update_proposal]
    pub async fn new_update_proposal(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<ProposalBundle> {
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
    ) -> CoreCryptoResult<ProposalBundle> {
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
    ) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .central
            .lock()
            .await
            .new_external_add_proposal(
                conversation_id,
                epoch.into(),
                ciphersuite.into(),
                credential_type.into(),
            )
            .await?
            .to_bytes()
            .map_err(MlsError::from)
            .map_err(CryptoError::from)?)
    }

    /// See [core_crypto::mls::MlsCentral::join_by_external_commit]
    pub async fn join_by_external_commit(
        &self,
        group_info: Vec<u8>,
        custom_configuration: CustomConfiguration,
        credential_type: MlsCredentialType,
    ) -> CoreCryptoResult<ConversationInitBundle> {
        let group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info.as_slice())
            .map_err(MlsError::from)
            .map_err(CryptoError::from)?;
        self.central
            .lock()
            .await
            .join_by_external_commit(group_info, custom_configuration.into(), credential_type.into())
            .await?
            .try_into()
    }

    /// See [core_crypto::mls::MlsCentral::merge_pending_group_from_external_commit]
    pub async fn merge_pending_group_from_external_commit(
        &self,
        conversation_id: Vec<u8>,
    ) -> CoreCryptoResult<Option<Vec<BufferedDecryptedMessage>>> {
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
                    .map(TryInto::try_into)
                    .collect::<CoreCryptoResult<Vec<_>>>()?,
            ));
        }

        Ok(None)
    }

    /// See [core_crypto::mls::MlsCentral::clear_pending_group_from_external_commit]
    pub async fn clear_pending_group_from_external_commit(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<()> {
        self.central
            .lock()
            .await
            .clear_pending_group_from_external_commit(&conversation_id)
            .await?;

        Ok(())
    }

    /// See [core_crypto::mls::MlsCentral::random_bytes]
    pub async fn random_bytes(&self, len: u32) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .central
            .lock()
            .await
            .random_bytes(len.try_into().map_err(CryptoError::from)?)?)
    }

    /// see [core_crypto::prelude::MlsCryptoProvider::reseed]
    pub async fn reseed_rng(&self, seed: Vec<u8>) -> CoreCryptoResult<()> {
        let seed = EntropySeed::try_from_slice(&seed).map_err(CryptoError::from)?;
        self.central.lock().await.provider_mut().reseed(Some(seed));

        Ok(())
    }

    /// See [core_crypto::mls::MlsCentral::commit_accepted]
    pub async fn commit_accepted(
        &self,
        conversation_id: Vec<u8>,
    ) -> CoreCryptoResult<Option<Vec<BufferedDecryptedMessage>>> {
        if let Some(decrypted_messages) = self.central.lock().await.commit_accepted(&conversation_id).await? {
            return Ok(Some(
                decrypted_messages
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<CoreCryptoResult<Vec<_>>>()?,
            ));
        }

        Ok(None)
    }

    /// See [core_crypto::mls::MlsCentral::clear_pending_proposal]
    pub async fn clear_pending_proposal(
        &self,
        conversation_id: Vec<u8>,
        proposal_ref: Vec<u8>,
    ) -> CoreCryptoResult<()> {
        Ok(self
            .central
            .lock()
            .await
            .clear_pending_proposal(&conversation_id, proposal_ref.into())
            .await?)
    }

    /// See [core_crypto::mls::MlsCentral::clear_pending_commit]
    pub async fn clear_pending_commit(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<()> {
        Ok(self.central.lock().await.clear_pending_commit(&conversation_id).await?)
    }

    /// See [core_crypto::mls::MlsCentral::get_client_ids]
    pub async fn get_client_ids(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<Vec<ClientId>> {
        Ok(self
            .central
            .lock()
            .await
            .get_client_ids(&conversation_id)
            .await
            .map(|cids| cids.into_iter().map(ClientId).collect())?)
    }

    /// See [core_crypto::mls::MlsCentral::export_secret_key]
    pub async fn export_secret_key(&self, conversation_id: Vec<u8>, key_length: u32) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .central
            .lock()
            .await
            .export_secret_key(&conversation_id, key_length as usize)
            .await?)
    }

    /// See [core_crypto::mls::MlsCentral::get_external_sender]
    pub async fn get_external_sender(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.central.lock().await.get_external_sender(&conversation_id).await?)
    }
}

#[derive(Debug, Copy, Clone, uniffi::Enum)]
#[repr(u8)]
pub enum E2eiConversationState {
    /// All clients have a valid E2EI certificate
    Verified = 1,
    /// Some clients are either still Basic or their certificate is expired
    NotVerified,
    /// All clients are still Basic. If all client have expired certificates, [E2eiConversationState::NotVerified] is returned.
    NotEnabled,
}

impl From<core_crypto::prelude::E2eiConversationState> for E2eiConversationState {
    fn from(value: core_crypto::prelude::E2eiConversationState) -> Self {
        match value {
            core_crypto::prelude::E2eiConversationState::Verified => Self::Verified,
            core_crypto::prelude::E2eiConversationState::NotVerified => Self::NotVerified,
            core_crypto::prelude::E2eiConversationState::NotEnabled => Self::NotEnabled,
        }
    }
}

#[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
#[uniffi::export]
impl CoreCrypto {
    /// See [core_crypto::proteus::ProteusCentral::try_new]
    pub async fn proteus_init(&self) -> CoreCryptoResult<()> {
        proteus_impl! { self.proteus_last_error_code => {
            self.central
                .lock()
                .await
                .proteus_init()
                .await?;

            CoreCryptoResult::Ok(())
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::session_from_prekey]
    pub async fn proteus_session_from_prekey(&self, session_id: String, prekey: Vec<u8>) -> CoreCryptoResult<()> {
        proteus_impl! { self.proteus_last_error_code => {
            let _ = self.central
                .lock()
                .await
                .proteus_session_from_prekey(&session_id, &prekey)
                .await?;

            CoreCryptoResult::Ok(())
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::session_from_message]
    pub async fn proteus_session_from_message(
        &self,
        session_id: String,
        envelope: Vec<u8>,
    ) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl! { self.proteus_last_error_code => {
            let (_, payload) = self.central
                .lock()
                .await
                .proteus_session_from_message(&session_id, &envelope)
                .await?;

            CoreCryptoResult::Ok(payload)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::session_save]
    /// **Note**: This isn't usually needed as persisting sessions happens automatically when decrypting/encrypting messages and initializing Sessions
    pub async fn proteus_session_save(&self, session_id: String) -> CoreCryptoResult<()> {
        proteus_impl! { self.proteus_last_error_code => {
            Ok(self.central
                .lock()
                .await
                .proteus_session_save(&session_id)
                .await?)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::session_delete]
    pub async fn proteus_session_delete(&self, session_id: String) -> CoreCryptoResult<()> {
        proteus_impl! { self.proteus_last_error_code => {
            Ok(self.central
                .lock()
                .await
                .proteus_session_delete(&session_id)
                .await?)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::session_exists]
    pub async fn proteus_session_exists(&self, session_id: String) -> CoreCryptoResult<bool> {
        proteus_impl! { self.proteus_last_error_code => {
            Ok(self.central
                .lock()
                .await
                .proteus_session_exists(&session_id)
                .await?)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::decrypt]
    pub async fn proteus_decrypt(&self, session_id: String, ciphertext: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl! { self.proteus_last_error_code => {
            Ok(self.central
                .lock()
                .await
                .proteus_decrypt(&session_id, &ciphertext)
                .await?)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::encrypt]
    pub async fn proteus_encrypt(&self, session_id: String, plaintext: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl! { self.proteus_last_error_code => {
            Ok(self.central
                .lock()
                .await
                .proteus_encrypt(&session_id, &plaintext)
                .await?)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::encrypt_batched]
    pub async fn proteus_encrypt_batched(
        &self,
        sessions: Vec<String>,
        plaintext: Vec<u8>,
    ) -> CoreCryptoResult<std::collections::HashMap<String, Vec<u8>>> {
        proteus_impl! { self.proteus_last_error_code => {
            Ok(self.central
                .lock()
                .await
                .proteus_encrypt_batched(sessions.as_slice(), &plaintext)
                .await?)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::new_prekey]
    pub async fn proteus_new_prekey(&self, prekey_id: u16) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl! { self.proteus_last_error_code => {
            Ok(self.central
                .lock()
                .await
                .proteus_new_prekey(prekey_id)
                .await?)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::new_prekey_auto]
    pub async fn proteus_new_prekey_auto(&self) -> CoreCryptoResult<ProteusAutoPrekeyBundle> {
        proteus_impl! { self.proteus_last_error_code => {
            let (id, pkb) = self.central
                .lock()
                .await
                .proteus_new_prekey_auto()
                .await?;

            CoreCryptoResult::Ok(ProteusAutoPrekeyBundle { id, pkb })
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::last_resort_prekey]
    pub async fn proteus_last_resort_prekey(&self) -> CoreCryptoResult<Vec<u8>> {
        proteus_impl! { self.proteus_last_error_code => {
            Ok(self.central
                .lock()
                .await
                .proteus_last_resort_prekey()
                .await?)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::last_resort_prekey_id]
    pub fn proteus_last_resort_prekey_id(&self) -> CoreCryptoResult<u16> {
        proteus_impl!({ Ok(core_crypto::CoreCrypto::proteus_last_resort_prekey_id()) })
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint]
    pub async fn proteus_fingerprint(&self) -> CoreCryptoResult<String> {
        proteus_impl! { self.proteus_last_error_code => {
            Ok(self.central
                .lock()
                .await
                .proteus_fingerprint()?)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_local]
    pub async fn proteus_fingerprint_local(&self, session_id: String) -> CoreCryptoResult<String> {
        proteus_impl! { self.proteus_last_error_code => {
            Ok(self.central
                .lock()
                .await
                .proteus_fingerprint_local(&session_id)
                .await?)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_remote]
    pub async fn proteus_fingerprint_remote(&self, session_id: String) -> CoreCryptoResult<String> {
        proteus_impl! { self.proteus_last_error_code => {
            Ok(self.central
                .lock()
                .await
                .proteus_fingerprint_remote(&session_id)
                .await?)
        }}
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle]
    /// NOTE: uniffi doesn't support associated functions, so we have to have the self here
    pub fn proteus_fingerprint_prekeybundle(&self, prekey: Vec<u8>) -> CoreCryptoResult<String> {
        proteus_impl!({ Ok(core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle(&prekey)?) })
    }

    /// See [core_crypto::proteus::ProteusCentral::cryptobox_migrate]
    pub async fn proteus_cryptobox_migrate(&self, path: String) -> CoreCryptoResult<()> {
        proteus_impl! { self.proteus_last_error_code => {
            Ok(self.central
                .lock()
                .await
                .proteus_cryptobox_migrate(&path)
                .await?)
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
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> CoreCryptoResult<E2eiEnrollment> {
        Ok(self
            .central
            .lock()
            .await
            .e2ei_new_enrollment(
                client_id.into_bytes().into(),
                display_name,
                handle,
                team,
                expiry_sec,
                ciphersuite.into(),
            )
            .map(async_lock::RwLock::new)
            .map(std::sync::Arc::new)
            .map(E2eiEnrollment)?)
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_new_activation_enrollment]
    pub async fn e2ei_new_activation_enrollment(
        &self,
        display_name: String,
        handle: String,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> CoreCryptoResult<E2eiEnrollment> {
        Ok(self
            .central
            .lock()
            .await
            .e2ei_new_activation_enrollment(display_name, handle, team, expiry_sec, ciphersuite.into())
            .map(async_lock::RwLock::new)
            .map(std::sync::Arc::new)
            .map(E2eiEnrollment)?)
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_new_rotate_enrollment]
    pub async fn e2ei_new_rotate_enrollment(
        &self,
        display_name: Option<String>,
        handle: Option<String>,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> CoreCryptoResult<E2eiEnrollment> {
        Ok(self
            .central
            .lock()
            .await
            .e2ei_new_rotate_enrollment(display_name, handle, team, expiry_sec, ciphersuite.into())
            .await
            .map(async_lock::RwLock::new)
            .map(std::sync::Arc::new)
            .map(E2eiEnrollment)?)
    }

    pub async fn e2ei_dump_pki_env(&self) -> CoreCryptoResult<Option<E2eiDumpedPkiEnv>> {
        Ok(self.central.lock().await.e2ei_dump_pki_env().await?.map(Into::into))
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> bool {
        self.central.lock().await.e2ei_is_pki_env_setup().await
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_register_acme_ca]
    pub async fn e2ei_register_acme_ca(&self, trust_anchor_pem: String) -> CoreCryptoResult<()> {
        Ok(self
            .central
            .lock()
            .await
            .e2ei_register_acme_ca(trust_anchor_pem)
            .await?)
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_register_intermediate_ca_pem]
    pub async fn e2ei_register_intermediate_ca(&self, cert_pem: String) -> CoreCryptoResult<Option<Vec<String>>> {
        Ok(self
            .central
            .lock()
            .await
            .e2ei_register_intermediate_ca_pem(cert_pem)
            .await?
            .into())
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_register_crl]
    pub async fn e2ei_register_crl(&self, crl_dp: String, crl_der: Vec<u8>) -> CoreCryptoResult<CrlRegistration> {
        Ok(self
            .central
            .lock()
            .await
            .e2ei_register_crl(crl_dp, crl_der)
            .await?
            .into())
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_mls_init_only]
    pub async fn e2ei_mls_init_only(
        &self,
        enrollment: std::sync::Arc<E2eiEnrollment>,
        certificate_chain: String,
        nb_key_package: Option<u32>,
    ) -> CoreCryptoResult<Option<Vec<String>>> {
        let nb_key_package = nb_key_package
            .map(usize::try_from)
            .transpose()
            .map_err(CryptoError::from)?;

        Ok(self
            .central
            .lock()
            .await
            .e2ei_mls_init_only(
                enrollment.0.write().await.deref_mut(),
                certificate_chain,
                nb_key_package,
            )
            .await?
            .into())
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_rotate_all]
    pub async fn e2ei_rotate_all(
        &self,
        enrollment: std::sync::Arc<E2eiEnrollment>,
        certificate_chain: String,
        new_key_packages_count: u32,
    ) -> CoreCryptoResult<RotateBundle> {
        self.central
            .lock()
            .await
            .e2ei_rotate_all(
                enrollment.0.write().await.deref_mut(),
                certificate_chain,
                new_key_packages_count as usize,
            )
            .await?
            .try_into()
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_enrollment_stash]
    pub async fn e2ei_enrollment_stash(&self, enrollment: std::sync::Arc<E2eiEnrollment>) -> CoreCryptoResult<Vec<u8>> {
        let enrollment = std::sync::Arc::into_inner(enrollment).ok_or_else(|| CryptoError::LockPoisonError)?;
        let enrollment = std::sync::Arc::into_inner(enrollment.0)
            .ok_or_else(|| CryptoError::LockPoisonError)?
            .into_inner();

        Ok(self.central.lock().await.e2ei_enrollment_stash(enrollment).await?)
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_enrollment_stash_pop]
    pub async fn e2ei_enrollment_stash_pop(&self, handle: Vec<u8>) -> CoreCryptoResult<E2eiEnrollment> {
        Ok(self
            .central
            .lock()
            .await
            .e2ei_enrollment_stash_pop(handle)
            .await
            .map(async_lock::RwLock::new)
            .map(std::sync::Arc::new)
            .map(E2eiEnrollment)?)
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_conversation_state]
    pub async fn e2ei_conversation_state(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<E2eiConversationState> {
        Ok(self
            .central
            .lock()
            .await
            .e2ei_conversation_state(&conversation_id)
            .await
            .map(Into::into)?)
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> CoreCryptoResult<bool> {
        let sc = core_crypto::prelude::MlsCiphersuite::from(core_crypto::prelude::CiphersuiteName::from(ciphersuite))
            .signature_algorithm();
        Ok(self.central.lock().await.e2ei_is_enabled(sc)?)
    }

    /// See [core_crypto::mls::MlsCentral::get_device_identities]
    pub async fn get_device_identities(
        &self,
        conversation_id: Vec<u8>,
        device_ids: Vec<ClientId>,
    ) -> CoreCryptoResult<Vec<WireIdentity>> {
        let device_ids = device_ids.into_iter().map(|cid| cid.0).collect::<Vec<_>>();
        Ok(self
            .central
            .lock()
            .await
            .get_device_identities(&conversation_id, &device_ids[..])
            .await?
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>())
    }

    /// See [core_crypto::mls::MlsCentral::get_user_identities]
    pub async fn get_user_identities(
        &self,
        conversation_id: Vec<u8>,
        user_ids: Vec<String>,
    ) -> CoreCryptoResult<HashMap<String, Vec<WireIdentity>>> {
        Ok(self
            .central
            .lock()
            .await
            .get_user_identities(&conversation_id, &user_ids[..])
            .await?
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().map(Into::into).collect()))
            .collect::<HashMap<String, Vec<WireIdentity>>>())
    }

    /// See [core_crypto::mls::MlsCentral::get_credential_in_use]
    pub async fn get_credential_in_use(
        &self,
        group_info: Vec<u8>,
        credential_type: MlsCredentialType,
    ) -> CoreCryptoResult<E2eiConversationState> {
        let group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info.as_slice())
            .map_err(MlsError::from)
            .map_err(CryptoError::from)?;
        Ok(self
            .central
            .lock()
            .await
            .get_credential_in_use(group_info, credential_type.into())
            .await?
            .into())
    }
}

#[derive(Debug, uniffi::Object)]
/// See [core_crypto::e2e_identity::E2eiEnrollment]
pub struct E2eiEnrollment(std::sync::Arc<async_lock::RwLock<core_crypto::prelude::E2eiEnrollment>>);

#[uniffi::export]
impl E2eiEnrollment {
    /// See [core_crypto::e2e_identity::E2eiEnrollment::directory_response]
    pub async fn directory_response(&self, directory: Vec<u8>) -> CoreCryptoResult<AcmeDirectory> {
        Ok(self
            .0
            .write()
            .await
            .directory_response(directory)
            .map(AcmeDirectory::from)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_account_request]
    pub async fn new_account_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.read().await.new_account_request(previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_account_response]
    pub async fn new_account_response(&self, account: Vec<u8>) -> CoreCryptoResult<()> {
        Ok(self.0.write().await.new_account_response(account)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_order_request]
    #[allow(clippy::too_many_arguments)]
    pub async fn new_order_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.read().await.new_order_request(previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_order_response]
    pub async fn new_order_response(&self, order: Vec<u8>) -> CoreCryptoResult<NewAcmeOrder> {
        Ok(self.0.read().await.new_order_response(order)?.into())
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_authz_request]
    pub async fn new_authz_request(&self, url: String, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.read().await.new_authz_request(url, previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_authz_response]
    pub async fn new_authz_response(&self, authz: Vec<u8>) -> CoreCryptoResult<NewAcmeAuthz> {
        Ok(self.0.write().await.new_authz_response(authz)?.into())
    }

    #[allow(clippy::too_many_arguments)]
    /// See [core_crypto::e2e_identity::E2eiEnrollment::create_dpop_token]
    pub async fn create_dpop_token(&self, expiry_secs: u32, backend_nonce: String) -> CoreCryptoResult<String> {
        Ok(self.0.read().await.create_dpop_token(expiry_secs, backend_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_dpop_challenge_request]
    pub async fn new_dpop_challenge_request(
        &self,
        access_token: String,
        previous_nonce: String,
    ) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .0
            .read()
            .await
            .new_dpop_challenge_request(access_token, previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_dpop_challenge_response]
    pub async fn new_dpop_challenge_response(&self, challenge: Vec<u8>) -> CoreCryptoResult<()> {
        Ok(self.0.read().await.new_dpop_challenge_response(challenge)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_oidc_challenge_request]
    pub async fn new_oidc_challenge_request(
        &self,
        id_token: String,
        refresh_token: String,
        previous_nonce: String,
    ) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .0
            .write()
            .await
            .new_oidc_challenge_request(id_token, refresh_token, previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_oidc_challenge_response]
    pub async fn new_oidc_challenge_response(
        &self,
        cc: std::sync::Arc<CoreCrypto>,
        challenge: Vec<u8>,
    ) -> CoreCryptoResult<()> {
        let cc = cc.central.lock().await;
        Ok(self
            .0
            .write()
            .await
            .new_oidc_challenge_response(cc.provider(), challenge)
            .await?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::check_order_request]
    pub async fn check_order_request(&self, order_url: String, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.read().await.check_order_request(order_url, previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::check_order_response]
    pub async fn check_order_response(&self, order: Vec<u8>) -> CoreCryptoResult<String> {
        Ok(self.0.write().await.check_order_response(order)?)
    }

    /// See [core_crypto::prelude::E2eiEnrollment::finalize_request]
    pub async fn finalize_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.write().await.finalize_request(previous_nonce)?)
    }

    /// See [core_crypto::prelude::E2eiEnrollment::finalize_response]
    pub async fn finalize_response(&self, finalize: Vec<u8>) -> CoreCryptoResult<String> {
        Ok(self.0.write().await.finalize_response(finalize)?)
    }

    /// See [core_crypto::prelude::E2eiEnrollment::certificate_request]
    pub async fn certificate_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.write().await.certificate_request(previous_nonce)?)
    }

    /// See [core_crypto::prelude::E2eiEnrollment::get_refresh_token]
    pub async fn get_refresh_token(&self) -> CoreCryptoResult<String> {
        Ok(self.0.read().await.get_refresh_token().map(Into::into)?)
    }
}

#[derive(Debug, uniffi::Record)]
/// See [core_crypto::e2e_identity::types::E2eiAcmeDirectory]
pub struct AcmeDirectory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub revoke_cert: String,
}

impl From<core_crypto::prelude::E2eiAcmeDirectory> for AcmeDirectory {
    fn from(directory: core_crypto::prelude::E2eiAcmeDirectory) -> Self {
        Self {
            new_nonce: directory.new_nonce,
            new_account: directory.new_account,
            new_order: directory.new_order,
            revoke_cert: directory.revoke_cert,
        }
    }
}

impl From<AcmeDirectory> for core_crypto::prelude::E2eiAcmeDirectory {
    fn from(directory: AcmeDirectory) -> Self {
        Self {
            new_nonce: directory.new_nonce,
            new_account: directory.new_account,
            new_order: directory.new_order,
            revoke_cert: directory.revoke_cert,
        }
    }
}

#[derive(Debug, uniffi::Record)]
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

#[derive(Debug, uniffi::Record)]
/// See [core_crypto::e2e_identity::types::E2eiNewAcmeAuthz]
pub struct NewAcmeAuthz {
    pub identifier: String,
    pub keyauth: Option<String>,
    pub challenge: AcmeChallenge,
}

impl From<core_crypto::prelude::E2eiNewAcmeAuthz> for NewAcmeAuthz {
    fn from(new_authz: core_crypto::prelude::E2eiNewAcmeAuthz) -> Self {
        Self {
            identifier: new_authz.identifier,
            keyauth: new_authz.keyauth,
            challenge: new_authz.challenge.into(),
        }
    }
}

impl From<NewAcmeAuthz> for core_crypto::prelude::E2eiNewAcmeAuthz {
    fn from(new_authz: NewAcmeAuthz) -> Self {
        Self {
            identifier: new_authz.identifier,
            keyauth: new_authz.keyauth,
            challenge: new_authz.challenge.into(),
        }
    }
}

#[derive(Debug, uniffi::Record)]
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
