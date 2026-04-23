use std::sync::Arc;

use core_crypto::{MlsGroupInfoBundle, MlsMessageIn, MlsMessageInBody};
use tls_codec::Deserialize;

use crate::{CoreCryptoError, CoreCryptoResult, core_crypto_context::mls::GroupInfo};

/// How a `GroupInfo` is encrypted in a commit bundle.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
#[repr(u8)]
pub enum MlsGroupInfoEncryptionType {
    /// Unencrypted `GroupInfo`
    Plaintext = 1,
    /// `GroupInfo` encrypted in a JWE
    JweEncrypted = 2,
}

impl From<core_crypto::MlsGroupInfoEncryptionType> for MlsGroupInfoEncryptionType {
    fn from(value: core_crypto::MlsGroupInfoEncryptionType) -> Self {
        match value {
            core_crypto::MlsGroupInfoEncryptionType::Plaintext => Self::Plaintext,
            core_crypto::MlsGroupInfoEncryptionType::JweEncrypted => Self::JweEncrypted,
        }
    }
}

impl From<MlsGroupInfoEncryptionType> for core_crypto::MlsGroupInfoEncryptionType {
    fn from(value: MlsGroupInfoEncryptionType) -> Self {
        match value {
            MlsGroupInfoEncryptionType::Plaintext => Self::Plaintext,
            MlsGroupInfoEncryptionType::JweEncrypted => Self::JweEncrypted,
        }
    }
}

/// How the ratchet tree is represented in a `GroupInfo`.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
#[repr(u8)]
pub enum MlsRatchetTreeType {
    /// The full ratchet tree is included.
    Full = 1,
    /// Only changes since the previous epoch are included.
    ///
    /// Not yet implemented. See the draft proposal:
    /// <https://github.com/rohan-wire/ietf-drafts/blob/main/mahy-mls-ratchet-tree-delta/draft-mahy-mls-ratchet-tree-delta.md>
    Delta = 2,
    /// The ratchet tree is identified by an external reference rather than included inline.
    ByRef = 3,
}

impl From<core_crypto::MlsRatchetTreeType> for MlsRatchetTreeType {
    fn from(value: core_crypto::MlsRatchetTreeType) -> Self {
        match value {
            core_crypto::MlsRatchetTreeType::Full => Self::Full,
            core_crypto::MlsRatchetTreeType::Delta => Self::Delta,
            core_crypto::MlsRatchetTreeType::ByRef => Self::ByRef,
        }
    }
}

impl From<MlsRatchetTreeType> for core_crypto::MlsRatchetTreeType {
    fn from(value: MlsRatchetTreeType) -> Self {
        match value {
            MlsRatchetTreeType::Full => Self::Full,
            MlsRatchetTreeType::Delta => Self::Delta,
            MlsRatchetTreeType::ByRef => Self::ByRef,
        }
    }
}

/// A `GroupInfo` with associated metadata.
#[derive(Debug, Clone, uniffi::Record)]
pub struct GroupInfoBundle {
    /// How the group info is encrypted.
    pub encryption_type: MlsGroupInfoEncryptionType,
    /// What kind of ratchet tree is used.
    pub ratchet_tree_type: MlsRatchetTreeType,
    /// The group info payload.
    pub payload: Arc<GroupInfo>,
}

impl TryFrom<MlsGroupInfoBundle> for GroupInfoBundle {
    type Error = CoreCryptoError;

    fn try_from(group_info_bundle: MlsGroupInfoBundle) -> CoreCryptoResult<Self> {
        // single variant => no match stmt necessary
        let core_crypto::GroupInfoPayload::Plaintext(payload) = group_info_bundle.payload;
        let message_in = MlsMessageIn::tls_deserialize_exact(payload)
            .map_err(CoreCryptoError::generic())?
            .extract();
        let MlsMessageInBody::GroupInfo(group_info) = message_in else {
            return Err(CoreCryptoError::ad_hoc(
                "group info bundle contained a non-GroupInfo body",
            ));
        };
        let payload = Arc::new(group_info.into());

        Ok(Self {
            encryption_type: group_info_bundle.encryption_type.into(),
            ratchet_tree_type: group_info_bundle.ratchet_tree_type.into(),
            payload,
        })
    }
}
