use core_crypto::MlsGroupInfoBundle;

use crate::core_crypto_context::mls::{GroupInfoMaybeArc, group_info_coerce_maybe_arc};

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

#[derive(Debug, Clone, Copy, uniffi::Enum)]
#[repr(u8)]
pub enum MlsRatchetTreeType {
    /// Plain old and complete `GroupInfo`
    Full = 1,
    /// Contains `GroupInfo` changes since previous epoch (not yet implemented)
    /// (see [draft](https://github.com/rohan-wire/ietf-drafts/blob/main/mahy-mls-ratchet-tree-delta/draft-mahy-mls-ratchet-tree-delta.md))
    Delta = 2,
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

/// A `GroupInfo` with some metadata
#[derive(Debug, Clone, uniffi::Record)]
pub struct GroupInfoBundle {
    /// How the group info is encrypetd
    pub encryption_type: MlsGroupInfoEncryptionType,
    /// What kind of ratchet tree is used
    pub ratchet_tree_type: MlsRatchetTreeType,
    /// The group info
    pub payload: GroupInfoMaybeArc,
}

impl From<MlsGroupInfoBundle> for GroupInfoBundle {
    fn from(gi: MlsGroupInfoBundle) -> Self {
        Self {
            encryption_type: gi.encryption_type.into(),
            ratchet_tree_type: gi.ratchet_tree_type.into(),
            payload: group_info_coerce_maybe_arc(gi.payload.bytes()),
        }
    }
}
