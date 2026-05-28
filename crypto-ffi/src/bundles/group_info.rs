use core_crypto::GroupInfoBundle as CcGroupInfoBundle;

/// How a `GroupInfo` is encrypted in a commit bundle.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
#[repr(u8)]
pub enum MlsGroupInfoEncryptionType {
    /// Unencrypted `GroupInfo`
    Plaintext = 1,
    /// `GroupInfo` encrypted in a JWE
    JweEncrypted = 2,
}

impl From<core_crypto::GroupInfoEncryptionType> for MlsGroupInfoEncryptionType {
    fn from(value: core_crypto::GroupInfoEncryptionType) -> Self {
        match value {
            core_crypto::GroupInfoEncryptionType::Plaintext => Self::Plaintext,
            core_crypto::GroupInfoEncryptionType::JweEncrypted => Self::JweEncrypted,
        }
    }
}

impl From<MlsGroupInfoEncryptionType> for core_crypto::GroupInfoEncryptionType {
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

impl From<core_crypto::RatchetTreeType> for MlsRatchetTreeType {
    fn from(value: core_crypto::RatchetTreeType) -> Self {
        match value {
            core_crypto::RatchetTreeType::Full => Self::Full,
            core_crypto::RatchetTreeType::Delta => Self::Delta,
            core_crypto::RatchetTreeType::ByRef => Self::ByRef,
        }
    }
}

impl From<MlsRatchetTreeType> for core_crypto::RatchetTreeType {
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
    pub payload: Vec<u8>,
}

impl From<CcGroupInfoBundle> for GroupInfoBundle {
    fn from(group_info_bundle: CcGroupInfoBundle) -> Self {
        // single variant => no match stmt necessary
        let core_crypto::GroupInfoPayload::Plaintext(payload) = group_info_bundle.payload;
        Self {
            encryption_type: group_info_bundle.encryption_type.into(),
            ratchet_tree_type: group_info_bundle.ratchet_tree_type.into(),
            payload,
        }
    }
}
