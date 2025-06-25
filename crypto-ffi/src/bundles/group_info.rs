use core_crypto::prelude::MlsGroupInfoBundle;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::core_crypto_context::mls::{GroupInfo_coerce_maybe_arc, GroupInfoMaybeArc};

#[derive(Debug, Clone, Copy)]
#[cfg_attr(target_family = "wasm", wasm_bindgen, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Enum))]
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

#[derive(Debug, Clone, Copy)]
#[cfg_attr(target_family = "wasm", wasm_bindgen, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Enum))]
#[repr(u8)]
pub enum MlsRatchetTreeType {
    /// Plain old and complete `GroupInfo`
    Full = 1,
    /// Contains `GroupInfo` changes since previous epoch (not yet implemented)
    /// (see [draft](https://github.com/rohan-wire/ietf-drafts/blob/main/mahy-mls-ratchet-tree-delta/draft-mahy-mls-ratchet-tree-delta.md))
    Delta = 2,
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

#[derive(Debug, Clone)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct GroupInfoBundle {
    pub encryption_type: MlsGroupInfoEncryptionType,
    pub ratchet_tree_type: MlsRatchetTreeType,
    pub payload: GroupInfoMaybeArc,
}

impl From<MlsGroupInfoBundle> for GroupInfoBundle {
    fn from(gi: MlsGroupInfoBundle) -> Self {
        Self {
            encryption_type: gi.encryption_type.into(),
            ratchet_tree_type: gi.ratchet_tree_type.into(),
            payload: GroupInfo_coerce_maybe_arc(gi.payload.bytes()),
        }
    }
}
