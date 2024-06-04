use openmls::prelude::{group_info::GroupInfo, MlsMessageOut};
use serde::{Deserialize, Serialize};

use crate::{CryptoResult, MlsError};

/// A [GroupInfo] with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsGroupInfoBundle {
    /// Indicates if the `payload` is encrypted or not
    pub encryption_type: MlsGroupInfoEncryptionType,
    /// Indicates if the `payload` contains a full, partial or referenced [GroupInfo]
    pub ratchet_tree_type: MlsRatchetTreeType,
    /// The [GroupInfo]
    pub payload: GroupInfoPayload,
}

impl MlsGroupInfoBundle {
    /// Creates a new [GroupInfoBundle] with complete and unencrypted [GroupInfo]
    pub(crate) fn try_new_full_plaintext(gi: GroupInfo) -> CryptoResult<Self> {
        use tls_codec::Serialize as _;

        let payload = MlsMessageOut::from(gi);
        let payload = payload.tls_serialize_detached().map_err(MlsError::from)?;
        Ok(Self {
            encryption_type: MlsGroupInfoEncryptionType::Plaintext,
            ratchet_tree_type: MlsRatchetTreeType::Full,
            payload: GroupInfoPayload::Plaintext(payload),
        })
    }
}

#[cfg(test)]
impl MlsGroupInfoBundle {
    pub fn get_group_info(self) -> openmls::prelude::group_info::VerifiableGroupInfo {
        match self.get_payload().extract() {
            openmls::prelude::MlsMessageInBody::GroupInfo(vgi) => vgi,
            _ => panic!("This payload should contain a GroupInfo"),
        }
    }

    pub fn get_payload(mut self) -> openmls::prelude::MlsMessageIn {
        use tls_codec::Deserialize as _;
        match &mut self.payload {
            GroupInfoPayload::Plaintext(gi) => {
                openmls::prelude::MlsMessageIn::tls_deserialize(&mut gi.as_slice()).unwrap()
            }
        }
    }
}

/// # GroupInfoEncryptionType
///
/// In order to guarantee confidentiality of the [GroupInfo] on the wire a domain can
/// request it to be encrypted when sent to the Delivery Service.
///
/// ```text
/// enum {
///     plaintext(1),
///     jwe_encrypted(2),
///     (255)
/// } GroupInfoEncryptionType;
/// ```
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MlsGroupInfoEncryptionType {
    /// Unencrypted [GroupInfo]
    Plaintext = 1,
    /// [GroupInfo] encrypted in a JWE
    JweEncrypted = 2,
}

/// # RatchetTreeType
///
/// In order to spare some precious bytes, a [GroupInfo] can have different representations.
///
/// ```text
/// enum {
///     full(1),
///     delta(2),
///     by_ref(3),
///     (255)
/// } RatchetTreeType;
/// ```
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MlsRatchetTreeType {
    /// Plain old and complete [GroupInfo]
    Full = 1,
    /// Contains [GroupInfo] changes since previous epoch (not yet implemented)
    /// (see [draft](https://github.com/rohan-wire/ietf-drafts/blob/main/mahy-mls-ratchet-tree-delta/draft-mahy-mls-ratchet-tree-delta.md))
    Delta = 2,
    /// Not implemented
    ByRef = 3,
}

/// Represents the byte array in [MlsGroupInfoBundle]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupInfoPayload {
    /// Unencrypted [GroupInfo]
    Plaintext(Vec<u8>),
    // not implemented
    // Encrypted(Vec<u8>),
}

impl GroupInfoPayload {
    /// Returns the internal byte array
    pub fn bytes(self) -> Vec<u8> {
        match self {
            GroupInfoPayload::Plaintext(gi) => gi,
        }
    }
}
