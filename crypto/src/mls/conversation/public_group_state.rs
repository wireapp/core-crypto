use openmls::prelude::PublicGroupState;
use serde::{Deserialize, Serialize};

use crate::{CryptoResult, MlsError};

/// A [PublicGroupState] with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsPublicGroupStateBundle {
    /// Indicates if the [payload] is encrypted or not
    pub encryption_type: MlsPublicGroupStateEncryptionType,
    /// Indicates if the [payload] contains a full, partial or referenced [PublicGroupState]
    pub ratchet_tree_type: MlsRatchetTreeType,
    /// The [PublicGroupState]
    pub payload: PublicGroupStatePayload,
}

impl MlsPublicGroupStateBundle {
    /// Creates a new [PublicGroupStateBundle] with complete and unencrypted [PublicGroupState]
    pub(crate) fn try_new_full_plaintext(pgs: PublicGroupState) -> CryptoResult<Self> {
        use tls_codec::Serialize as _;
        let payload = pgs.tls_serialize_detached().map_err(MlsError::from)?.into();
        Ok(Self {
            encryption_type: MlsPublicGroupStateEncryptionType::Plaintext,
            ratchet_tree_type: MlsRatchetTreeType::Full,
            payload: PublicGroupStatePayload::Plaintext(payload),
        })
    }
}

#[cfg(test)]
impl MlsPublicGroupStateBundle {
    pub fn get_pgs(mut self) -> openmls::prelude::VerifiablePublicGroupState {
        use tls_codec::Deserialize as _;
        match &mut self.payload {
            PublicGroupStatePayload::Plaintext(pgs) => {
                openmls::prelude::VerifiablePublicGroupState::tls_deserialize(&mut pgs.as_slice()).unwrap()
            }
        }
    }
}

/// # PublicGroupStateEncryptionType
///
/// In order to guarantee confidentiality of the [PublicGroupState] on the wire a domain can
/// request it to be encrypted when sent to the Delivery Service.
///
/// ```text
/// enum {
///     plaintext(1),
///     jwe_encrypted(2),
///     (255)
/// } PublicGroupStateEncryptionType;
/// ```
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MlsPublicGroupStateEncryptionType {
    /// Unencrypted [PublicGroupState]
    Plaintext = 1,
    /// [PublicGroupState] encrypted in a JWE
    JweEncrypted = 2,
}

/// # RatchetTreeType
///
/// In order to spare some precious bytes, a [PublicGroupState] can have different representations.
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
    /// Plain old and complete [PublicGroupState]
    Full = 1,
    /// Contains [PublicGroupState] changes since previous epoch (not yet implemented)
    /// (see [draft](https://github.com/rohan-wire/ietf-drafts/blob/main/mahy-mls-ratchet-tree-delta/draft-mahy-mls-ratchet-tree-delta.md))
    Delta = 2,
    /// TODO: to define
    ByRef = 3,
}

/// Represents the byte array in [PublicGroupStateBundle]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PublicGroupStatePayload {
    /// Unencrypted [PublicGroupState]
    Plaintext(tls_codec::TlsByteVecU32),
    // TODO: expose when fully implemented
    // Encrypted(Vec<u8>),
}

impl tls_codec::Size for PublicGroupStatePayload {
    fn tls_serialized_len(&self) -> usize {
        match &self {
            Self::Plaintext(pgs) => pgs.tls_serialized_len(),
        }
    }
}

impl tls_codec::Serialize for PublicGroupStatePayload {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        match self {
            Self::Plaintext(pgs) => pgs.tls_serialize(writer),
        }
    }
}
