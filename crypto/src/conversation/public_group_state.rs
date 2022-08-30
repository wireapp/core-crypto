use std::io::{Read, Write};

use openmls::prelude::{PublicGroupState, Verifiable, VerifiablePublicGroupState};
use tls_codec::{Error, TlsDeserialize, TlsSerialize, TlsSize};

use crate::{CryptoResult, MlsError};

/// # PublicGroupStateEncryption
///
/// In order to guarantee confidentiality of the [PublicGroupState] on the wire a domain can
/// request it to be encrypted when sent to the Delivery Service.
///
/// ```text
/// enum {
///     reserved(0),
///     unencrypted(1),
///     jwe_encrypted(2),
///     (255)
/// } PublicGroupStateEncryption;
/// ```
#[derive(Debug, Clone, Eq, PartialEq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum PublicGroupStateEncryption {
    Reserved = 0,
    Unencrypted = 1,
    JweEncrypted = 2,
}

/// # RatchetTreeType
///
/// In order to spare some precious bytes, a [PublicGroupState] can have different representations.
///
/// ```text
/// enum {
///     reserved(0),
///     full(1),
///     delta(2),
///     by_ref(3),
///     (255)
/// } RatchetTreeType;
/// ```
#[derive(Debug, Clone, Eq, PartialEq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum RatchetTreeType {
    Reserved = 0,
    /// Plain old and complete [PublicGroupState]
    Full = 1,
    /// Contains [PublicGroupState] changes since previous epoch (Not yet implemented)
    /// (see [draft](https://github.com/rohan-wire/ietf-drafts/blob/main/mahy-mls-ratchet-tree-delta/draft-mahy-mls-ratchet-tree-delta.md))
    Delta = 2,
    ByRef = 3,
}

/// Represents the byte array in [PublicGroupStateBundle]
#[derive(Debug)]
pub enum PublicGroupStatePayload {
    /// Unencrypted [PublicGroupState]
    Plaintext(tls_codec::TlsByteVecU32),
    // TODO: expose when fully implemented
    // Encrypted(Vec<u8>),
}

/// Contains a [PublicGroupState] alongside metadatas
#[derive(Debug)]
pub struct PublicGroupStateBundle {
    /// Indicates if the [payload] is encrypted or not
    encryption_type: PublicGroupStateEncryption,
    /// Indicates if the [payload] contains a full, partial or referenced [PublicGroupState]
    ratchet_tree_type: RatchetTreeType,
    /// The [PublicGroupState]
    payload: PublicGroupStatePayload,
}

impl PublicGroupStateBundle {
    /// Creates a new [PublicGroupStateBundle] with complete and unencrypted [PublicGroupState]
    pub(crate) fn try_new_full_unencrypted(pgs: PublicGroupState) -> CryptoResult<Self> {
        use tls_codec::Serialize as _;
        let payload = pgs.tls_serialize_detached().map_err(MlsError::from)?.into();
        Ok(Self {
            encryption_type: PublicGroupStateEncryption::Unencrypted,
            ratchet_tree_type: RatchetTreeType::Full,
            payload: PublicGroupStatePayload::Plaintext(payload),
        })
    }
}

#[cfg(test)]
impl PublicGroupStateBundle {
    pub fn get_pgs(mut self) -> VerifiablePublicGroupState {
        use tls_codec::Deserialize as _;
        match &mut self.payload {
            PublicGroupStatePayload::Plaintext(pgs) => {
                VerifiablePublicGroupState::tls_deserialize(&mut pgs.as_slice()).unwrap()
            }
        }
    }
}

impl tls_codec::Size for PublicGroupStateBundle {
    fn tls_serialized_len(&self) -> usize {
        self.encryption_type.tls_serialized_len()
            + self.ratchet_tree_type.tls_serialized_len()
            + match &self.payload {
                PublicGroupStatePayload::Plaintext(pgs) => pgs.tls_serialized_len(),
            }
    }
}

impl tls_codec::Serialize for PublicGroupStateBundle {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.encryption_type
            .tls_serialize(writer)
            .and_then(|w| self.ratchet_tree_type.tls_serialize(writer).map(|l| l + w))
            .and_then(|w| match &self.payload {
                PublicGroupStatePayload::Plaintext(pgs) => pgs.tls_serialize(writer).map(|l| l + w),
            })
    }
}

impl tls_codec::Deserialize for PublicGroupStateBundle {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
        let encryption_type = PublicGroupStateEncryption::tls_deserialize(bytes)?;
        let ratchet_tree_type = RatchetTreeType::tls_deserialize(bytes)?;
        match encryption_type {
            PublicGroupStateEncryption::Unencrypted => {
                let payload = VerifiablePublicGroupState::tls_deserialize(bytes)?;
                let payload = PublicGroupStatePayload::Plaintext(payload.unsigned_payload()?.into());
                Ok(Self {
                    encryption_type,
                    ratchet_tree_type,
                    payload,
                })
            }
            _ => Err(Error::DecodingError("Unsupported encryption type".to_string())),
        }
    }
}
