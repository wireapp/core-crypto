use zeroize::Zeroize;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    entities::{ConversationId, ConversationIdRef},
};

/// Entity representing a list of [StoredEncryptionKeyPair][super::StoredEncryptionKeyPair]
#[derive(
    core_crypto_macros::Debug,
    Clone,
    PartialEq,
    Eq,
    Zeroize,
    core_crypto_macros::Entity,
    serde::Serialize,
    serde::Deserialize,
)]
#[zeroize(drop)]
#[entity(table_name = "mls_epoch_encryption_keypairs")]
pub struct StoredEpochEncryptionKeypair {
    pub id: Vec<u8>,
    #[sensitive]
    pub keypairs: Vec<u8>,
}

/// Primary key type for [`StoredEpochEncryptionKeypair`]
pub struct StoredEpochEncryptionKeypairPk {
    pub conversation_id: ConversationId,
    pub own_leaf_idx: u32,
    pub epoch: u64,
}

/// Borrowed primary key type for [`StoredEpochEncryptionKeypair`]
pub struct StoredEpochEncryptionKeypairPkRef<'a> {
    pub conversation_id: &'a ConversationIdRef,
    pub own_leaf_idx: u32,
    pub epoch: u64,
}

impl<'a> From<&'a StoredEpochEncryptionKeypairPk> for StoredEpochEncryptionKeypairPkRef<'a> {
    fn from(
        StoredEpochEncryptionKeypairPk {
            conversation_id,
            own_leaf_idx,
            epoch,
        }: &'a StoredEpochEncryptionKeypairPk,
    ) -> Self {
        StoredEpochEncryptionKeypairPkRef {
            conversation_id: ConversationIdRef::new(conversation_id.bytes()),
            own_leaf_idx: *own_leaf_idx,
            epoch: *epoch,
        }
    }
}

impl<'a> From<StoredEpochEncryptionKeypairPkRef<'a>> for StoredEpochEncryptionKeypairPk {
    fn from(
        StoredEpochEncryptionKeypairPkRef {
            conversation_id,
            own_leaf_idx,
            epoch,
        }: StoredEpochEncryptionKeypairPkRef<'a>,
    ) -> Self {
        StoredEpochEncryptionKeypairPk {
            conversation_id: conversation_id.into(),
            own_leaf_idx,
            epoch,
        }
    }
}

impl<'a> StoredEpochEncryptionKeypairPkRef<'a> {
    /// Parse this PK from its binary representation
    ///
    /// OpenMLS assumes that all primary keys are byte slices, and designed
    /// its trait structure accordingly. So we have to be able to parse a
    /// (probably-freshly-constructed) slice into a discrete type.
    pub fn parse_bytes(bytes: &'a [u8]) -> CryptoKeystoreResult<Self> {
        let (rest, epoch) = bytes.split_at_checked(bytes.len() - size_of::<u64>()).ok_or_else(|| {
            CryptoKeystoreError::MlsKeyStoreError(
                "insufficient bytes to parse epoch when parsing StoredEpochEncryptionKeypairPkRef".into(),
            )
        })?;
        let (conversation_id, own_leaf_idx) =
            rest.split_at_checked(rest.len() - size_of::<u32>()).ok_or_else(|| {
                CryptoKeystoreError::MlsKeyStoreError(
                    "insufficient bytes to parse own leaf idx when parsing StoredEpochEncryptionKeypairPkRef".into(),
                )
            })?;

        let epoch = u64::from_be_bytes(
            epoch
                .try_into()
                .expect("we already chose exactly the right number of bytes"),
        );
        let own_leaf_idx = u32::from_be_bytes(
            own_leaf_idx
                .try_into()
                .expect("we already chose exactly the right number of bytes"),
        );
        let conversation_id = ConversationIdRef::new(conversation_id);

        Ok(Self {
            conversation_id,
            own_leaf_idx,
            epoch,
        })
    }
}
