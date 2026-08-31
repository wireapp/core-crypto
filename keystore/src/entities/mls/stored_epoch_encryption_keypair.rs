use rusqlite::{named_params, params};
use zeroize::Zeroize;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Transactionlike,
    entities::{ConversationId, ConversationIdRef},
};

/// Entity representing a list of [StoredEncryptionKeyPair][super::StoredEncryptionKeyPair]
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct StoredEpochEncryptionKeypair {
    pub conversation_id: Vec<u8>,
    pub own_leaf_idx: u32,
    pub epoch: u64,
    #[sensitive]
    pub keypairs: Vec<u8>,
}

/// Primary key type for [`StoredEpochEncryptionKeypair`]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoredEpochEncryptionKeypairPk {
    pub conversation_id: ConversationId,
    pub own_leaf_idx: u32,
    pub epoch: u64,
}

/// Borrowed primary key type for [`StoredEpochEncryptionKeypair`]
#[derive(Clone, Copy)]
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

    /// Construct a pk ref from the requisite data
    pub fn new(conversation_id: &'a [u8], own_leaf_idx: u32, epoch: u64) -> Self {
        Self {
            conversation_id: ConversationIdRef::new(conversation_id),
            own_leaf_idx,
            epoch,
        }
    }
}

impl StoredEpochEncryptionKeypair {
    const PK_COLUMN_NAMES: &[&str] = &["conversation_id", "own_leaf_index", "epoch"];

    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        let conversation_id = row.get("conversation_id")?;
        let own_leaf_idx = row.get("own_leaf_index")?;
        let epoch = row.get("epoch")?;
        let keypairs = row.get("keypairs")?;
        Ok(Self {
            conversation_id,
            own_leaf_idx,
            epoch,
            keypairs,
        })
    }
}

impl crate::traits::PrimaryKey for StoredEpochEncryptionKeypair {
    type PrimaryKey = StoredEpochEncryptionKeypairPk;
    fn primary_key(&self) -> Self::PrimaryKey {
        StoredEpochEncryptionKeypairPk {
            conversation_id: self.conversation_id.clone().into(),
            own_leaf_idx: self.own_leaf_idx,
            epoch: self.epoch,
        }
    }
}

impl crate::traits::BorrowPrimaryKey for StoredEpochEncryptionKeypair {
    type BorrowedPrimaryKey<'a> = StoredEpochEncryptionKeypairPkRef<'a>;
    fn borrow_primary_key(&self) -> Self::BorrowedPrimaryKey<'_> {
        StoredEpochEncryptionKeypairPkRef {
            conversation_id: ConversationIdRef::new(&self.conversation_id),
            own_leaf_idx: self.own_leaf_idx,
            epoch: self.epoch,
        }
    }
}

impl crate::traits::Entity for StoredEpochEncryptionKeypair {
    const TABLE_NAME: &'static str = "epoch_encryption_keypairs";
    fn get(conn: &rusqlite::Connection, key: &Self::PrimaryKey) -> crate::CryptoKeystoreResult<Option<Self>> {
        <Self as crate::traits::EntityGetBorrowed>::get_borrowed(conn, key.into())
    }
    fn count(conn: &rusqlite::Connection) -> crate::CryptoKeystoreResult<u32> {
        crate::entities::helpers::count_helper::<Self>(conn)
    }
    fn load_all(conn: &rusqlite::Connection) -> crate::CryptoKeystoreResult<Vec<Self>> {
        crate::entities::helpers::load_all_helper::<Self, _>(conn, Self::from_row)
    }
}

impl crate::traits::EntityGetBorrowed for StoredEpochEncryptionKeypair {
    fn get_borrowed(
        conn: &rusqlite::Connection,
        key: Self::BorrowedPrimaryKey<'_>,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        crate::entities::helpers::get_helper_composite_key::<Self, _>(
            conn,
            Self::PK_COLUMN_NAMES,
            params![key.conversation_id, key.own_leaf_idx, key.epoch],
            Self::from_row,
        )
    }
}

impl crate::traits::EntityDatabaseMutation for StoredEpochEncryptionKeypair {
    fn save<'a, Tx>(&self, tx: &'a Tx) -> crate::CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO epoch_encryption_keypairs (
                conversation_id,
                own_leaf_index,
                epoch,
                keypairs
            ) VALUES (
                :conversation_id,
                :own_leaf_idx,
                :epoch,
                :keypairs
            )",
        )?;
        stmt.execute(named_params! {
            ":conversation_id": self.conversation_id,
            ":own_leaf_idx": self.own_leaf_idx,
            ":epoch": self.epoch,
            ":keypairs": self.keypairs,
        })?;
        Ok(())
    }
    fn delete<'a, Tx>(tx: &'a Tx, id: &Self::PrimaryKey) -> crate::CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        <Self as crate::traits::EntityDeleteBorrowed>::delete_borrowed(tx, id.into())
    }
}

impl crate::traits::EntityDeleteBorrowed for StoredEpochEncryptionKeypair {
    fn delete_borrowed<'a, Tx>(
        tx: &'a Tx,
        key: <Self as crate::traits::BorrowPrimaryKey>::BorrowedPrimaryKey<'_>,
    ) -> crate::CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        crate::entities::helpers::delete_helper_composite_key::<Self, _>(
            tx,
            Self::PK_COLUMN_NAMES,
            params![key.conversation_id, key.own_leaf_idx, key.epoch],
        )
        .map(|count| count > 0)
    }
}
