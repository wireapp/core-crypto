use rusqlite::{Connection, named_params};
use zeroize::ZeroizeOnDrop;

use crate::{
    CryptoKeystoreResult, Sha256Hash, Transactionlike,
    ancillary::{ConversationId, ConversationIdRef, helpers},
    traits::{BorrowPrimaryKey, Entity, EntityDatabaseMutation, EntityDeleteBorrowed, EntityGetBorrowed, PrimaryKey},
};

/// This type exists so that we can efficiently search for the children of a given group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::From, derive_more::Into, derive_more::AsRef)]
pub struct ParentGroupId<'a>(&'a [u8]);

/// Entity representing a persisted `MlsGroup`
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct PersistedMlsGroup {
    pub id: ConversationId,
    #[sensitive]
    pub state: Vec<u8>,
    pub epoch: u64,
    pub ciphersuite: u16,
    /// Hash of the public key of the credential currently in use by our leaf node, if one
    /// can be determined. `None` if the group's leaf node has been removed, or if that
    /// credential is no longer present in `mls_credentials`.
    #[zeroize(skip)]
    pub credential_id: Sha256Hash,
    /// The type of the credential identified by `credential_id`. `mls_credentials`'s primary key
    /// is `(public_key_sha256, credential_type)`, not `public_key_sha256` alone, so this always
    /// travels alongside `credential_id`: both are `Some` or both are `None`.
    #[zeroize(skip)]
    pub credential_type: u16,
    pub own_leaf_index: u32,
    /// Distinguishes a group joined by external commit but not yet merged from an established one.
    pub is_pending: bool,
}

impl PersistedMlsGroup {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            state: row.get("state")?,
            epoch: row.get("epoch")?,
            ciphersuite: row.get("ciphersuite")?,
            credential_id: row.get("credential_id")?,
            credential_type: row.get("credential_type")?,
            own_leaf_index: row.get("own_leaf_index")?,
            is_pending: row.get("is_pending")?,
        })
    }
}

impl PrimaryKey for PersistedMlsGroup {
    type PrimaryKey = ConversationId;

    fn primary_key(&self) -> Self::PrimaryKey {
        self.id.clone()
    }
}

impl BorrowPrimaryKey for PersistedMlsGroup {
    type BorrowedPrimaryKey<'a> = &'a ConversationIdRef;

    fn borrow_primary_key(&self) -> Self::BorrowedPrimaryKey<'_> {
        self.id.as_ref()
    }
}

impl Entity for PersistedMlsGroup {
    const TABLE_NAME: &'static str = "mls_groups";

    fn get(conn: &Connection, key: &Self::PrimaryKey) -> CryptoKeystoreResult<Option<Self>> {
        helpers::get_helper(conn, "id", key, Self::from_row)
    }

    fn count(conn: &Connection) -> CryptoKeystoreResult<u32> {
        helpers::count_helper::<Self>(conn)
    }

    fn load_all(conn: &Connection) -> CryptoKeystoreResult<Vec<Self>> {
        helpers::load_all_helper(conn, Self::from_row)
    }
}

impl EntityGetBorrowed for PersistedMlsGroup {
    fn get_borrowed(conn: &Connection, key: Self::BorrowedPrimaryKey<'_>) -> CryptoKeystoreResult<Option<Self>> {
        helpers::get_helper(conn, "id", key, Self::from_row)
    }
}

impl EntityDatabaseMutation for PersistedMlsGroup {
    fn save<'a, Tx>(&self, tx: &'a Tx) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        // This must upsert via `ON CONFLICT ... DO UPDATE`, not `INSERT OR REPLACE`:
        // several tables use this table's id as a foreign key, and `INSERT OR REPLACE` is actually
        // "delete then insert", so all those foreign keys would cascade-delete before we insert a replacement.
        let mut stmt = conn.prepare_cached(
            "INSERT INTO mls_groups
                ( id,  state,  epoch,  ciphersuite,  credential_id,  credential_type,  own_leaf_index,  is_pending)
             VALUES
                (:id, :state, :epoch, :ciphersuite, :credential_id, :credential_type, :own_leaf_index, :is_pending)
             ON CONFLICT (id) DO UPDATE SET
                state = excluded.state,
                epoch = excluded.epoch,
                ciphersuite = excluded.ciphersuite,
                credential_id = excluded.credential_id,
                credential_type = excluded.credential_type,
                own_leaf_index = excluded.own_leaf_index,
                is_pending = excluded.is_pending",
        )?;
        stmt.execute(named_params![
            ":id": self.id,
            ":state": self.state,
            ":epoch": self.epoch,
            ":ciphersuite": self.ciphersuite,
            ":credential_id": self.credential_id,
            ":credential_type": self.credential_type,
            ":own_leaf_index": self.own_leaf_index,
            ":is_pending": self.is_pending,
        ])?;
        Ok(())
    }

    fn delete<'a, Tx>(tx: &'a Tx, id: &ConversationId) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        helpers::delete_helper::<Self, _>(tx, "id", id)
    }
}

impl EntityDeleteBorrowed for PersistedMlsGroup {
    fn delete_borrowed<'a, Tx>(tx: &'a Tx, id: &ConversationIdRef) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        helpers::delete_helper::<Self, _>(tx, "id", id)
    }
}
