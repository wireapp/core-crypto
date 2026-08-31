use rusqlite::Connection;
use zeroize::Zeroize;

use crate::{
    Transactionlike,
    traits::{BorrowPrimaryKey, PrimaryKey},
};

/// Entity representing a temporarily persisted `MlsGroup`
///
/// This entity keeps its upsert semantics deliberately. Nothing updates one in place — there is a
/// single writer, and the row is deleted once the external join it represents is merged or
/// abandoned — so it reads like a candidate for a plain `INSERT`. It is not. `join_by_external_commit`
/// invites the caller to retry, and whether the abandoned row is still there on the retry depends on
/// what the caller did with the previous failure: an error crossing the FFI becomes an exception
/// which by default cancels the transaction, discarding the row, but a caller may catch it and carry
/// on with the same transaction, in which case the row survives. Both are legitimate, so the second
/// save has to be allowed to replace the first.
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct PersistedMlsPendingGroup {
    #[sensitive]
    pub id: Vec<u8>,
    #[sensitive]
    pub state: Vec<u8>,
    #[sensitive]
    pub parent_id: Option<Vec<u8>>,
    pub custom_configuration: Vec<u8>,
}

impl PrimaryKey for PersistedMlsPendingGroup {
    type PrimaryKey = Vec<u8>;

    fn primary_key(&self) -> Self::PrimaryKey {
        self.id.clone()
    }
}

impl BorrowPrimaryKey for PersistedMlsPendingGroup {
    type BorrowedPrimaryKey<'a> = &'a [u8];

    fn borrow_primary_key(&self) -> Self::BorrowedPrimaryKey<'_> {
        &self.id
    }
}

impl crate::traits::Entity for PersistedMlsPendingGroup {
    const TABLE_NAME: &'static str = "mls_pending_groups";

    fn get(conn: &Connection, key: &Vec<u8>) -> crate::CryptoKeystoreResult<Option<Self>> {
        crate::entities::helpers::get_helper(conn, "id", key.as_slice(), |row| {
            Ok(Self {
                id: row.get("id")?,
                state: row.get("state")?,
                parent_id: row.get("parent_id")?,
                custom_configuration: row.get("cfg")?,
            })
        })
    }

    fn count(conn: &Connection) -> crate::CryptoKeystoreResult<u32> {
        crate::entities::helpers::count_helper::<Self>(conn)
    }

    fn load_all(conn: &Connection) -> crate::CryptoKeystoreResult<Vec<Self>> {
        crate::entities::helpers::load_all_helper(conn, |row| {
            Ok(Self {
                id: row.get("id")?,
                state: row.get("state")?,
                parent_id: row.get("parent_id")?,
                custom_configuration: row.get("cfg")?,
            })
        })
    }
}

impl crate::traits::EntityGetBorrowed for PersistedMlsPendingGroup {
    fn get_borrowed(conn: &Connection, key: &[u8]) -> crate::CryptoKeystoreResult<Option<Self>> {
        crate::entities::helpers::get_helper(conn, "id", key, |row| {
            Ok(Self {
                id: row.get("id")?,
                state: row.get("state")?,
                parent_id: row.get("parent_id")?,
                custom_configuration: row.get("cfg")?,
            })
        })
    }
}

impl crate::traits::EntityDatabaseMutation for PersistedMlsPendingGroup {
    fn save<'a, Tx>(&self, tx: &'a Tx) -> crate::CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO mls_pending_groups (id, state, parent_id, cfg) VALUES (?, ?, ?, ?)",
        )?;
        stmt.execute(rusqlite::params![
            self.id,
            self.state,
            self.parent_id,
            self.custom_configuration
        ])?;
        Ok(())
    }

    fn delete<'a, Tx>(tx: &'a Tx, id: &Vec<u8>) -> crate::CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        crate::entities::helpers::delete_helper::<Self, _>(tx, "id", id.as_slice())
    }
}

impl crate::traits::EntityDeleteBorrowed for PersistedMlsPendingGroup {
    fn delete_borrowed<'a, Tx>(tx: &'a Tx, id: &[u8]) -> crate::CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        crate::entities::helpers::delete_helper::<Self, _>(tx, "id", id)
    }
}
