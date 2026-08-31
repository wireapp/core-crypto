use const_format::formatcp;

use crate::{
    CryptoKeystoreResult, Transactionlike,
    entities::{
        ConversationId, ConversationIdRef,
        helpers::{count_helper, delete_helper, get_helper, load_all_helper},
    },
    traits::{BorrowPrimaryKey, Entity, EntityDatabaseMutation, EntityDeleteBorrowed, EntityGetBorrowed, PrimaryKey},
};

#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TntMessageTxCounter {
    pub conversation_id: ConversationId,
    pub count: u32,
}

impl TntMessageTxCounter {
    const TABLE_NAME: &str = "tnt_message_tx_counters";
    const PRIMARY_KEY_COLUMN_NAME: &str = "conversation_id";

    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            conversation_id: row.get("conversation_id")?,
            count: row.get("count")?,
        })
    }
}

impl PrimaryKey for TntMessageTxCounter {
    type PrimaryKey = ConversationId;
    fn primary_key(&self) -> Self::PrimaryKey {
        self.conversation_id.clone()
    }
}

impl Entity for TntMessageTxCounter {
    const TABLE_NAME: &str = Self::TABLE_NAME;

    fn get(conn: &rusqlite::Connection, key: &ConversationId) -> CryptoKeystoreResult<Option<Self>> {
        get_helper(conn, Self::PRIMARY_KEY_COLUMN_NAME, key.bytes(), Self::from_row)
    }

    fn count(conn: &rusqlite::Connection) -> CryptoKeystoreResult<u32> {
        count_helper::<Self>(conn)
    }

    fn load_all(conn: &rusqlite::Connection) -> CryptoKeystoreResult<Vec<Self>> {
        load_all_helper(conn, Self::from_row)
    }
}

impl EntityDatabaseMutation for TntMessageTxCounter {
    fn save<'a, Tx>(&self, tx: &'a Tx) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(formatcp!(
            "INSERT OR REPLACE INTO {} (conversation_id, count) VALUES (?, ?)",
            TntMessageTxCounter::TABLE_NAME
        ))?;
        stmt.execute(rusqlite::params![self.conversation_id, self.count])?;
        Ok(())
    }

    fn delete<'a, Tx>(tx: &'a Tx, primary_key: &Self::PrimaryKey) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        delete_helper::<Self, _>(tx, Self::PRIMARY_KEY_COLUMN_NAME, primary_key.bytes())
    }
}

impl BorrowPrimaryKey for TntMessageTxCounter {
    type BorrowedPrimaryKey<'a> = &'a ConversationIdRef;

    fn borrow_primary_key(&self) -> Self::BorrowedPrimaryKey<'_> {
        self.conversation_id.as_ref()
    }
}

impl EntityGetBorrowed for TntMessageTxCounter {
    fn get_borrowed(
        conn: &rusqlite::Connection,
        key: Self::BorrowedPrimaryKey<'_>,
    ) -> CryptoKeystoreResult<Option<Self>> {
        get_helper(conn, Self::PRIMARY_KEY_COLUMN_NAME, key, Self::from_row)
    }
}

impl EntityDeleteBorrowed for TntMessageTxCounter {
    fn delete_borrowed<'a, Tx>(tx: &'a Tx, id: Self::BorrowedPrimaryKey<'_>) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        delete_helper::<Self, _>(tx, Self::PRIMARY_KEY_COLUMN_NAME, id)
    }
}
