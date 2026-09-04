use const_format::formatcp;

use crate::{
    CryptoKeystoreResult, Transactionlike,
    ancillary::{
        ConversationEpochsOlderThan, ConversationId, MessageRxCounterPk, MessageRxCounterPkRef,
        helpers::{count_helper, get_helper_composite_key, load_all_helper},
    },
    traits::{
        BorrowPrimaryKey, DeletableBySearchKey, Entity, EntityDatabaseMutation, EntityDeleteBorrowed,
        EntityGetBorrowed, PrimaryKey, SearchableEntity,
    },
};

#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransientMessageRxCounter {
    pub conversation_id: ConversationId,
    pub sender: u32,
    pub epoch: u64,
    pub count: u32,
}

impl TransientMessageRxCounter {
    const TABLE_NAME: &str = "transient_message_rx_counters";
    const PRIMARY_KEY_COLUMN_NAMES: [&str; 3] = ["conversation_id", "sender", "epoch"];

    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            conversation_id: row.get("conversation_id")?,
            sender: row.get("sender")?,
            epoch: row.get("epoch")?,
            count: row.get("count")?,
        })
    }
}

impl PrimaryKey for TransientMessageRxCounter {
    type PrimaryKey = MessageRxCounterPk;

    fn primary_key(&self) -> Self::PrimaryKey {
        MessageRxCounterPk::new(self.conversation_id.clone(), self.sender, self.epoch)
    }
}

impl Entity for TransientMessageRxCounter {
    const TABLE_NAME: &str = Self::TABLE_NAME;

    fn get(conn: &rusqlite::Connection, key: &MessageRxCounterPk) -> CryptoKeystoreResult<Option<Self>> {
        get_helper_composite_key(
            conn,
            &Self::PRIMARY_KEY_COLUMN_NAMES,
            rusqlite::params![key.conversation_id, key.sender_idx, key.epoch],
            Self::from_row,
        )
    }

    fn count(conn: &rusqlite::Connection) -> CryptoKeystoreResult<u32> {
        count_helper::<Self>(conn)
    }

    fn load_all(conn: &rusqlite::Connection) -> CryptoKeystoreResult<Vec<Self>> {
        load_all_helper(conn, Self::from_row)
    }
}

impl EntityDatabaseMutation for TransientMessageRxCounter {
    fn save<'a, Tx>(&self, tx: &'a Tx) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(formatcp!(
            "INSERT OR REPLACE INTO {} (conversation_id, sender, epoch, count) \
             VALUES (:conversation_id, :sender, :epoch, :count)",
            TransientMessageRxCounter::TABLE_NAME
        ))?;
        stmt.execute(rusqlite::named_params! {
            ":conversation_id": self.conversation_id,
            ":sender": self.sender,
            ":epoch": self.epoch,
            ":count": self.count,
        })?;
        Ok(())
    }

    fn delete<'a, Tx>(tx: &'a Tx, primary_key: &MessageRxCounterPk) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(formatcp!(
            "DELETE FROM {} WHERE conversation_id = ? AND sender = ? AND epoch = ?",
            TransientMessageRxCounter::TABLE_NAME
        ))?;
        stmt.execute(rusqlite::params![
            primary_key.conversation_id,
            primary_key.sender_idx,
            primary_key.epoch
        ])
        .map(|affected_rows| affected_rows > 0)
        .map_err(Into::into)
    }
}

impl BorrowPrimaryKey for TransientMessageRxCounter {
    type BorrowedPrimaryKey<'a> = MessageRxCounterPkRef<'a>;

    fn borrow_primary_key(&self) -> Self::BorrowedPrimaryKey<'_> {
        MessageRxCounterPkRef::new(self.conversation_id.as_ref(), self.sender, self.epoch)
    }
}

impl EntityGetBorrowed for TransientMessageRxCounter {
    fn get_borrowed(
        conn: &rusqlite::Connection,
        key: Self::BorrowedPrimaryKey<'_>,
    ) -> CryptoKeystoreResult<Option<Self>> {
        get_helper_composite_key(
            conn,
            &Self::PRIMARY_KEY_COLUMN_NAMES,
            rusqlite::params![key.conversation_id, key.sender_idx, key.epoch],
            Self::from_row,
        )
    }
}

impl EntityDeleteBorrowed for TransientMessageRxCounter {
    fn delete_borrowed<'a, Tx>(tx: &'a Tx, key: Self::BorrowedPrimaryKey<'_>) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(formatcp!(
            "DELETE FROM {} WHERE conversation_id = ? AND sender = ? AND epoch = ?",
            TransientMessageRxCounter::TABLE_NAME
        ))?;
        stmt.execute(rusqlite::params![key.conversation_id, key.sender_idx, key.epoch])
            .map(|affected_rows| affected_rows > 0)
            .map_err(Into::into)
    }
}

impl SearchableEntity<ConversationEpochsOlderThan> for TransientMessageRxCounter {
    fn find_all_matching(
        conn: &rusqlite::Connection,
        conversation_epoch: &ConversationEpochsOlderThan,
    ) -> CryptoKeystoreResult<Vec<Self>> {
        let mut stmt = conn.prepare_cached(formatcp!(
            "SELECT * FROM {} WHERE conversation_id = ? AND epoch < ?",
            TransientMessageRxCounter::TABLE_NAME
        ))?;
        stmt.query_map(
            rusqlite::params![conversation_epoch.conversation_id, conversation_epoch.epoch],
            Self::from_row,
        )?
        .collect::<Result<_, _>>()
        .map_err(Into::into)
    }

    fn matches(&self, conversation_epoch: &ConversationEpochsOlderThan) -> bool {
        self.conversation_id == conversation_epoch.conversation_id && self.epoch < conversation_epoch.epoch
    }
}

impl DeletableBySearchKey<ConversationEpochsOlderThan> for TransientMessageRxCounter {
    fn delete_all_matching<'a, Tx>(
        tx: &'a Tx,
        conversation_epoch: &ConversationEpochsOlderThan,
    ) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(formatcp!(
            "DELETE FROM {} WHERE conversation_id = ? AND epoch < ?",
            TransientMessageRxCounter::TABLE_NAME
        ))?;
        stmt.execute(rusqlite::params![
            conversation_epoch.conversation_id,
            conversation_epoch.epoch
        ])?;
        Ok(())
    }
}
