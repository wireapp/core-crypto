use const_format::formatcp;
use openmls::prelude::ContentType;
use rusqlite::{Connection, Row, named_params, params, types::Type};

use crate::{
    CryptoKeystoreResult, Transactionlike,
    ancillary::{ConversationIdRef, helpers},
    entities::{InboxMessage, InboxMessagePk, InboxMessagePkRef},
    traits::{
        BorrowPrimaryKey, DeletableBySearchKey, Entity, EntityDatabaseMutation, EntityDeleteBorrowed,
        EntityGetBorrowed, PrimaryKey, SearchableEntity,
    },
};

impl InboxMessage {
    /// SQL table in which this is stored
    pub(super) const TABLE: &str = "mls_inbox";

    /// Column names of the primary key
    const PRIMARY_KEY_COLUMN_NAMES: &[&str] = &["conversation_id", "message_hash"];

    pub(super) fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        let msg = Self {
            arrival_sequence: row.get("arrival_sequence")?,
            conversation_id: row.get("conversation_id")?,
            message: row.get("message")?,
            waiting_for: row.get("waiting_for")?,
            epoch: row.get("epoch")?,
            content_type: row.get::<_, u8>("content_type")?.try_into().map_err(
                // tls_codec::Error, except that's not in scope here
                |err: <ContentType as TryFrom<u8>>::Error| {
                    let idx = match row.as_ref().column_index("content_type") {
                        Ok(idx) => idx,
                        // in the error case, propagate the failure to get the index
                        Err(err) => return err,
                    };
                    rusqlite::Error::FromSqlConversionFailure(idx, Type::Integer, Box::new(err))
                },
            )?,
        };
        Ok(msg)
    }
}

impl PrimaryKey for InboxMessage {
    type PrimaryKey = InboxMessagePk;

    fn primary_key(&self) -> Self::PrimaryKey {
        self.borrow_primary_key().into()
    }
}

impl BorrowPrimaryKey for InboxMessage {
    type BorrowedPrimaryKey<'a>
        = InboxMessagePkRef<'a>
    where
        Self: 'a;

    fn borrow_primary_key(&self) -> Self::BorrowedPrimaryKey<'_> {
        InboxMessagePkRef {
            conversation_id_ref: self.conversation_id.as_ref(),
            message_hash: self.message_hash(),
        }
    }
}

impl Entity for InboxMessage {
    const TABLE_NAME: &str = Self::TABLE;

    fn get(conn: &Connection, key: &Self::PrimaryKey) -> CryptoKeystoreResult<Option<Self>> {
        Self::get_borrowed(conn, key.borrow())
    }

    fn count(conn: &Connection) -> CryptoKeystoreResult<u32> {
        helpers::count_helper::<Self>(conn)
    }

    fn load_all(conn: &Connection) -> CryptoKeystoreResult<Vec<Self>> {
        helpers::load_all_helper(conn, Self::from_row)
    }
}

impl EntityGetBorrowed for InboxMessage {
    fn get_borrowed(conn: &Connection, key: Self::BorrowedPrimaryKey<'_>) -> CryptoKeystoreResult<Option<Self>> {
        helpers::get_helper_composite_key(
            conn,
            Self::PRIMARY_KEY_COLUMN_NAMES,
            params![key.conversation_id_ref, key.message_hash],
            Self::from_row,
        )
    }
}

impl EntityDatabaseMutation for InboxMessage {
    /// Duplicate save is a silent noop. Other conflicts return errors.
    fn save<'a, Tx>(&self, tx: &'a Tx) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(formatcp!(
            "INSERT INTO {table_name} (
                conversation_id,
                message,
                message_hash,
                content_type,
                waiting_for,
                epoch,
                arrival_sequence
            ) VALUES (
                :conversation_id,
                :message,
                :message_hash,
                :content_type,
                :waiting_for,
                :epoch,
                :arrival_sequence
            )
            ON CONFLICT (conversation_id, message_hash) DO NOTHING",
            table_name = InboxMessage::TABLE,
        ))?;
        stmt.execute(named_params! {
            ":conversation_id": self.conversation_id,
            ":message": self.message,
            ":message_hash": self.message_hash(),
            ":content_type": self.content_type as u8,
            ":waiting_for": self.waiting_for,
            ":epoch": self.epoch,
            ":arrival_sequence": self.arrival_sequence,
        })?;
        Ok(())
    }

    fn delete<'a, Tx>(tx: &'a Tx, id: &Self::PrimaryKey) -> CryptoKeystoreResult<bool>
    where
        Transactionlike<'a>: From<&'a Tx>,
    {
        Self::delete_borrowed(tx, id.borrow())
    }
}

impl EntityDeleteBorrowed for InboxMessage {
    fn delete_borrowed<'a, Tx>(tx: &'a Tx, id: Self::BorrowedPrimaryKey<'_>) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        helpers::delete_helper_composite_key::<Self, _>(
            tx,
            Self::PRIMARY_KEY_COLUMN_NAMES,
            params![id.conversation_id_ref, id.message_hash],
        )
        .map(|count| count > 0)
    }
}

impl SearchableEntity<ConversationIdRef> for InboxMessage {
    fn find_all_matching(conn: &Connection, search_key: &ConversationIdRef) -> CryptoKeystoreResult<Vec<Self>> {
        let mut stmt = conn.prepare_cached(formatcp!(
            "SELECT * FROM {table_name} WHERE conversation_id = ? ORDER BY content_type, arrival_sequence",
            table_name = InboxMessage::TABLE,
        ))?;
        stmt.query_map([search_key], Self::from_row)?
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }

    fn matches(&self, search_key: &ConversationIdRef) -> bool {
        self.conversation_id.as_ref() == search_key
    }
}

impl DeletableBySearchKey<ConversationIdRef> for InboxMessage {
    fn delete_all_matching<'a, Tx>(tx: &'a Tx, search_key: &ConversationIdRef) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(formatcp!(
            "DELETE FROM {table_name} WHERE conversation_id = ?",
            table_name = InboxMessage::TABLE,
        ))?;
        stmt.execute([search_key])?;
        Ok(())
    }
}
