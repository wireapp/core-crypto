mod entity;
mod primary_key;
mod waiting_for;

use const_format::formatcp;
use openmls::prelude::ContentType;
use rusqlite::{Connection, named_params};

pub use self::{
    primary_key::{InboxMessagePk, InboxMessagePkRef},
    waiting_for::WaitingFor,
};
use crate::{
    CryptoKeystoreResult, Sha256Hash, Transactionlike,
    ancillary::{ConversationId, ConversationIdRef},
};

/// An MLS message waiting in the inbox until it can be processed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxMessage {
    /// Conversation for which this message is intended.
    pub conversation_id: ConversationId,
    /// Encrypted message data.
    pub message: Vec<u8>,
    /// What kind of message this is.
    pub content_type: ContentType,
    /// What event this message is waiting for.
    pub waiting_for: WaitingFor,
    /// Epoch of this message.
    pub epoch: u64,
    /// An arbitrary monotonically increasing integer.
    ///
    /// See [`crate::Transaction::inbox_message_next_arrival_sequence`].
    pub arrival_sequence: u64,
}

impl InboxMessage {
    fn message_hash(&self) -> Sha256Hash {
        Sha256Hash::hash_from(&self.message)
    }

    /// Get the max current `arrival_sequence` value.
    ///
    /// For efficiency, callers should avoid calling this for each instantiation.
    /// Instead, they should fetch this (potentially lazily) once per transaction,
    /// incrementing the value within the transaction context as inbox messages
    /// are created.
    pub fn max_arrival_sequence(conn: &Connection) -> CryptoKeystoreResult<u64> {
        let mut stmt = conn.prepare_cached(formatcp!(
            "SELECT COALESCE(MAX(arrival_sequence), 0) FROM {table_name}",
            table_name = InboxMessage::TABLE
        ))?;
        stmt.query_one([], |row| row.get(0)).map_err(Into::into)
    }

    /// Take items out of the inbox according to the provided parameters.
    ///
    /// This removes items from the table. The intent is that cases where we don't actually
    /// want to remove items from the table produce rollbacks, restoring these without hassle.
    ///
    /// It is expected that taking messages waiting for a pending join will usually not set
    /// an epoch. This is not enforced in any way.
    ///
    /// Results are returned ordered first by `content_type`, then by `arrival_sequence`.
    pub fn take<'a, Tx>(
        tx: &'a Tx,
        conversation_id: &ConversationIdRef,
        waiting_for: WaitingFor,
        epoch: Option<u64>,
    ) -> CryptoKeystoreResult<Vec<Self>>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;

        let params = named_params! {
            ":conversation_id": conversation_id,
            ":waiting_for": waiting_for,
            ":epoch": epoch,
        };

        let mut search_stmt = conn.prepare_cached(formatcp!(
            "SELECT * FROM {table_name}
            WHERE conversation_id = :conversation_id
            AND waiting_for = :waiting_for
            AND (:epoch IS NULL OR epoch = :epoch)
            ORDER BY content_type, arrival_sequence",
            table_name = InboxMessage::TABLE,
        ))?;
        let inbox_messages = search_stmt
            .query_map(params, Self::from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        let mut delete_stmt = conn.prepare_cached(formatcp!(
            "DELETE FROM {table_name}
            WHERE conversation_id = :conversation_id
            AND waiting_for = :waiting_for
            AND (:epoch IS NULL OR epoch = :epoch)",
            table_name = InboxMessage::TABLE,
        ))?;
        delete_stmt.execute(params)?;

        Ok(inbox_messages)
    }

    /// Drop items from the inbox if they have gone stale.
    ///
    /// This removes all items from the table which have an epoch older than `new_epoch`,
    /// except for those waiting for a pending join,
    /// returning the number of items dropped.
    pub fn drop_stale<'a, Tx>(
        tx: &'a Tx,
        conversation_id: &ConversationIdRef,
        new_epoch: u64,
    ) -> CryptoKeystoreResult<usize>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;

        let mut stmt = conn.prepare_cached(formatcp!(
            "DELETE FROM {table_name}
            WHERE conversation_id = :conversation_id
            AND waiting_for <> 1 -- 1 = PendingJoin
            AND epoch < :new_epoch",
            table_name = InboxMessage::TABLE
        ))?;
        stmt.execute(named_params! {":conversation_id": conversation_id, ":new_epoch": new_epoch})
            .map_err(Into::into)
    }
}
