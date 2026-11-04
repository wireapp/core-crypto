use zeroize::Zeroize;

use crate::{
    Sha256Hash, Transactionlike,
    ancillary::{
        ConversationId, ConversationIdRef,
        helpers::{count_helper, delete_helper, get_helper, load_all_helper},
    },
    traits::{DeletableBySearchKey, Entity, EntityDatabaseMutation, PrimaryKey, SearchableEntity},
};

/// Entity representing a buffered message
///
/// A message is buffered when it cannot be decrypted yet, which happens in two unrelated situations: the
/// conversation was joined by external commit and that join has not been merged, or the conversation is
/// fully established but the message belongs to epoch `n + 1` while we are still in epoch `n`. Both kinds
/// of conversation are rows in `mls_groups`.
///
/// This entity cannot be updated in the DB: the primary key is formed of a hash of all the rest
/// of the data, so duplicate save attempts silently succeed without changing anything.
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct MlsPendingMessage {
    pub conversation_id: ConversationId,
    #[sensitive]
    pub message: Vec<u8>,
}

impl MlsPendingMessage {
    const PRIMARY_KEY_COLUMN_NAME: &str = "hash_sha256";

    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            conversation_id: row.get("conversation_id")?,
            message: row.get("message")?,
        })
    }
}

impl PrimaryKey for MlsPendingMessage {
    type PrimaryKey = Sha256Hash;
    fn primary_key(&self) -> Self::PrimaryKey {
        // Hashing the fields in sequence is equivalent to hashing their concatenation, so without a
        // delimiter the boundary between them is ambiguous: `("ab", "c")` and `("a", "bc")` would
        // share a primary key. A big-endian `u64` length prefix on the conversation id fixes the
        // boundary. The message needs no prefix, as nothing follows it.
        let conversation_id_len = (self.conversation_id.len() as u64).to_be_bytes();
        Sha256Hash::hash_from_many([conversation_id_len.as_slice(), &self.conversation_id, &self.message])
    }
}

impl Entity for MlsPendingMessage {
    const TABLE_NAME: &'static str = "mls_pending_messages";

    fn get(conn: &rusqlite::Connection, key: &Sha256Hash) -> crate::CryptoKeystoreResult<Option<Self>> {
        get_helper(conn, Self::PRIMARY_KEY_COLUMN_NAME, key, Self::from_row)
    }

    fn count(conn: &rusqlite::Connection) -> crate::CryptoKeystoreResult<u32> {
        count_helper::<Self>(conn)
    }

    fn load_all(conn: &rusqlite::Connection) -> crate::CryptoKeystoreResult<Vec<Self>> {
        load_all_helper(conn, |row| {
            Ok(Self {
                conversation_id: row.get("conversation_id")?,
                message: row.get("message")?,
            })
        })
    }
}

impl EntityDatabaseMutation for MlsPendingMessage {
    fn save<'a, Tx>(&self, tx: &'a Tx) -> crate::CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        // The primary key is a hash of the other two columns, so a conflict means this exact row
        // already exists and there is nothing to write. `IGNORE` rather than `REPLACE` because
        // replacing would delete and reinsert an identical row to no purpose.
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(
            "INSERT OR IGNORE INTO mls_pending_messages (hash_sha256, conversation_id, message) VALUES (?, ?, ?)",
        )?;
        stmt.execute(rusqlite::params![
            self.primary_key(),
            self.conversation_id,
            self.message
        ])?;
        Ok(())
    }

    fn delete<'a, Tx>(tx: &'a Tx, primary_key: &Sha256Hash) -> crate::CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        delete_helper::<Self, _>(tx, Self::PRIMARY_KEY_COLUMN_NAME, primary_key)
    }
}

// We can search this entity by both an owned conversation ID and a reference.
// We _don't_ impl this for `Vec<u8>` for future-proofing: we might in the future
// add a new bytes field to the entity, which would make that kind of search ambiguous.

impl SearchableEntity<ConversationIdRef> for MlsPendingMessage {
    fn find_all_matching(
        conn: &rusqlite::Connection,
        conversation_id: &ConversationIdRef,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let mut stmt = conn.prepare_cached("SELECT * FROM mls_pending_messages WHERE conversation_id = ?")?;
        stmt.query_map([conversation_id], Self::from_row)?
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }

    fn matches(&self, conversation_id: &ConversationIdRef) -> bool {
        conversation_id.bytes() == self.conversation_id.bytes()
    }
}

impl SearchableEntity<ConversationId> for MlsPendingMessage {
    fn find_all_matching(
        conn: &rusqlite::Connection,
        conversation_id: &ConversationId,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        Self::find_all_matching(conn, conversation_id.as_ref())
    }

    fn matches(&self, conversation_id: &ConversationId) -> bool {
        conversation_id.bytes() == self.conversation_id.bytes()
    }
}

impl DeletableBySearchKey<ConversationId> for MlsPendingMessage {
    fn delete_all_matching<'a, Tx>(tx: &'a Tx, conversation_id: &ConversationId) -> crate::CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        delete_helper::<Self, _>(tx, "conversation_id", conversation_id)?;
        Ok(())
    }
}

impl DeletableBySearchKey<ConversationIdRef> for MlsPendingMessage {
    fn delete_all_matching<'a, Tx>(tx: &'a Tx, conversation_id: &ConversationIdRef) -> crate::CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        delete_helper::<Self, _>(tx, "conversation_id", conversation_id)?;
        Ok(())
    }
}
