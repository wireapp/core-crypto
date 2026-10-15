use const_format::formatcp;
use zeroize::Zeroize;

use crate::{
    CryptoKeystoreResult, Transactionlike,
    ancillary::{
        ConversationEpochsNewerThan, ConversationEpochsOlderThan, ConversationId, ConversationIdRef,
        helpers::{count_helper, get_helper_composite_key, load_all_helper},
    },
    traits::{
        BorrowPrimaryKey, DeletableBySearchKey, Entity, EntityDatabaseMutation, EntityDeleteBorrowed,
        EntityGetBorrowed, PrimaryKey, SearchableEntity,
    },
};

#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct OldEpochData {
    pub conversation_id: ConversationId,
    pub epoch: u64,
    pub own_leaf_index: u32,
    #[sensitive]
    pub hpke_private_key: Vec<u8>,
    pub group_context: Vec<u8>,
    #[sensitive]
    pub targeted_message_psk: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, derive_more::Constructor)]
pub struct OldEpochDataPk {
    conversation_id: ConversationId,
    epoch: u64,
}

impl OldEpochData {
    const TABLE_NAME: &str = "old_epoch_data";
    const PRIMARY_KEY_COLUMN_NAMES: [&str; 2] = ["conversation_id", "epoch"];

    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            conversation_id: row.get("conversation_id")?,
            epoch: row.get("epoch")?,
            own_leaf_index: row.get("own_leaf_index")?,
            hpke_private_key: row.get("hpke_private_key")?,
            group_context: row.get("group_context")?,
            targeted_message_psk: row.get("targeted_message_psk")?,
        })
    }
}

impl PrimaryKey for OldEpochData {
    type PrimaryKey = OldEpochDataPk;

    fn primary_key(&self) -> Self::PrimaryKey {
        OldEpochDataPk::new(self.conversation_id.clone(), self.epoch)
    }
}

impl Entity for OldEpochData {
    const TABLE_NAME: &str = Self::TABLE_NAME;

    fn get(conn: &rusqlite::Connection, key: &OldEpochDataPk) -> CryptoKeystoreResult<Option<Self>> {
        get_helper_composite_key(
            conn,
            &Self::PRIMARY_KEY_COLUMN_NAMES,
            rusqlite::params![key.conversation_id, key.epoch],
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

impl EntityDatabaseMutation for OldEpochData {
    fn save<'a, Tx>(&self, tx: &'a Tx) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(formatcp!(
            "INSERT INTO {}
                    ( conversation_id,  epoch,  hpke_private_key,  group_context,  targeted_message_psk,  own_leaf_index)
             VALUES (:conversation_id, :epoch, :hpke_private_key, :group_context, :targeted_message_psk, :own_leaf_index)",
            OldEpochData::TABLE_NAME
        ))?;
        stmt.execute(rusqlite::named_params! {
            ":conversation_id": self.conversation_id,
            ":epoch": self.epoch,
            ":hpke_private_key": self.hpke_private_key,
            ":group_context": self.group_context,
            ":targeted_message_psk": self.targeted_message_psk,
            ":own_leaf_index": self.own_leaf_index,
        })?;
        Ok(())
    }

    fn delete<'a, Tx>(tx: &'a Tx, key: &OldEpochDataPk) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(formatcp!(
            "DELETE FROM {} WHERE conversation_id = ? AND epoch = ?",
            OldEpochData::TABLE_NAME
        ))?;
        stmt.execute(rusqlite::params![key.conversation_id, key.epoch])
            .map(|affected_rows| affected_rows > 0)
            .map_err(Into::into)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, derive_more::Constructor)]
pub struct OldEpochDataPkRef<'a> {
    conversation_id: &'a ConversationIdRef,
    epoch: u64,
}

impl BorrowPrimaryKey for OldEpochData {
    type BorrowedPrimaryKey<'a> = OldEpochDataPkRef<'a>;

    fn borrow_primary_key(&self) -> Self::BorrowedPrimaryKey<'_> {
        OldEpochDataPkRef::new(self.conversation_id.as_ref(), self.epoch)
    }
}

impl EntityGetBorrowed for OldEpochData {
    fn get_borrowed(
        conn: &rusqlite::Connection,
        key: Self::BorrowedPrimaryKey<'_>,
    ) -> CryptoKeystoreResult<Option<Self>> {
        get_helper_composite_key(
            conn,
            &Self::PRIMARY_KEY_COLUMN_NAMES,
            rusqlite::params![key.conversation_id, key.epoch],
            Self::from_row,
        )
    }
}

impl EntityDeleteBorrowed for OldEpochData {
    fn delete_borrowed<'a, Tx>(tx: &'a Tx, key: Self::BorrowedPrimaryKey<'_>) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(formatcp!(
            "DELETE FROM {} WHERE conversation_id = ? AND epoch = ?",
            OldEpochData::TABLE_NAME
        ))?;
        stmt.execute(rusqlite::params![key.conversation_id, key.epoch])
            .map(|affected_rows| affected_rows > 0)
            .map_err(Into::into)
    }
}

impl SearchableEntity<ConversationEpochsOlderThan<'_>> for OldEpochData {
    fn find_all_matching(
        conn: &rusqlite::Connection,
        conversation_epoch: &ConversationEpochsOlderThan,
    ) -> CryptoKeystoreResult<Vec<Self>> {
        let mut stmt = conn.prepare_cached(formatcp!(
            "SELECT * FROM {} WHERE conversation_id = ? AND epoch < ?",
            OldEpochData::TABLE_NAME
        ))?;
        stmt.query_map(
            rusqlite::params![conversation_epoch.conversation_id, conversation_epoch.epoch],
            Self::from_row,
        )?
        .collect::<Result<_, _>>()
        .map_err(Into::into)
    }

    fn matches(&self, conversation_epoch: &ConversationEpochsOlderThan) -> bool {
        &self.conversation_id == conversation_epoch.conversation_id && self.epoch < conversation_epoch.epoch
    }
}

impl DeletableBySearchKey<ConversationEpochsOlderThan<'_>> for OldEpochData {
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
            OldEpochData::TABLE_NAME
        ))?;
        stmt.execute(rusqlite::params![
            conversation_epoch.conversation_id,
            conversation_epoch.epoch
        ])?;
        Ok(())
    }
}

impl From<OldEpochDataPkRef<'_>> for OldEpochDataPk {
    fn from(key: OldEpochDataPkRef<'_>) -> Self {
        Self::new(key.conversation_id.into(), key.epoch)
    }
}

impl SearchableEntity<ConversationEpochsNewerThan<'_>> for OldEpochData {
    fn find_all_matching(
        conn: &rusqlite::Connection,
        conversation_epoch: &ConversationEpochsNewerThan<'_>,
    ) -> CryptoKeystoreResult<Vec<Self>> {
        let mut stmt = conn.prepare_cached(formatcp!(
            "SELECT * FROM {} WHERE conversation_id = ? AND epoch >= ?",
            OldEpochData::TABLE_NAME
        ))?;
        stmt.query_map(
            rusqlite::params![conversation_epoch.conversation_id, conversation_epoch.epoch],
            Self::from_row,
        )?
        .collect::<Result<_, _>>()
        .map_err(Into::into)
    }

    fn matches(&self, conversation_epoch: &ConversationEpochsNewerThan<'_>) -> bool {
        &self.conversation_id == conversation_epoch.conversation_id && self.epoch >= conversation_epoch.epoch
    }
}

impl DeletableBySearchKey<ConversationEpochsNewerThan<'_>> for OldEpochData {
    fn delete_all_matching<'a, Tx>(
        tx: &'a Tx,
        conversation_epoch: &ConversationEpochsNewerThan<'_>,
    ) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(formatcp!(
            "DELETE FROM {} WHERE conversation_id = ? AND epoch >= ?",
            OldEpochData::TABLE_NAME
        ))?;
        stmt.execute(rusqlite::params![
            conversation_epoch.conversation_id,
            conversation_epoch.epoch
        ])?;
        Ok(())
    }
}
