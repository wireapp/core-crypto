use const_format::formatcp;
use zeroize::Zeroize;

use crate::{
    CryptoKeystoreResult, Transactionlike,
    entities::{
        ConversationEpochsOlderThan, ConversationId, ConversationIdRef,
        helpers::{count_helper, get_helper_composite_key, load_all_helper},
    },
    traits::{
        BorrowPrimaryKey, DeletableBySearchKey, Entity, EntityDatabaseMutation, EntityDeleteBorrowed,
        EntityGetBorrowed, PrimaryKey, SearchableEntity,
    },
};

#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct TntSecret {
    pub conversation_id: ConversationId,
    pub epoch: u64,
    #[sensitive]
    pub hpke_private_key: Vec<u8>,
    pub group_context: Vec<u8>,
    #[sensitive]
    pub targeted_message_psk: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, derive_more::Constructor)]
pub struct TntSecretPk {
    conversation_id: ConversationId,
    epoch: u64,
}

impl TntSecret {
    const TABLE_NAME: &str = "tnt_secrets";
    const PRIMARY_KEY_COLUMN_NAMES: [&str; 2] = ["conversation_id", "epoch"];

    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            conversation_id: row.get("conversation_id")?,
            epoch: row.get("epoch")?,
            hpke_private_key: row.get("hpke_private_key")?,
            group_context: row.get("group_context")?,
            targeted_message_psk: row.get("targeted_message_psk")?,
        })
    }
}

impl PrimaryKey for TntSecret {
    type PrimaryKey = TntSecretPk;

    fn primary_key(&self) -> Self::PrimaryKey {
        TntSecretPk::new(self.conversation_id.clone(), self.epoch)
    }
}

impl Entity for TntSecret {
    const TABLE_NAME: &str = Self::TABLE_NAME;

    fn get(conn: &rusqlite::Connection, key: &TntSecretPk) -> CryptoKeystoreResult<Option<Self>> {
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

impl EntityDatabaseMutation for TntSecret {
    fn save<'a, Tx>(&self, tx: &'a Tx) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(formatcp!(
            "INSERT OR REPLACE INTO {}
                (conversation_id, epoch, hpke_private_key, group_context, targeted_message_psk)
             VALUES (:conversation_id, :epoch, :hpke_private_key, :group_context, :targeted_message_psk)",
            TntSecret::TABLE_NAME
        ))?;
        stmt.execute(rusqlite::named_params! {
            ":conversation_id": self.conversation_id,
            ":epoch": self.epoch,
            ":hpke_private_key": self.hpke_private_key,
            ":group_context": self.group_context,
            ":targeted_message_psk": self.targeted_message_psk,
        })?;
        Ok(())
    }

    fn delete<'a, Tx>(tx: &'a Tx, key: &TntSecretPk) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(formatcp!(
            "DELETE FROM {} WHERE conversation_id = ? AND epoch = ?",
            TntSecret::TABLE_NAME
        ))?;
        stmt.execute(rusqlite::params![key.conversation_id, key.epoch])
            .map(|affected_rows| affected_rows > 0)
            .map_err(Into::into)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, derive_more::Constructor)]
pub struct TntSecretPkRef<'a> {
    conversation_id: &'a ConversationIdRef,
    epoch: u64,
}

impl BorrowPrimaryKey for TntSecret {
    type BorrowedPrimaryKey<'a> = TntSecretPkRef<'a>;

    fn borrow_primary_key(&self) -> Self::BorrowedPrimaryKey<'_> {
        TntSecretPkRef::new(self.conversation_id.as_ref(), self.epoch)
    }
}

impl EntityGetBorrowed for TntSecret {
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

impl EntityDeleteBorrowed for TntSecret {
    fn delete_borrowed<'a, Tx>(tx: &'a Tx, key: Self::BorrowedPrimaryKey<'_>) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(formatcp!(
            "DELETE FROM {} WHERE conversation_id = ? AND epoch = ?",
            TntSecret::TABLE_NAME
        ))?;
        stmt.execute(rusqlite::params![key.conversation_id, key.epoch])
            .map(|affected_rows| affected_rows > 0)
            .map_err(Into::into)
    }
}

impl SearchableEntity<ConversationEpochsOlderThan> for TntSecret {
    fn find_all_matching(
        conn: &rusqlite::Connection,
        conversation_epoch: &ConversationEpochsOlderThan,
    ) -> CryptoKeystoreResult<Vec<Self>> {
        let mut stmt = conn.prepare_cached(formatcp!(
            "SELECT * FROM {} WHERE conversation_id = ? AND epoch < ?",
            TntSecret::TABLE_NAME
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

impl DeletableBySearchKey<ConversationEpochsOlderThan> for TntSecret {
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
            TntSecret::TABLE_NAME
        ))?;
        stmt.execute(rusqlite::params![
            conversation_epoch.conversation_id,
            conversation_epoch.epoch
        ])?;
        Ok(())
    }
}

impl From<TntSecretPkRef<'_>> for TntSecretPk {
    fn from(key: TntSecretPkRef<'_>) -> Self {
        Self::new(key.conversation_id.into(), key.epoch)
    }
}
