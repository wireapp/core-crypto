use std::borrow::Borrow;

use async_trait::async_trait;
use rusqlite::{Row, params};

use crate::{
    CryptoKeystoreResult, MissingKeyErrorKind,
    connection::{DatabaseConnection, KeystoreDatabaseConnection, TransactionWrapper},
    entities::{
        Entity, EntityBase, EntityFindParams, EntityTransactionExt, MlsPendingMessage, StringEntityId, count_helper,
        count_helper_tx, delete_helper, get_helper, load_all_helper,
    },
    traits::{
        BorrowPrimaryKey, Entity as NewEntity, EntityBase as NewEntityBase, EntityDatabaseMutation,
        EntityDeleteBorrowed, EntityGetBorrowed, KeyType, PrimaryKey,
    },
};

impl MlsPendingMessage {
    pub async fn find_all_by_conversation_id(
        conn: &mut <Self as EntityBase>::ConnectionType,
        conversation_id: &[u8],
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let mut conn = conn.conn().await;
        let transaction = conn.transaction()?;
        let query: String = format!(
            "SELECT rowid FROM mls_pending_messages WHERE id = ? {}",
            params.to_sql()
        );

        let mut stmt = transaction.prepare_cached(&query)?;
        let rows = stmt.query_map([conversation_id], |r| r.get(0))?;
        rows.map(|rowid_result| {
            let rowid = rowid_result?;
            use std::io::Read as _;

            let mut blob = transaction.blob_open(rusqlite::MAIN_DB, "mls_pending_messages", "id", rowid, true)?;
            let mut conversation_id = vec![];
            blob.read_to_end(&mut conversation_id)?;
            blob.close()?;

            let mut blob = transaction.blob_open(rusqlite::MAIN_DB, "mls_pending_messages", "message", rowid, true)?;
            let mut message = vec![];
            blob.read_to_end(&mut message)?;
            blob.close()?;

            Ok(Self {
                foreign_id: conversation_id,
                message,
            })
        })
        .collect()
    }

    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        let foreign_id = row.get("id")?;
        let message = row.get("message")?;
        Ok(Self { foreign_id, message })
    }

    // TODO WPB-22196 delete the old method and replace it with this
    /// Pending replacement for [`Self::find_all_by_conversation_id`].
    pub async fn new_find_all_by_conversation_id(
        conn: &mut <Self as NewEntityBase>::ConnectionType,
        conversation_id: &[u8],
    ) -> CryptoKeystoreResult<Vec<Self>> {
        let conn = conn.conn().await;
        let mut stmt = conn.prepare_cached("SELECT * FROM mls_pending_messages WHERE id = ?")?;
        let values = stmt
            .query_map([conversation_id], Self::from_row)?
            .collect::<Result<_, _>>()?;
        Ok(values)
    }

    pub async fn delete_by_conversation_id(
        tx: &TransactionWrapper<'_>,
        conversation_id: &[u8],
    ) -> CryptoKeystoreResult<bool> {
        // a slight misuse of this helper, but SQL doesn't care if we end up deleting N rows instead of 1
        // with this query
        delete_helper::<Self>(tx, "id", conversation_id).await
    }
}

#[async_trait::async_trait]
impl Entity for MlsPendingMessage {
    fn id_raw(&self) -> &[u8] {
        self.foreign_id.as_slice()
    }

    fn merge_key(&self) -> Vec<u8> {
        // Use this as a merge key because the `id` is not used as a primary key
        // but  as a foreign key: it's the ID of the PersistedMlsPendingGroup.
        self.message.clone()
    }

    async fn find_one(_: &mut Self::ConnectionType, _: &StringEntityId) -> crate::CryptoKeystoreResult<Option<Self>> {
        panic!("Must not be called. The intended usage is to call MlsPendingMessage::find_all_by_conversation_id().")
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let mut conn = conn.conn().await;
        let transaction = conn.transaction()?;
        let query: String = format!("SELECT rowid FROM mls_pending_messages {}", params.to_sql());

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| r.get(0))?;
        let entities = rows.try_fold(Vec::new(), |mut acc, rowid_result| {
            use std::io::Read as _;
            let rowid = rowid_result?;

            let mut blob = transaction.blob_open(rusqlite::MAIN_DB, "mls_pending_messages", "id", rowid, true)?;
            let mut id = vec![];
            blob.read_to_end(&mut id)?;
            blob.close()?;

            let mut blob = transaction.blob_open(rusqlite::MAIN_DB, "mls_pending_messages", "message", rowid, true)?;
            let mut message = vec![];
            blob.read_to_end(&mut message)?;
            blob.close()?;

            acc.push(Self {
                foreign_id: id,
                message,
            });
            crate::CryptoKeystoreResult::Ok(acc)
        })?;

        Ok(entities)
    }

    async fn find_many(
        _conn: &mut Self::ConnectionType,
        _ids: &[StringEntityId],
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        unreachable!()
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let conn = conn.conn().await;
        conn.query_row("SELECT COUNT(*) FROM mls_pending_messages", [], |r| r.get(0))
            .map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl EntityBase for MlsPendingMessage {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "mls_pending_messages";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsPendingMessages
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::MlsPendingMessage(self.into())
    }
}

#[async_trait::async_trait]
impl EntityTransactionExt for MlsPendingMessage {
    async fn save(&self, transaction: &TransactionWrapper<'_>) -> CryptoKeystoreResult<()> {
        Self::ConnectionType::check_buffer_size(self.foreign_id.len())?;
        Self::ConnectionType::check_buffer_size(self.message.len())?;

        let zid = rusqlite::blob::ZeroBlob(self.foreign_id.len() as i32);
        let zmsg = rusqlite::blob::ZeroBlob(self.message.len() as i32);

        let id_bytes = &self.foreign_id;

        use rusqlite::ToSql as _;
        transaction.execute(
            "INSERT INTO mls_pending_messages (id, message) VALUES(?, ?)",
            [&zid.to_sql()?, &zmsg.to_sql()?],
        )?;
        let rowid = transaction.last_insert_rowid();

        let mut blob = transaction.blob_open(rusqlite::MAIN_DB, "mls_pending_messages", "id", rowid, false)?;
        use std::io::Write as _;
        blob.write_all(id_bytes)?;
        blob.close()?;

        let mut blob = transaction.blob_open(rusqlite::MAIN_DB, "mls_pending_messages", "message", rowid, false)?;
        blob.write_all(&self.message)?;
        blob.close()?;

        Ok(())
    }

    async fn delete_fail_on_missing_id(
        transaction: &TransactionWrapper<'_>,
        id: StringEntityId<'_>,
    ) -> CryptoKeystoreResult<()> {
        let updated = transaction.execute("DELETE FROM mls_pending_messages WHERE id = ?", [id.as_slice()])?;

        if updated > 0 {
            Ok(())
        } else {
            Err(Self::to_missing_key_err_kind().into())
        }
    }
}

impl NewEntityBase for MlsPendingMessage {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "mls_pending_messages";

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::MlsPendingMessage(self.into())
    }
}

/// Pending messages have no distinct primary key;
/// they must always be accessed via [`MlsPendingMessage::find_all_by_conversation_id`] and
/// cleaned up with [`MlsPendingMessage::delete_by_conversation_id`]
///
/// However, we have to fake it here to support `KeystoreTransaction::remove_pending_messages_by_conversation_id`.
/// This is temporary! Post WPB-20844, we should remove that whole API and also reset the primary key type here to `()`.
impl PrimaryKey for MlsPendingMessage {
    type PrimaryKey = Vec<u8>;
    fn primary_key(&self) -> Self::PrimaryKey {
        self.foreign_id.clone()
    }
}

impl BorrowPrimaryKey for MlsPendingMessage {
    type BorrowedPrimaryKey = [u8];

    fn borrow_primary_key(&self) -> &Self::BorrowedPrimaryKey {
        &self.foreign_id
    }
}

#[async_trait]
impl NewEntity for MlsPendingMessage {
    async fn get(conn: &mut Self::ConnectionType, key: &Self::PrimaryKey) -> CryptoKeystoreResult<Option<Self>> {
        panic!("cannot get `MlsPendingMessage` by primary key as it has no distinct primary key")
    }

    async fn count(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<u32> {
        count_helper::<Self>(conn).await
    }

    async fn load_all(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Vec<Self>> {
        load_all_helper::<Self, _>(conn, Self::from_row).await
    }
}

#[async_trait]
impl EntityGetBorrowed for MlsPendingMessage {
    async fn get_borrowed(
        conn: &mut Self::ConnectionType,
        key: &Self::BorrowedPrimaryKey,
    ) -> CryptoKeystoreResult<Option<Self>> {
        panic!("cannot get `MlsPendingMessage` by primary key as it has no distinct primary key")
    }
}

#[async_trait]
impl<'a> EntityDatabaseMutation<'a> for MlsPendingMessage {
    type Transaction = TransactionWrapper<'a>;

    async fn save(&'a self, tx: &Self::Transaction) -> CryptoKeystoreResult<()> {
        let mut stmt = tx.prepare_cached("INSERT INTO mls_pending_messages (id, message) VALUES (?, ?)")?;
        stmt.execute(params![self.foreign_id, self.message])?;
        Ok(())
    }

    async fn count(tx: &Self::Transaction) -> CryptoKeystoreResult<u32> {
        count_helper_tx::<Self>(tx).await
    }

    async fn delete(tx: &Self::Transaction, id: &Self::PrimaryKey) -> CryptoKeystoreResult<bool> {
        panic!("cannot delete `MlsPendingMessage` by primary key as it has no distinct primary key")
    }
}
