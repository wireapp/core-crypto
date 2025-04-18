use crate::{
    CryptoKeystoreResult,
    connection::TransactionWrapper,
    entities::{EntityIdStringExt, EntityTransactionExt},
};
use crate::{
    MissingKeyErrorKind,
    connection::{DatabaseConnection, KeystoreDatabaseConnection},
    entities::{Entity, EntityBase, EntityFindParams, MlsPskBundle, StringEntityId},
};
use std::io::{Read, Write};

#[async_trait::async_trait]
impl Entity for MlsPskBundle {
    fn id_raw(&self) -> &[u8] {
        self.psk_id.as_slice()
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let mut conn = conn.conn().await;
        let transaction = conn.transaction()?;
        let query: String = format!("SELECT rowid FROM mls_psk_bundles {}", params.to_sql());

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| r.get(0))?;
        let entities = rows.try_fold(Vec::new(), |mut acc, row_result| {
            use std::io::Read as _;
            let rowid = row_result?;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_psk_bundles", "psk_id", rowid, true)?;

            let mut psk_id = vec![];
            blob.read_to_end(&mut psk_id)?;
            blob.close()?;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_psk_bundles", "psk", rowid, true)?;

            let mut psk = vec![];
            blob.read_to_end(&mut psk)?;
            blob.close()?;

            acc.push(Self { psk_id, psk });

            crate::CryptoKeystoreResult::Ok(acc)
        })?;

        Ok(entities)
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        let mut conn = conn.conn().await;
        let transaction = conn.transaction()?;
        use rusqlite::OptionalExtension as _;
        let maybe_rowid = transaction
            .query_row(
                "SELECT rowid FROM mls_psk_bundles WHERE id_sha256 = ?",
                [id.sha256()],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;

        if let Some(rowid) = maybe_rowid {
            let psk_id = id.as_slice().to_vec();

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_psk_bundles", "psk", rowid, true)?;

            let mut psk = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut psk)?;
            blob.close()?;

            Ok(Some(Self { psk_id, psk }))
        } else {
            Ok(None)
        }
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let conn = conn.conn().await;
        conn.query_row("SELECT COUNT(*) FROM mls_psk_bundles", [], |r| r.get(0))
            .map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl EntityBase for MlsPskBundle {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "mls_psk_bundles";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsPskBundle
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::PskBundle(self)
    }
}

#[async_trait::async_trait]
impl EntityTransactionExt for MlsPskBundle {
    async fn save(&self, transaction: &TransactionWrapper<'_>) -> CryptoKeystoreResult<()> {
        use rusqlite::ToSql as _;
        Self::ConnectionType::check_buffer_size(self.psk.len())?;
        Self::ConnectionType::check_buffer_size(self.psk_id.len())?;

        let zb_psk_id = rusqlite::blob::ZeroBlob(self.psk_id.len() as i32);
        let zb_psk = rusqlite::blob::ZeroBlob(self.psk.len() as i32);

        // Use UPSERT (ON CONFLICT DO UPDATE)
        let sql = "
        INSERT INTO mls_psk_bundles (id_sha256, psk_id, psk)
        VALUES (?, ?, ?)
        ON CONFLICT(id_sha256) DO UPDATE SET psk_id = excluded.psk_id, psk = excluded.psk
        RETURNING rowid";

        let row_id: i64 = transaction.query_row(
            sql,
            [&self.id_sha256().to_sql()?, &zb_psk_id.to_sql()?, &zb_psk.to_sql()?],
            |r| r.get(0),
        )?;

        let mut blob =
            transaction.blob_open(rusqlite::DatabaseName::Main, "mls_psk_bundles", "psk_id", row_id, false)?;
        blob.write_all(&self.psk_id)?;
        blob.close()?;

        let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_psk_bundles", "psk", row_id, false)?;
        blob.write_all(&self.psk)?;
        blob.close()?;

        Ok(())
    }

    async fn delete_fail_on_missing_id(
        transaction: &TransactionWrapper<'_>,
        id: StringEntityId<'_>,
    ) -> CryptoKeystoreResult<()> {
        let updated = transaction.execute("DELETE FROM mls_psk_bundles WHERE id_sha256 = ?", [id.sha256()])?;

        if updated > 0 {
            Ok(())
        } else {
            Err(Self::to_missing_key_err_kind().into())
        }
    }
}
