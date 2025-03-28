use crate::{
    CryptoKeystoreError, MissingKeyErrorKind,
    connection::KeystoreDatabaseConnection,
    entities::{Entity, EntityBase, EntityFindParams, PersistedMlsPendingGroup, StringEntityId},
};
use crate::{
    CryptoKeystoreResult,
    connection::{DatabaseConnection, TransactionWrapper},
    entities::EntityTransactionExt,
};

#[async_trait::async_trait]
impl Entity for PersistedMlsPendingGroup {
    fn id_raw(&self) -> &[u8] {
        self.id.as_slice()
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        use rusqlite::OptionalExtension as _;
        use std::io::Read as _;

        let mut conn = conn.conn().await;
        let transaction = conn.transaction()?;
        let rowid: Option<i64> = transaction
            .query_row(
                "SELECT rowid FROM mls_pending_groups WHERE id = ?",
                [&id.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        match rowid {
            Some(rowid) => {
                let mut blob =
                    transaction.blob_open(rusqlite::DatabaseName::Main, "mls_pending_groups", "id", rowid, true)?;
                let mut id = vec![];
                blob.read_to_end(&mut id)?;
                blob.close()?;

                let mut blob =
                    transaction.blob_open(rusqlite::DatabaseName::Main, "mls_pending_groups", "state", rowid, true)?;
                let mut state = vec![];
                blob.read_to_end(&mut state)?;
                blob.close()?;

                let mut blob =
                    transaction.blob_open(rusqlite::DatabaseName::Main, "mls_pending_groups", "cfg", rowid, true)?;
                let mut custom_configuration = vec![];
                blob.read_to_end(&mut custom_configuration)?;
                blob.close()?;

                let mut parent_id = None;
                let mut blob = transaction.blob_open(
                    rusqlite::DatabaseName::Main,
                    "mls_pending_groups",
                    "parent_id",
                    rowid,
                    true,
                )?;
                if !blob.is_empty() {
                    let tmp = Vec::with_capacity(blob.len());
                    blob.read_to_end(&mut state)?;
                    parent_id.replace(tmp);
                }
                blob.close()?;

                Ok(Some(Self {
                    id,
                    state,
                    parent_id,
                    custom_configuration,
                }))
            }
            None => Ok(None),
        }
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let mut conn = conn.conn().await;
        let transaction = conn.transaction()?;
        let query: String = format!("SELECT rowid FROM mls_pending_groups {}", params.to_sql());

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| r.get(0))?;
        let entities = rows.try_fold(Vec::new(), |mut acc, rowid_result| {
            use std::io::Read as _;
            let rowid = rowid_result?;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_pending_groups", "id", rowid, true)?;
            let mut id = vec![];
            blob.read_to_end(&mut id)?;
            blob.close()?;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_pending_groups", "state", rowid, true)?;
            let mut state = vec![];
            blob.read_to_end(&mut state)?;
            blob.close()?;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_pending_groups", "cfg", rowid, true)?;
            let mut custom_configuration = vec![];
            blob.read_to_end(&mut custom_configuration)?;
            blob.close()?;

            let mut parent_id = None;
            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_pending_groups",
                "parent_id",
                rowid,
                true,
            )?;
            if !blob.is_empty() {
                let mut tmp = Vec::with_capacity(blob.len());
                blob.read_to_end(&mut tmp)?;
                parent_id.replace(tmp);
            }
            blob.close()?;

            acc.push(Self {
                id,
                state,
                parent_id,
                custom_configuration,
            });
            crate::CryptoKeystoreResult::Ok(acc)
        })?;

        Ok(entities)
    }

    async fn find_many(
        conn: &mut Self::ConnectionType,
        _ids: &[StringEntityId],
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let mut conn = conn.conn().await;

        // Plot twist: we always select ALL the persisted groups. Unsure if we want to make it a real API with selection
        let mut stmt = conn.prepare_cached("SELECT rowid FROM mls_pending_groups ORDER BY rowid ASC")?;
        let rowids: Vec<i64> = stmt
            .query_map([], |r| r.get(0))?
            .map(|r| r.map_err(CryptoKeystoreError::from))
            .collect::<crate::CryptoKeystoreResult<_>>()?;

        drop(stmt);

        if rowids.is_empty() {
            return Ok(Default::default());
        }

        let transaction = conn.transaction()?;

        let mut res = Vec::with_capacity(rowids.len());
        for rowid in rowids.into_iter() {
            use std::io::Read as _;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_pending_groups", "id", rowid, true)?;
            let mut id = vec![];
            blob.read_to_end(&mut id)?;
            blob.close()?;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_pending_groups", "state", rowid, true)?;
            let mut state = vec![];
            blob.read_to_end(&mut state)?;
            blob.close()?;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_pending_groups", "cfg", rowid, true)?;
            let mut custom_configuration = vec![];
            blob.read_to_end(&mut custom_configuration)?;
            blob.close()?;

            let mut parent_id = None;
            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_pending_groups",
                "parent_id",
                rowid,
                true,
            )?;
            if !blob.is_empty() {
                let mut tmp = Vec::with_capacity(blob.len());
                blob.read_to_end(&mut tmp)?;
                parent_id.replace(tmp);
            }
            blob.close()?;

            res.push(Self {
                id,
                state,
                parent_id,
                custom_configuration,
            });
        }

        transaction.commit()?;

        Ok(res)
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let conn = conn.conn().await;
        conn.query_row("SELECT COUNT(*) FROM mls_pending_groups", [], |r| r.get(0))
            .map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl EntityBase for PersistedMlsPendingGroup {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "mls_pending_groups";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsPendingGroup
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::PersistedMlsPendingGroup(self)
    }
}

#[async_trait::async_trait]
impl EntityTransactionExt for PersistedMlsPendingGroup {
    async fn save(&self, transaction: &TransactionWrapper<'_>) -> CryptoKeystoreResult<()> {
        let parent_id = self.parent_id.as_ref();

        use rusqlite::OptionalExtension as _;

        Self::ConnectionType::check_buffer_size(self.state.len())?;
        Self::ConnectionType::check_buffer_size(self.id.len())?;
        Self::ConnectionType::check_buffer_size(parent_id.map(Vec::len).unwrap_or_default())?;

        let zcfg = rusqlite::blob::ZeroBlob(self.custom_configuration.len() as i32);
        let zpid = rusqlite::blob::ZeroBlob(parent_id.map(Vec::len).unwrap_or_default() as i32);
        let zb = rusqlite::blob::ZeroBlob(self.state.len() as i32);
        let zid = rusqlite::blob::ZeroBlob(self.id.len() as i32);

        let rowid: i64 = match transaction
            .query_row(
                "SELECT rowid FROM mls_pending_groups WHERE id = ?",
                [self.id.as_slice()],
                |r| r.get(0),
            )
            .optional()?
        {
            Some(rowid) => {
                use rusqlite::ToSql as _;
                transaction.execute(
                    "UPDATE mls_pending_groups SET state = ?, parent_id = ?, cfg = ? WHERE id = ?",
                    [&zb.to_sql()?, &zpid.to_sql()?, &zcfg.to_sql()?, &self.id.to_sql()?],
                )?;
                rowid
            }
            _ => {
                let id_bytes = &self.id;

                use rusqlite::ToSql as _;
                transaction.execute(
                    "INSERT INTO mls_pending_groups (id, state, cfg, parent_id) VALUES(?, ?, ?, ?)",
                    [&zid.to_sql()?, &zb.to_sql()?, &zcfg.to_sql()?, &zpid.to_sql()?],
                )?;
                let rowid = transaction.last_insert_rowid();

                let mut blob =
                    transaction.blob_open(rusqlite::DatabaseName::Main, "mls_pending_groups", "id", rowid, false)?;
                use std::io::Write as _;
                blob.write_all(id_bytes)?;
                blob.close()?;

                rowid
            }
        };

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_pending_groups",
            "state",
            rowid,
            false,
        )?;
        use std::io::Write as _;
        blob.write_all(&self.state)?;
        blob.close()?;

        let mut blob =
            transaction.blob_open(rusqlite::DatabaseName::Main, "mls_pending_groups", "cfg", rowid, false)?;
        blob.write_all(&self.custom_configuration)?;
        blob.close()?;

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_pending_groups",
            "parent_id",
            rowid,
            false,
        )?;
        if let Some(parent_id) = self.parent_id.as_ref() {
            blob.write_all(parent_id)?;
        }
        blob.close()?;

        Ok(())
    }

    async fn delete_fail_on_missing_id(
        transaction: &TransactionWrapper<'_>,
        id: StringEntityId<'_>,
    ) -> CryptoKeystoreResult<()> {
        let updated = transaction.execute("DELETE FROM mls_pending_groups WHERE id = ?", [id.as_slice()])?;

        if updated > 0 {
            Ok(())
        } else {
            Err(Self::to_missing_key_err_kind().into())
        }
    }
}
