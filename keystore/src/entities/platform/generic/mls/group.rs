// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::{
    connection::{DatabaseConnection, KeystoreDatabaseConnection},
    entities::{Entity, EntityBase, EntityFindParams, PersistedMlsGroup, PersistedMlsGroupExt, StringEntityId},
    CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind,
};

impl Entity for PersistedMlsGroup {
    fn id_raw(&self) -> &[u8] {
        &self.id
    }
}

#[async_trait::async_trait(?Send)]
impl EntityBase for PersistedMlsGroup {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsGroup
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let transaction = conn.transaction()?;
        let query: String = format!("SELECT rowid FROM mls_groups {}", params.to_sql());

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| r.get(0))?;
        let entities = rows.try_fold(Vec::new(), |mut acc, rowid_result| {
            use std::io::Read as _;
            let rowid = rowid_result?;

            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "id", rowid, true)?;
            let mut id = vec![];
            blob.read_to_end(&mut id)?;
            blob.close()?;

            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "state", rowid, true)?;
            let mut state = vec![];
            blob.read_to_end(&mut state)?;
            blob.close()?;

            let mut parent_id = None;
            if let Ok(mut blob) =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "parent_id", rowid, true)
            {
                if !blob.is_empty() {
                    let mut tmp = Vec::with_capacity(blob.len());
                    blob.read_to_end(&mut tmp)?;
                    parent_id.replace(tmp);
                }
                blob.close()?;
            }

            acc.push(Self { id, parent_id, state });
            crate::CryptoKeystoreResult::Ok(acc)
        })?;

        Ok(entities)
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        use rusqlite::OptionalExtension as _;
        use rusqlite::ToSql as _;

        let group_id = &self.id;
        let state = &self.state;
        let parent_id = self.parent_id.as_ref();
        let transaction = conn.transaction()?;

        let id_bytes = &self.id;

        Self::ConnectionType::check_buffer_size(state.len())?;
        Self::ConnectionType::check_buffer_size(id_bytes.len())?;
        Self::ConnectionType::check_buffer_size(parent_id.map(Vec::len).unwrap_or_default())?;

        let zbs = rusqlite::blob::ZeroBlob(state.len() as i32);
        let zbpid = rusqlite::blob::ZeroBlob(parent_id.map(Vec::len).unwrap_or_default() as i32);
        let zid = rusqlite::blob::ZeroBlob(id_bytes.len() as i32);

        let rowid: i64 = if let Some(rowid) = transaction
            .query_row("SELECT rowid FROM mls_groups WHERE id = ?", [group_id], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?
        {
            transaction.execute(
                "UPDATE mls_groups SET state = ?, parent_id = ? WHERE rowid = ?",
                [zbs.to_sql()?, zbpid.to_sql()?, rowid.to_sql()?],
            )?;

            rowid
        } else {
            transaction.execute(
                "INSERT INTO mls_groups (id, state, parent_id) VALUES(?, ?, ?)",
                [&zid.to_sql()?, &zbs.to_sql()?, &zbpid.to_sql()?],
            )?;
            let rowid = transaction.last_insert_rowid();

            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "id", rowid, false)?;
            use std::io::Write as _;
            blob.write_all(id_bytes)?;
            blob.close()?;

            rowid
        };

        let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "state", rowid, false)?;
        use std::io::Write as _;
        blob.write_all(state)?;
        blob.close()?;

        let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "parent_id", rowid, false)?;
        if let Some(parent_id) = parent_id {
            blob.write_all(parent_id)?;
        }
        blob.close()?;

        transaction.commit()?;

        Ok(())
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        use rusqlite::OptionalExtension as _;
        let transaction = conn.transaction()?;
        let mut rowid: Option<i64> = transaction
            .query_row("SELECT rowid FROM mls_groups WHERE id = ?", [id.into_bytes()], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?;

        if let Some(rowid) = rowid.take() {
            use std::io::Read as _;

            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "id", rowid, true)?;
            let mut id = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut id)?;
            blob.close()?;

            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "state", rowid, true)?;
            let mut state = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut state)?;
            blob.close()?;

            let mut parent_id = None;
            if let Ok(mut blob) =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "parent_id", rowid, true)
            {
                if !blob.is_empty() {
                    let mut tmp = Vec::with_capacity(blob.len());
                    blob.read_to_end(&mut tmp)?;
                    parent_id.replace(tmp);
                }
                blob.close()?;
            }

            Ok(Some(Self { id, parent_id, state }))
        } else {
            Ok(None)
        }
    }

    async fn find_many(
        conn: &mut Self::ConnectionType,
        _ids: &[StringEntityId],
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        // Plot twist: we always select ALL the persisted groups. Unsure if we want to make it a real API with selection
        let mut stmt = conn.prepare_cached("SELECT rowid FROM mls_groups ORDER BY rowid ASC")?;
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

            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "id", rowid, true)?;
            let mut id = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut id)?;
            blob.close()?;

            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "state", rowid, true)?;
            let mut state = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut state)?;
            blob.close()?;

            let mut parent_id = None;
            if let Ok(mut blob) =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "parent_id", rowid, true)
            {
                if !blob.is_empty() {
                    let mut tmp = Vec::with_capacity(blob.len());
                    blob.read_to_end(&mut tmp)?;
                    parent_id.replace(tmp);
                }
                blob.close()?;
            }

            res.push(Self { id, parent_id, state });
        }

        transaction.commit()?;

        Ok(res)
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        Ok(conn.query_row("SELECT COUNT(*) FROM mls_groups", [], |r| r.get(0))?)
    }

    async fn delete(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<()> {
        let transaction = conn.transaction()?;
        let len = ids.len();
        let mut updated = 0;
        for id in ids {
            updated += transaction.execute("DELETE FROM mls_groups WHERE id = ?", [id.into_bytes()])?;
        }

        if updated == len {
            transaction.commit()?;
            Ok(())
        } else {
            transaction.rollback()?;
            Err(Self::to_missing_key_err_kind().into())
        }
    }
}

#[async_trait::async_trait(?Send)]
impl PersistedMlsGroupExt for PersistedMlsGroup {
    fn parent_id(&self) -> Option<&[u8]> {
        self.parent_id.as_deref()
    }

    async fn child_groups(&self, conn: &mut <Self as EntityBase>::ConnectionType) -> CryptoKeystoreResult<Vec<Self>> {
        let id = self.id_raw();
        let transaction = conn.transaction()?;
        let mut query = transaction.prepare_cached("SELECT rowid FROM mls_groups WHERE parent_id = ?")?;
        let mut rows = query.query_map([id], |r| r.get(0))?;

        let entities = rows.try_fold(Vec::new(), |mut acc, rowid_result| {
            use std::io::Read as _;
            let rowid = rowid_result?;

            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "id", rowid, true)?;
            let mut id = vec![];
            blob.read_to_end(&mut id)?;
            blob.close()?;

            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "state", rowid, true)?;
            let mut state = vec![];
            blob.read_to_end(&mut state)?;
            blob.close()?;

            let mut parent_id = None;
            // Ignore errors because null blobs cause errors on open
            if let Ok(mut blob) =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "parent_id", rowid, true)
            {
                if !blob.is_empty() {
                    let mut tmp = Vec::with_capacity(blob.len());
                    blob.read_to_end(&mut tmp)?;
                    parent_id.replace(tmp);
                }
                blob.close()?;
            }

            acc.push(Self { id, parent_id, state });
            crate::CryptoKeystoreResult::Ok(acc)
        })?;

        Ok(entities)
    }
}
