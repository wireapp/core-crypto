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

use crate::connection::DatabaseConnection;
use crate::entities::PersistedMlsGroup;
use crate::entities::PersistedMlsPendingGroup;
use crate::entities::StringEntityId;
use crate::{
    connection::KeystoreDatabaseConnection,
    entities::{Entity, EntityBase},
    CryptoKeystoreError, MissingKeyErrorKind,
};

impl Entity for PersistedMlsGroup {
    fn id_raw(&self) -> &[u8] {
        self.id.as_slice()
    }
}

impl Entity for PersistedMlsPendingGroup {
    fn id_raw(&self) -> &[u8] {
        self.id.as_slice()
    }
}


#[async_trait::async_trait(?Send)]
impl EntityBase for PersistedMlsGroup {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsGroup
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        use rusqlite::OptionalExtension as _;
        use rusqlite::ToSql as _;

        let group_id = &self.id;
        let state = &self.state;
        let transaction = conn.transaction()?;

        let id_bytes = &self.id;

        Self::ConnectionType::check_buffer_size(state.len())?;
        Self::ConnectionType::check_buffer_size(id_bytes.len())?;

        let zb = rusqlite::blob::ZeroBlob(state.len() as i32);
        let zid = rusqlite::blob::ZeroBlob(id_bytes.len() as i32);

        let rowid: i64 = if let Some(rowid) = transaction
            .query_row("SELECT rowid FROM mls_groups WHERE id = ?", [group_id], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?
        {
            transaction.execute(
                "UPDATE mls_groups SET state = ? WHERE rowid = ?",
                [zb.to_sql()?, rowid.to_sql()?],
            )?;

            rowid
        } else {
            transaction.execute(
                "INSERT INTO mls_groups (id, state) VALUES(?, ?)",
                [&zid.to_sql()?, &zb.to_sql()?],
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
            .query_row("SELECT rowid FROM mls_groups WHERE id = ?", [id.as_bytes()], |r| {
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

            Ok(Some(Self { id, state }))
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

            res.push(Self { id, state });
        }

        transaction.commit()?;

        Ok(res)
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        Ok(conn.query_row("SELECT COUNT(*) FROM mls_groups", [], |r| r.get(0))?)
    }

    async fn delete(conn: &mut Self::ConnectionType, id: &StringEntityId) -> crate::CryptoKeystoreResult<()> {
        let updated = conn.execute("DELETE FROM mls_groups WHERE id = ?", [id.as_bytes()])?;

        if updated != 0 {
            Ok(())
        } else {
            Err(MissingKeyErrorKind::MlsGroup.into())
        }
    }
}

#[async_trait::async_trait(?Send)]
impl EntityBase for PersistedMlsPendingGroup {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsGroup
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        let state = &self.state;
        let transaction = conn.transaction()?;

        use rusqlite::OptionalExtension as _;

        let rowid: i64 = if let Some(rowid) = transaction
            .query_row("SELECT rowid FROM mls_pending_groups WHERE id = ?", [&self.id], |r| {
                r.get(0)
            })
            .optional()?
        {
            // we have to update the size of the blob, otherwise we can have trash in the data
            let zb = rusqlite::blob::ZeroBlob(state.len() as i32);
            use rusqlite::ToSql as _;
            transaction.execute(
                "UPDATE mls_pending_groups SET state = ? WHERE id = ?",
                [&zb.to_sql()?, &self.id.to_sql()?],
            )?;
            rowid
        } else {
            let id_bytes = &self.id;
            let zb = rusqlite::blob::ZeroBlob(state.len() as i32);
            let zid = rusqlite::blob::ZeroBlob(id_bytes.len() as i32);
            use rusqlite::ToSql as _;
            transaction.execute(
                "INSERT INTO mls_pending_groups (id, state) VALUES(?, ?)",
                [&zid.to_sql()?, &zb.to_sql()?],
            )?;
            let rowid = transaction.last_insert_rowid();

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_pending_groups", "id", rowid, false)?;
            use std::io::Write as _;
            blob.write_all(id_bytes)?;
            blob.close()?;

            rowid
        };

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_pending_groups",
            "state",
            rowid,
            false,
        )?;
        use std::io::Write as _;
        blob.write_all(state)?;
        blob.close()?;

        transaction.commit()?;

        Ok(())
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        use rusqlite::OptionalExtension as _;
        use std::io::Read as _;

        let transaction = conn.transaction()?;
        let rowid: Option<i64> = transaction
            .query_row(
                "SELECT rowid FROM mls_pending_groups WHERE id = ?",
                [&id.as_bytes()],
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
                Ok(Some(Self { id, state }))
            }
            None => Ok(None),
        }
    }

    async fn find_many(
        conn: &mut Self::ConnectionType,
        _ids: &[StringEntityId],
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
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

            res.push(Self { id, state });
        }

        transaction.commit()?;

        Ok(res)
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        Ok(conn.query_row("SELECT COUNT(*) FROM mls_pending_groups", [], |r| r.get(0))?)
    }

    async fn delete(conn: &mut Self::ConnectionType, id: &StringEntityId) -> crate::CryptoKeystoreResult<()> {
        let updated = conn.execute("DELETE FROM mls_pending_groups WHERE id = ?", [id.as_bytes()])?;

        if updated != 0 {
            Ok(())
        } else {
            Err(MissingKeyErrorKind::MlsPendingGroup.into())
        }
    }
}
