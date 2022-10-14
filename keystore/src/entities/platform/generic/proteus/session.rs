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

use crate::entities::{EntityFindParams, ProteusSession, StringEntityId};
use crate::CryptoKeystoreError;
use crate::{
    connection::{DatabaseConnection, KeystoreDatabaseConnection},
    entities::{Entity, EntityBase},
    MissingKeyErrorKind,
};

impl Entity for ProteusSession {
    fn id_raw(&self) -> &[u8] {
        self.id.as_bytes()
    }
}

#[async_trait::async_trait(?Send)]
impl EntityBase for ProteusSession {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::ProteusSession
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let transaction = conn.transaction()?;
        let query: String = format!("SELECT rowid, id FROM proteus_sessions {}", params.to_sql());

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let entities = rows.try_fold(Vec::new(), |mut acc, q_result| {
            use std::io::Read as _;
            let (rowid, id) = q_result?;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "proteus_sessions", "session", rowid, true)?;
            let mut session = vec![];
            blob.read_to_end(&mut session)?;
            blob.close()?;

            acc.push(Self { id, session });
            crate::CryptoKeystoreResult::Ok(acc)
        })?;

        Ok(entities)
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        use rusqlite::OptionalExtension as _;
        use rusqlite::ToSql as _;

        let session_id = &self.id;
        let session = &self.session;
        let transaction = conn.transaction()?;

        let id_bytes = &self.id;

        Self::ConnectionType::check_buffer_size(session.len())?;
        Self::ConnectionType::check_buffer_size(id_bytes.len())?;

        let zb = rusqlite::blob::ZeroBlob(session.len() as i32);

        let rowid: i64 = if let Some(rowid) = transaction
            .query_row("SELECT rowid FROM proteus_sessions WHERE id = ?", [session_id], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?
        {
            transaction.execute(
                "UPDATE proteus_sessions SET session = ? WHERE rowid = ?",
                [zb.to_sql()?, rowid.to_sql()?],
            )?;

            rowid
        } else {
            transaction.execute(
                "INSERT INTO proteus_sessions (id, session) VALUES(?, ?)",
                [&session_id.to_sql()?, &zb.to_sql()?],
            )?;
            transaction.last_insert_rowid()
        };

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "proteus_sessions",
            "session",
            rowid,
            false,
        )?;
        use std::io::Write as _;
        blob.write_all(session)?;
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
        let id_string: String = id.try_into()?;
        let mut rowid: Option<i64> = transaction
            .query_row("SELECT rowid FROM proteus_sessions WHERE id = ?", [&id_string], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?;

        if let Some(rowid) = rowid.take() {
            use std::io::Read as _;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "proteus_sessions", "session", rowid, true)?;
            let mut session = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut session)?;
            blob.close()?;

            Ok(Some(Self { id: id_string, session }))
        } else {
            Ok(None)
        }
    }

    async fn find_many(
        conn: &mut Self::ConnectionType,
        _ids: &[StringEntityId],
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        // Plot twist: we always select ALL the persisted groups. Unsure if we want to make it a real API with selection
        let mut stmt = conn.prepare_cached("SELECT rowid, id FROM proteus_sessions ORDER BY rowid ASC")?;
        let rows: Vec<(i64, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .map(|r| r.map_err(CryptoKeystoreError::from))
            .collect::<crate::CryptoKeystoreResult<_>>()?;

        drop(stmt);

        if rows.is_empty() {
            return Ok(Default::default());
        }

        let transaction = conn.transaction()?;

        let mut res = Vec::with_capacity(rows.len());
        for (rowid, id) in rows.into_iter() {
            use std::io::Read as _;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "proteus_sessions", "session", rowid, true)?;
            let mut session = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut session)?;
            blob.close()?;

            res.push(Self { id, session });
        }

        transaction.commit()?;

        Ok(res)
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        Ok(conn.query_row("SELECT COUNT(*) FROM proteus_sessions", [], |r| r.get(0))?)
    }

    async fn delete(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<()> {
        let transaction = conn.transaction()?;
        let len = ids.len();
        let mut updated = 0;
        for id in ids {
            let id_string: String = id.try_into()?;
            updated += transaction.execute("DELETE FROM proteus_sessions WHERE id = ?", [id_string])?;
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
