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
use crate::entities::MlsKeypackage;
use crate::entities::StringEntityId;
use crate::{
    connection::KeystoreDatabaseConnection,
    entities::{Entity, EntityBase},
    MissingKeyErrorKind,
};

impl Entity for MlsKeypackage {
    fn id_raw(&self) -> &[u8] {
        self.id.as_bytes()
    }
}

#[async_trait::async_trait(?Send)]
impl EntityBase for MlsKeypackage {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsKeyPackageBundle
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        use rusqlite::OptionalExtension as _;
        use rusqlite::ToSql as _;

        Self::ConnectionType::check_buffer_size(self.key.len())?;

        let transaction = conn.transaction()?;
        let mut existing_rowid = transaction
            .query_row("SELECT rowid FROM mls_keys WHERE id = ?", [&self.id], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?;

        let row_id = if let Some(rowid) = existing_rowid.take() {
            let zb = rusqlite::blob::ZeroBlob(self.key.len() as i32);
            transaction.execute(
                "UPDATE mls_keys SET key = ? WHERE rowid = ?",
                [zb.to_sql()?, rowid.to_sql()?],
            )?;

            rowid
        } else {
            let zb = rusqlite::blob::ZeroBlob(self.key.len() as i32);
            let params: [rusqlite::types::ToSqlOutput; 2] = [self.id.to_sql()?, zb.to_sql()?];
            transaction.execute("INSERT INTO mls_keys (id, key) VALUES (?, ?)", params)?;
            transaction.last_insert_rowid()
        };

        let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_keys", "key", row_id, false)?;

        use std::io::Write as _;
        blob.write_all(&self.key)?;
        blob.close()?;

        transaction.commit()?;

        Ok(())
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        let id = String::from_utf8(id.as_bytes())?;

        let transaction = conn.transaction()?;
        use rusqlite::OptionalExtension as _;
        let mut row_id = transaction
            .query_row("SELECT rowid FROM mls_keys WHERE id = ?", [&id], |r| r.get::<_, i64>(0))
            .optional()?;

        if let Some(rowid) = row_id.take() {
            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_keys", "key", rowid, true)?;
            use std::io::Read as _;
            let mut buf = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut buf)?;
            blob.close()?;

            transaction.commit()?;

            Ok(Some(Self { id, key: buf }))
        } else {
            Ok(None)
        }
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let count: usize = conn.query_row("SELECT COUNT(*) FROM mls_keys", [], |r| r.get(0))?;
        Ok(count)
    }

    async fn delete(conn: &mut Self::ConnectionType, id: &StringEntityId) -> crate::CryptoKeystoreResult<()> {
        let id = String::from_utf8(id.as_bytes())?;
        let updated = conn.execute("DELETE FROM mls_keys WHERE id = ?", [id])?;

        if updated != 0 {
            Ok(())
        } else {
            Err(Self::to_missing_key_err_kind().into())
        }
    }
}
