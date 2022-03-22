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

use crate::entities::MlsKeypackage;
use crate::entities::StringEntityId;
use crate::{
    connection::KeystoreDatabaseConnection,
    entities::{Entity, EntityBase},
    MissingKeyErrorKind,
};

impl Entity for MlsKeypackage {}

impl EntityBase for MlsKeypackage {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsKeyBundle
    }

    fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        let data = &self.key;
        let id: String = self.id.clone();

        use rusqlite::ToSql as _;
        let zb = rusqlite::blob::ZeroBlob(data.len() as i32);
        let params: [rusqlite::types::ToSqlOutput; 2] = [id.to_sql()?, zb.to_sql()?];
        let transaction = conn.transaction()?;
        transaction.execute("INSERT INTO mls_keys (id, key) VALUES (?, ?)", params)?;
        let row_id = transaction.last_insert_rowid();

        let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_keys", "key", row_id, false)?;

        use std::io::Write as _;
        blob.write_all(&data)?;
        blob.close()?;

        transaction.commit()?;

        Ok(())
    }

    fn find_one(conn: &mut Self::ConnectionType, id: &StringEntityId) -> crate::CryptoKeystoreResult<Option<Self>> {
        let id = String::from_utf8(id.as_bytes())?;

        let transaction = conn.transaction()?;
        use rusqlite::OptionalExtension as _;
        let mut row_id = transaction
            .query_row("SELECT rowid FROM mls_keys WHERE id = ?", [&id], |r| r.get::<_, i64>(0))
            .optional()?;

        if let Some(rowid) = row_id.take() {
            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_keys", "key", rowid, true)?;
            use std::io::Read as _;
            let mut buf = vec![];
            blob.read_to_end(&mut buf)?;
            blob.close()?;

            transaction.commit()?;

            Ok(Some(Self { id, key: buf }))
        } else {
            Ok(None)
        }
    }

    fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let count: usize = conn.query_row("SELECT COUNT(*) FROM mls_keys", [], |r| r.get(0))?;
        Ok(count)
    }

    fn delete(conn: &mut Self::ConnectionType, id: &StringEntityId) -> crate::CryptoKeystoreResult<()> {
        let id = String::from_utf8(id.as_bytes())?;
        let updated = conn.execute("DELETE FROM mls_keys WHERE id = ?", [id])?;

        if updated != 0 {
            Ok(())
        } else {
            Err(MissingKeyErrorKind::MlsKeyBundle.into())
        }
    }
}
