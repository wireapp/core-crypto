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

use crate::entities::{ProteusPrekey, StringEntityId};
use crate::{
    connection::KeystoreDatabaseConnection,
    entities::{Entity, EntityBase},
    MissingKeyErrorKind,
};

impl Entity for ProteusPrekey {}

impl EntityBase for ProteusPrekey {
    type ConnectionType = KeystoreDatabaseConnection;

    fn find_one(conn: &mut Self::ConnectionType, id: &StringEntityId) -> crate::CryptoKeystoreResult<Option<Self>> {
        let id: u16 = id.to_string().parse()?;
        let transaction = conn.transaction()?;

        use rusqlite::OptionalExtension as _;
        let maybe_row_id = transaction
            .query_row("SELECT rowid FROM proteus_prekeys WHERE id = ?", [id], |r| {
                r.get::<_, u16>(0)
            })
            .optional()?;

        if let Some(row_id) = maybe_row_id {
            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "proteus_prekeys",
                "key",
                row_id as i64,
                true,
            )?;

            use std::io::Read as _;
            let mut buf = vec![];
            blob.read_to_end(&mut buf)?;

            Ok(Some(Self { id, prekey: buf }))
        } else {
            Ok(None)
        }
    }

    fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        Ok(conn.query_row("SELECT COUNT(*) FROM proteus_prekeys", [], |r| r.get(0))?)
    }

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::ProteusPrekey
    }

    fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        let id = self.id;
        let prekey = &self.prekey;
        let transaction = conn.transaction()?;

        use rusqlite::ToSql as _;
        transaction.execute(
            "INSERT INTO proteus_prekeys (id, key) VALUES (?, ?)",
            [id.to_sql()?, rusqlite::blob::ZeroBlob(prekey.len() as i32).to_sql()?],
        )?;

        let row_id = transaction.last_insert_rowid();

        let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "proteus_prekeys", "key", row_id, false)?;
        use std::io::Write as _;
        blob.write_all(&prekey)?;
        blob.close()?;

        transaction.commit()?;

        Ok(())
    }

    fn delete(conn: &mut Self::ConnectionType, id: &crate::entities::StringEntityId) -> crate::CryptoKeystoreResult<()> {
        let id = String::from_utf8(id.as_bytes())?;
        let updated = conn.execute("DELETE FROM proteus_prekeys WHERE id = ?", [id])?;

        if updated != 0 {
            Ok(())
        } else {
            Err(MissingKeyErrorKind::ProteusPrekey.into())
        }
    }
}
