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

use crate::entities::{EntityFindParams, ProteusPrekey, StringEntityId};
use crate::{
    connection::KeystoreDatabaseConnection,
    entities::{Entity, EntityBase},
    MissingKeyErrorKind,
};

impl Entity for ProteusPrekey {
    fn id_raw(&self) -> &[u8] {
        self.id.to_le_bytes().as_slice()
    }
}

#[async_trait::async_trait(?Send)]
impl EntityBase for ProteusPrekey {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::ProteusPrekey
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let transaction = conn.transaction()?;
        let query: String = format!("SELECT rowid, id FROM proteus_prekeys {}", params.to_sql());

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let entities = rows.try_fold(Vec::new(), |mut acc, query_result| {
            use std::io::Read as _;
            let (rowid, id) = query_result?;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "proteus_prekeys", "key", rowid, true)?;

            let mut buf = vec![];
            blob.read_to_end(&mut buf)?;
            blob.close()?;

            acc.push(Self { id, prekey: buf });
            crate::CryptoKeystoreResult::Ok(acc)
        })?;

        Ok(entities)
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
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
            let mut buf = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut buf)?;
            blob.close()?;

            Ok(Some(Self { id, prekey: buf }))
        } else {
            Ok(None)
        }
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        Ok(conn.query_row("SELECT COUNT(*) FROM proteus_prekeys", [], |r| r.get(0))?)
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
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

    async fn delete(
        conn: &mut Self::ConnectionType,
        id: &[crate::entities::StringEntityId],
    ) -> crate::CryptoKeystoreResult<()> {
        let transaction = conn.transaction()?;
        let len = ids.len();
        let mut updated = 0;
        for id in ids {
            updated += transaction.execute(
                "DELETE FROM proteus_prekeys WHERE id = ?",
                [String::from_utf8(id.as_bytes())],
            )?;
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
