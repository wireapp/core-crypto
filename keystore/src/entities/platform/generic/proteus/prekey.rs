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
        self.id_bytes()
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityBase for ProteusPrekey {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "proteus_prekeys";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::ProteusPrekey
    }

    fn to_transaction_entity(self) -> crate::transaction::Entity {
        unimplemented!("This has not yet been implemented for Proteus")
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let transaction = conn.transaction()?;
        let query: String = format!("SELECT rowid, id FROM proteus_prekeys {}", params.to_sql());

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, u16>(1)?)))?;
        let entities = rows.try_fold(Vec::new(), |mut acc, query_result| {
            use std::io::Read as _;
            let (rowid, id) = query_result?;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "proteus_prekeys", "key", rowid, true)?;

            let mut buf = vec![];
            blob.read_to_end(&mut buf)?;
            blob.close()?;

            acc.push(Self::from_raw(id, buf));
            crate::CryptoKeystoreResult::Ok(acc)
        })?;

        Ok(entities)
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        let id = ProteusPrekey::id_from_slice(id.as_slice());

        let transaction = conn.transaction()?;

        use rusqlite::OptionalExtension as _;
        let maybe_row_id = transaction
            .query_row("SELECT rowid FROM proteus_prekeys WHERE id = ?", [id], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?;

        if let Some(row_id) = maybe_row_id {
            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "proteus_prekeys", "key", row_id, true)?;

            use std::io::Read as _;
            let mut buf = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut buf)?;
            blob.close()?;

            Ok(Some(Self::from_raw(id, buf)))
        } else {
            Ok(None)
        }
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        Ok(conn.query_row("SELECT COUNT(*) FROM proteus_prekeys", [], |r| r.get(0))?)
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        use rusqlite::ToSql as _;

        let transaction = conn.transaction()?;

        // Use UPSERT (ON CONFLICT DO UPDATE)
        let sql = "
        INSERT INTO proteus_prekeys (id, key)
        VALUES (?, ?)
        ON CONFLICT(id) DO UPDATE SET key = excluded.key
        RETURNING rowid";

        // Create a zeroed blob for the key
        let zb_key = rusqlite::blob::ZeroBlob(self.prekey.len() as i32);

        // Execute the UPSERT and get the row_id of the affected row
        let row_id: i64 = transaction.query_row(sql, [self.id.to_sql()?, zb_key.to_sql()?], |r| r.get(0))?;

        // Write the actual prekey data into the blob
        let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "proteus_prekeys", "key", row_id, false)?;

        use std::io::Write as _;
        blob.write_all(&self.prekey)?;
        blob.close()?;

        transaction.commit()?;

        Ok(())
    }

    async fn delete(
        conn: &mut Self::ConnectionType,
        id: crate::entities::StringEntityId<'_>,
    ) -> crate::CryptoKeystoreResult<()> {
        let transaction = conn.transaction()?;

        let id = ProteusPrekey::id_from_slice(id.as_slice());
        let updated = transaction.execute("DELETE FROM proteus_prekeys WHERE id = ?", [id])?;

        if updated > 0 {
            transaction.commit()?;
            Ok(())
        } else {
            transaction.rollback()?;
            Err(Self::to_missing_key_err_kind().into())
        }
    }
}
