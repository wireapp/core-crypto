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
    entities::{Entity, EntityBase, EntityFindParams, MlsPskBundle, StringEntityId},
    MissingKeyErrorKind,
};
use std::io::{Read, Write};

impl Entity for MlsPskBundle {
    fn id_raw(&self) -> &[u8] {
        self.psk_id.as_slice()
    }
}

#[async_trait::async_trait(?Send)]
impl EntityBase for MlsPskBundle {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsPskBundle
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let transaction = conn.transaction()?;
        let query: String = format!("SELECT rowid FROM mls_psk_bundles {}", params.to_sql());

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| r.get(0))?;
        let entities = rows.try_fold(Vec::new(), |mut acc, rowid_result| {
            use std::io::Read as _;
            let rowid = rowid_result?;

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

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        use rusqlite::OptionalExtension as _;

        Self::ConnectionType::check_buffer_size(self.psk_id.len())?;
        Self::ConnectionType::check_buffer_size(self.psk.len())?;

        let zb_psk = rusqlite::blob::ZeroBlob(self.psk.len() as i32);

        let transaction = conn.transaction()?;
        let mut existing_rowid = transaction
            .query_row(
                "SELECT rowid FROM mls_psk_bundles WHERE psk_id = ?",
                [&self.psk_id],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;

        let row_id = if let Some(rowid) = existing_rowid.take() {
            use rusqlite::ToSql as _;
            transaction.execute(
                "UPDATE mls_psk_bundles SET psk = ? WHERE rowid = ?",
                [&zb_psk.to_sql()?, &rowid.to_sql()?],
            )?;
            rowid
        } else {
            let zb_psk_id = rusqlite::blob::ZeroBlob(self.psk_id.len() as i32);
            use rusqlite::ToSql as _;
            let params: [rusqlite::types::ToSqlOutput; 2] = [zb_psk_id.to_sql()?, zb_psk.to_sql()?];

            transaction.execute("INSERT INTO mls_psk_bundles (psk_id, psk) VALUES (?, ?)", params)?;
            let row_id = transaction.last_insert_rowid();
            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_psk_bundles", "psk_id", row_id, false)?;

            blob.write_all(&self.psk_id)?;
            blob.close()?;

            row_id
        };

        let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_psk_bundles", "psk", row_id, false)?;
        blob.write_all(&self.psk)?;
        blob.close()?;

        transaction.commit()?;

        Ok(())
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        let transaction = conn.transaction()?;
        use rusqlite::OptionalExtension as _;
        let maybe_rowid = transaction
            .query_row(
                "SELECT rowid FROM mls_psk_bundles WHERE psk_id = ?",
                [id.as_slice()],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;

        if let Some(rowid) = maybe_rowid {
            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_psk_bundles", "psk_id", rowid, true)?;

            let mut psk_id = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut psk_id)?;
            blob.close()?;

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
        Ok(conn.query_row("SELECT COUNT(*) FROM mls_psk_bundles", [], |r| r.get(0))?)
    }

    async fn delete(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<()> {
        let transaction = conn.transaction()?;
        let len = ids.len();
        let mut updated = 0;
        for id in ids {
            updated += transaction.execute("DELETE FROM mls_psk_bundles WHERE psk_id = ?", [id.as_slice()])?;
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
