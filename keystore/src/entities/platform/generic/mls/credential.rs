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
    entities::{Entity, EntityBase, EntityFindParams, MlsCredential, StringEntityId},
    MissingKeyErrorKind,
};
use std::io::{Read, Write};

impl Entity for MlsCredential {
    fn id_raw(&self) -> &[u8] {
        self.id.as_slice()
    }
}

#[async_trait::async_trait(?Send)]
impl EntityBase for MlsCredential {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsCredential
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let transaction = conn.transaction()?;
        let query: String = format!("SELECT rowid FROM mls_credentials {}", params.to_sql());

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| r.get(0))?;
        let entities = rows.try_fold(Vec::new(), |mut acc, rowid_result| {
            use std::io::Read as _;
            let rowid = rowid_result?;

            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_credentials", "id", rowid, true)?;

            let mut id = vec![];
            blob.read_to_end(&mut id)?;
            blob.close()?;

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_credentials",
                "credential",
                rowid,
                true,
            )?;

            let mut credential = vec![];
            blob.read_to_end(&mut credential)?;
            blob.close()?;

            acc.push(Self { id, credential });

            crate::CryptoKeystoreResult::Ok(acc)
        })?;

        Ok(entities)
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        use rusqlite::OptionalExtension as _;

        Self::ConnectionType::check_buffer_size(self.credential.len())?;

        let zb_cred = rusqlite::blob::ZeroBlob(self.credential.len() as i32);

        let transaction = conn.transaction()?;
        let mut existing_rowid = transaction
            .query_row("SELECT rowid FROM mls_credentials WHERE id = ?", [&self.id], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?;

        let row_id = if let Some(rowid) = existing_rowid.take() {
            use rusqlite::ToSql as _;
            transaction.execute(
                "UPDATE mls_credentials SET credential = ? WHERE rowid = ?",
                [&zb_cred.to_sql()?, &rowid.to_sql()?],
            )?;
            rowid
        } else {
            use rusqlite::ToSql as _;
            Self::ConnectionType::check_buffer_size(self.id.len())?;
            let id_zb = rusqlite::blob::ZeroBlob(self.id.len() as i32);

            let params: [rusqlite::types::ToSqlOutput; 2] = [id_zb.to_sql()?, zb_cred.to_sql()?];

            transaction.execute("INSERT INTO mls_credentials (id, credential) VALUES (?, ?)", params)?;
            let rowid = transaction.last_insert_rowid();
            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_credentials", "id", rowid, false)?;
            blob.write_all(&self.id)?;
            blob.close()?;

            rowid
        };

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_credentials",
            "credential",
            row_id,
            false,
        )?;

        blob.write_all(&self.credential)?;
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
            .query_row("SELECT rowid FROM mls_credentials WHERE id = ?", [id.as_slice()], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?;

        if let Some(rowid) = maybe_rowid {
            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_credentials",
                "credential",
                rowid,
                true,
            )?;

            let mut credential = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut credential)?;
            blob.close()?;

            Ok(Some(Self {
                id: id.to_bytes(),
                credential,
            }))
        } else {
            Ok(None)
        }
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        Ok(conn.query_row("SELECT COUNT(*) FROM mls_credentials", [], |r| r.get(0))?)
    }

    async fn delete(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<()> {
        let transaction = conn.transaction()?;
        let len = ids.len();
        let mut updated = 0;
        for id in ids {
            updated += transaction.execute("DELETE FROM mls_credentials WHERE id = ?", [id.as_slice()])?;
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