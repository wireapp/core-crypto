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
    entities::{Entity, EntityBase, EntityFindParams, MlsKeyPackage, StringEntityId},
    MissingKeyErrorKind,
};
use std::io::Read;

impl Entity for MlsKeyPackage {
    fn id_raw(&self) -> &[u8] {
        self.keypackage_ref.as_slice()
    }
}

#[async_trait::async_trait(?Send)]
impl EntityBase for MlsKeyPackage {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsKeyPackageBundle
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let transaction = conn.transaction()?;
        let query: String = format!("SELECT rowid FROM mls_keypackages {}", params.to_sql());

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| r.get(0))?;
        let entities = rows.try_fold(Vec::new(), |mut acc, rowid_result| {
            use std::io::Read as _;
            let rowid = rowid_result?;

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_keypackages",
                "keypackage_ref",
                rowid,
                true,
            )?;
            let mut keypackage_ref = vec![];
            blob.read_to_end(&mut keypackage_ref)?;
            blob.close()?;

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_keypackages",
                "keypackage",
                rowid,
                true,
            )?;
            let mut keypackage = vec![];
            blob.read_to_end(&mut keypackage)?;
            blob.close()?;

            acc.push(Self {
                keypackage_ref,
                keypackage,
            });

            crate::CryptoKeystoreResult::Ok(acc)
        })?;

        Ok(entities)
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        use rusqlite::OptionalExtension as _;
        use rusqlite::ToSql as _;

        Self::ConnectionType::check_buffer_size(self.keypackage_ref.len())?;
        Self::ConnectionType::check_buffer_size(self.keypackage.len())?;

        let transaction = conn.transaction()?;
        let mut existing_rowid = transaction
            .query_row(
                "SELECT rowid FROM mls_keypackages WHERE keypackage_ref = ?",
                [&self.keypackage_ref],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;

        let kp_zb = rusqlite::blob::ZeroBlob(self.keypackage.len() as i32);

        let row_id = if let Some(rowid) = existing_rowid.take() {
            transaction.execute(
                "UPDATE mls_keypackages SET keypackage = ? WHERE rowid = ?",
                [kp_zb.to_sql()?, rowid.to_sql()?],
            )?;

            rowid
        } else {
            let kp_ref_zb = rusqlite::blob::ZeroBlob(self.keypackage_ref.len() as i32);
            let params: [rusqlite::types::ToSqlOutput; 2] = [kp_ref_zb.to_sql()?, kp_zb.to_sql()?];
            transaction.execute(
                "INSERT INTO mls_keypackages (keypackage_ref, keypackage) VALUES (?, ?)",
                params,
            )?;
            let row_id = transaction.last_insert_rowid();
            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_keypackages",
                "keypackage_ref",
                row_id,
                false,
            )?;

            use std::io::Write as _;
            blob.write_all(&self.keypackage_ref)?;
            blob.close()?;

            row_id
        };

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_keypackages",
            "keypackage",
            row_id,
            false,
        )?;

        use std::io::Write as _;
        blob.write_all(&self.keypackage)?;
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
        let mut row_id = transaction
            .query_row(
                "SELECT rowid FROM mls_keypackages WHERE keypackage_ref = ?",
                [id.as_slice()],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;

        if let Some(rowid) = row_id.take() {
            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_keypackages",
                "keypackage_ref",
                rowid,
                true,
            )?;

            let mut keypackage_ref = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut keypackage_ref)?;
            blob.close()?;

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_keypackages",
                "keypackage",
                rowid,
                true,
            )?;

            let mut keypackage = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut keypackage)?;
            blob.close()?;

            transaction.commit()?;

            Ok(Some(Self {
                keypackage_ref,
                keypackage,
            }))
        } else {
            Ok(None)
        }
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let count: usize = conn.query_row("SELECT COUNT(*) FROM mls_keypackages", [], |r| r.get(0))?;
        Ok(count)
    }

    async fn delete(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<()> {
        let transaction = conn.transaction()?;
        let len = ids.len();
        let mut updated = 0;
        for id in ids {
            updated += transaction.execute("DELETE FROM mls_keypackages WHERE keypackage_ref = ?", [id.as_slice()])?;
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
