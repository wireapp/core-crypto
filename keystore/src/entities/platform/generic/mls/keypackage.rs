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

use crate::entities::EntityIdStringExt;
use crate::{
    connection::{DatabaseConnection, KeystoreDatabaseConnection},
    entities::{Entity, EntityBase, EntityFindParams, MlsKeyPackage, StringEntityId},
    MissingKeyErrorKind,
};
use rusqlite::ToSql;
use std::io::{Read, Write};

impl Entity for MlsKeyPackage {
    fn id_raw(&self) -> &[u8] {
        self.keypackage_ref.as_slice()
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityBase for MlsKeyPackage {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsKeyPackageBundle
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let transaction = conn.transaction()?;
        let query: String = format!(
            "SELECT rowid, keypackage_ref_hex FROM mls_keypackages {}",
            params.to_sql()
        );

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| {
            let rowid: i64 = r.get(0)?;
            let keypackage_ref_hex: String = r.get(1)?;
            Ok((rowid, keypackage_ref_hex))
        })?;
        let entities = rows.try_fold(Vec::new(), |mut acc, row_result| {
            use std::io::Read as _;
            let (rowid, keypackage_ref_hex) = row_result?;

            let keypackage_ref = Self::id_from_hex(&keypackage_ref_hex)?;

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
        Self::ConnectionType::check_buffer_size(self.keypackage.len())?;

        let transaction = conn.transaction()?;

        // Create zero blobs for keypackage and keypackage_ref
        let kp_zb = rusqlite::blob::ZeroBlob(self.keypackage.len() as i32);

        // Use UPSERT (ON CONFLICT DO UPDATE)
        let sql = "
        INSERT INTO mls_keypackages (keypackage_ref_hex, keypackage) 
        VALUES (?, ?) 
        ON CONFLICT(keypackage_ref_hex) DO UPDATE SET keypackage = excluded.keypackage
        RETURNING rowid";

        let row_id: i64 = transaction.query_row(sql, [&self.id_hex().to_sql()?, &kp_zb.to_sql()?], |r| r.get(0))?;

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_keypackages",
            "keypackage",
            row_id,
            false,
        )?;
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
                "SELECT rowid FROM mls_keypackages WHERE keypackage_ref_hex = ?",
                [id.as_hex_string()],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;

        if let Some(rowid) = row_id.take() {
            let keypackage_ref = id.as_slice().to_vec();

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
            updated += transaction.execute(
                "DELETE FROM mls_keypackages WHERE keypackage_ref_hex = ?",
                [id.as_hex_string()],
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
