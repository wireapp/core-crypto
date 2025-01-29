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
    connection::TransactionWrapper,
    entities::{EntityIdStringExt, EntityTransactionExt, MlsEpochEncryptionKeyPair},
    CryptoKeystoreResult,
};
use crate::{
    connection::{DatabaseConnection, KeystoreDatabaseConnection},
    entities::{Entity, EntityBase, EntityFindParams, StringEntityId},
    MissingKeyErrorKind,
};
use rusqlite::ToSql;
use std::io::{Read, Write};

#[async_trait::async_trait]
impl Entity for MlsEpochEncryptionKeyPair {
    fn id_raw(&self) -> &[u8] {
        self.id.as_slice()
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let mut conn = conn.conn().await;
        let transaction = conn.transaction()?;
        let query: String = format!(
            "SELECT rowid, id_hex FROM mls_epoch_encryption_keypairs {}",
            params.to_sql()
        );

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| {
            let rowid: i64 = r.get(0)?;
            let id_hex: String = r.get(1)?;
            Ok((rowid, id_hex))
        })?;
        let entities = rows.try_fold(Vec::new(), |mut acc, row_result| {
            use std::io::Read as _;
            let (rowid, id_hex) = row_result?;

            let id = Self::id_from_hex(&id_hex)?;

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_epoch_encryption_keypairs",
                "keypairs",
                rowid,
                true,
            )?;

            let mut keypairs = vec![];
            blob.read_to_end(&mut keypairs)?;
            blob.close()?;

            acc.push(Self { id, keypairs });

            crate::CryptoKeystoreResult::Ok(acc)
        })?;

        Ok(entities)
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        let mut conn = conn.conn().await;
        let transaction = conn.transaction()?;
        use rusqlite::OptionalExtension as _;
        let maybe_rowid = transaction
            .query_row(
                "SELECT rowid FROM mls_epoch_encryption_keypairs WHERE id_hex = ?",
                [id.as_hex_string().to_sql()?],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;

        if let Some(rowid) = maybe_rowid {
            let id = id.as_slice().to_vec();

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_epoch_encryption_keypairs",
                "keypairs",
                rowid,
                true,
            )?;

            let mut keypairs = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut keypairs)?;
            blob.close()?;

            Ok(Some(Self { id, keypairs }))
        } else {
            Ok(None)
        }
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let conn = conn.conn().await;
        conn.query_row("SELECT COUNT(*) FROM mls_epoch_encryption_keypairs", [], |r| r.get(0))
            .map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl EntityBase for MlsEpochEncryptionKeyPair {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "mls_epoch_encryption_keypairs";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsEpochEncryptionKeyPair
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::EpochEncryptionKeyPair(self)
    }
}

#[async_trait::async_trait]
impl EntityTransactionExt for MlsEpochEncryptionKeyPair {
    async fn save(&self, transaction: &TransactionWrapper<'_>) -> CryptoKeystoreResult<()> {
        Self::ConnectionType::check_buffer_size(self.keypairs.len())?;

        let zb_keypairs = rusqlite::blob::ZeroBlob(self.keypairs.len() as i32);

        // Use UPSERT (ON CONFLICT DO UPDATE)
        let sql = "
            INSERT INTO mls_epoch_encryption_keypairs (id_hex, keypairs)
            VALUES (?, ?)
            ON CONFLICT(id_hex) DO UPDATE SET keypairs = excluded.keypairs
            RETURNING rowid";

        let row_id: i64 =
            transaction.query_row(sql, [&self.id_hex().to_sql()?, &zb_keypairs.to_sql()?], |r| r.get(0))?;

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_epoch_encryption_keypairs",
            "keypairs",
            row_id,
            false,
        )?;

        blob.write_all(&self.keypairs)?;
        blob.close()?;

        Ok(())
    }
    async fn delete_fail_on_missing_id(
        transaction: &TransactionWrapper<'_>,
        id: StringEntityId<'_>,
    ) -> CryptoKeystoreResult<()> {
        let updated = transaction.execute(
            "DELETE FROM mls_epoch_encryption_keypairs WHERE id_hex = ?",
            [id.as_hex_string()],
        )?;

        if updated > 0 {
            Ok(())
        } else {
            Err(Self::to_missing_key_err_kind().into())
        }
    }
}
