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
    entities::{EntityIdStringExt, EntityMlsExt},
    CryptoKeystoreResult,
};
use crate::{
    connection::{DatabaseConnection, KeystoreDatabaseConnection},
    entities::{Entity, EntityBase, EntityFindParams, MlsEncryptionKeyPair, StringEntityId},
    MissingKeyErrorKind,
};
use std::io::{Read, Write};

impl Entity for MlsEncryptionKeyPair {
    fn id_raw(&self) -> &[u8] {
        self.pk.as_slice()
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityBase for MlsEncryptionKeyPair {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "mls_encryption_keypairs";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsEncryptionKeyPair
    }

    fn to_transaction_entity(self) -> crate::transaction::Entity {
        crate::transaction::Entity::EncryptionKeyPair(self)
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let transaction = conn.transaction()?;
        let query: String = format!("SELECT rowid FROM mls_encryption_keypairs {}", params.to_sql());

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| r.get(0))?;
        let entities = rows.try_fold(Vec::new(), |mut acc, row_result| {
            use std::io::Read as _;
            let rowid = row_result?;

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_encryption_keypairs",
                "sk",
                rowid,
                true,
            )?;

            let mut sk = vec![];
            blob.read_to_end(&mut sk)?;
            blob.close()?;

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_encryption_keypairs",
                "pk",
                rowid,
                true,
            )?;

            let mut pk = vec![];
            blob.read_to_end(&mut pk)?;
            blob.close()?;

            acc.push(Self { sk, pk });

            crate::CryptoKeystoreResult::Ok(acc)
        })?;

        Ok(entities)
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        let transaction = conn.transaction()?;
        use rusqlite::OptionalExtension as _;
        let maybe_rowid = transaction
            .query_row(
                "SELECT rowid FROM mls_encryption_keypairs WHERE pk_sha256 = ?",
                [id.sha256()],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;

        if let Some(rowid) = maybe_rowid {
            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_encryption_keypairs",
                "pk",
                rowid,
                true,
            )?;

            let mut pk = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut pk)?;
            blob.close()?;

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_encryption_keypairs",
                "sk",
                rowid,
                true,
            )?;

            let mut sk = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut sk)?;
            blob.close()?;

            Ok(Some(Self { pk, sk }))
        } else {
            Ok(None)
        }
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        Ok(conn.query_row("SELECT COUNT(*) FROM mls_encryption_keypairs", [], |r| r.get(0))?)
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityMlsExt for MlsEncryptionKeyPair {
    async fn mls_save(&self, transaction: &TransactionWrapper<'_>) -> CryptoKeystoreResult<()> {
        use rusqlite::ToSql as _;

        Self::ConnectionType::check_buffer_size(self.sk.len())?;
        Self::ConnectionType::check_buffer_size(self.pk.len())?;

        let zb_pk = rusqlite::blob::ZeroBlob(self.pk.len() as i32);
        let zb_sk = rusqlite::blob::ZeroBlob(self.sk.len() as i32);

        // Use UPSERT (ON CONFLICT DO UPDATE)
        let sql = "
                INSERT INTO mls_encryption_keypairs (pk_sha256, pk, sk)
                VALUES (?, ?, ?)
                ON CONFLICT(pk_sha256) DO UPDATE SET pk = excluded.pk, sk = excluded.sk
                RETURNING rowid";

        let row_id: i64 = transaction.query_row(
            sql,
            [&self.id_sha256().to_sql()?, &zb_pk.to_sql()?, &zb_sk.to_sql()?],
            |r| r.get(0),
        )?;

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_encryption_keypairs",
            "pk",
            row_id,
            false,
        )?;

        blob.write_all(&self.pk)?;
        blob.close()?;

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_encryption_keypairs",
            "sk",
            row_id,
            false,
        )?;

        blob.write_all(&self.sk)?;
        blob.close()?;

        Ok(())
    }

    async fn mls_delete(transaction: &TransactionWrapper<'_>, id: StringEntityId<'_>) -> CryptoKeystoreResult<()> {
        let updated = transaction.execute("DELETE FROM mls_encryption_keypairs WHERE pk_sha256 = ?", [id.sha256()])?;

        if updated > 0 {
            Ok(())
        } else {
            Err(Self::to_missing_key_err_kind().into())
        }
    }
}
