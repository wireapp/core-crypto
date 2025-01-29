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
    entities::{EntityTransactionExt, MlsCredentialExt},
    CryptoKeystoreError,
};
use crate::{
    connection::{DatabaseConnection, KeystoreDatabaseConnection},
    entities::{Entity, EntityBase, EntityFindParams, MlsCredential, StringEntityId},
    CryptoKeystoreResult, MissingKeyErrorKind,
};
use std::{
    io::{Read, Write},
    time::SystemTime,
};

#[async_trait::async_trait]
impl Entity for MlsCredential {
    fn id_raw(&self) -> &[u8] {
        self.id.as_slice()
    }

    fn merge_key(&self) -> Vec<u8> {
        // Credentials are unique by id and type, the type is contained in the bytes
        // inside self.credential.
        self.id_raw().iter().chain(self.credential.iter()).cloned().collect()
    }
    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let mut conn = conn.conn().await;
        let transaction = conn.transaction()?;
        let query: String = format!(
            "SELECT rowid, unixepoch(created_at) FROM mls_credentials {}",
            params.to_sql()
        );

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let entities = rows.try_fold(Vec::new(), |mut acc, rowid_result| {
            use std::io::Read as _;
            let (rowid, created_at) = rowid_result?;

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

            acc.push(Self {
                id,
                credential,
                created_at,
            });

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
                "SELECT rowid, unixepoch(created_at) FROM mls_credentials WHERE id = ?",
                [id.as_slice()],
                |r| Ok((r.get::<_, i64>(0)?, r.get(1)?)),
            )
            .optional()?;

        if let Some((rowid, created_at)) = maybe_rowid {
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
                created_at,
            }))
        } else {
            Ok(None)
        }
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let conn = conn.conn().await;
        conn.query_row("SELECT COUNT(*) FROM mls_credentials", [], |r| r.get(0))
            .map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl EntityBase for MlsCredential {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = u64;
    const COLLECTION_NAME: &'static str = "mls_credentials";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsCredential
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::MlsCredential(self)
    }
}

#[async_trait::async_trait]
impl EntityTransactionExt for MlsCredential {
    async fn save(&self, transaction: &TransactionWrapper<'_>) -> crate::CryptoKeystoreResult<()> {
        Self::ConnectionType::check_buffer_size(self.id.len())?;
        Self::ConnectionType::check_buffer_size(self.credential.len())?;

        let zb_id = rusqlite::blob::ZeroBlob(self.id.len() as i32);
        let zb_cred = rusqlite::blob::ZeroBlob(self.credential.len() as i32);

        use rusqlite::ToSql as _;
        let params: [rusqlite::types::ToSqlOutput; 3] = [zb_id.to_sql()?, zb_cred.to_sql()?, self.created_at.to_sql()?];

        let sql = "INSERT INTO mls_credentials (id, credential, created_at) VALUES (?, ?, datetime(?, 'unixepoch'))";
        transaction.execute(sql, params)?;
        let row_id = transaction.last_insert_rowid();

        let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_credentials", "id", row_id, false)?;

        blob.write_all(&self.id)?;
        blob.close()?;

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_credentials",
            "credential",
            row_id,
            false,
        )?;

        blob.write_all(&self.credential)?;
        blob.close()?;

        Ok(())
    }

    async fn pre_save<'a>(&'a mut self) -> CryptoKeystoreResult<Self::AutoGeneratedFields> {
        let now = SystemTime::now();
        let created_at = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| CryptoKeystoreError::TimestampError)?
            .as_secs();
        self.created_at = created_at;
        Ok(created_at)
    }

    async fn delete_fail_on_missing_id(
        transaction: &TransactionWrapper<'_>,
        id: StringEntityId<'_>,
    ) -> crate::CryptoKeystoreResult<()> {
        let updated = transaction.execute("DELETE FROM mls_credentials WHERE id = ?", [id.as_slice()])?;

        if updated > 0 {
            Ok(())
        } else {
            Err(Self::to_missing_key_err_kind().into())
        }
    }
}

#[async_trait::async_trait]
impl MlsCredentialExt for MlsCredential {
    async fn delete_by_credential(
        transaction: &TransactionWrapper<'_>,
        credential: Vec<u8>,
    ) -> CryptoKeystoreResult<()> {
        // we do not have an index on this since we'll never have more than a handful of credentials in the sotre (~40 max)
        transaction.execute("DELETE FROM mls_credentials WHERE credential = ?", [&credential[..]])?;
        Ok(())
    }
}
