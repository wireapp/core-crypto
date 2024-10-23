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
    connection::{DatabaseConnection, KeystoreDatabaseConnection, TransactionWrapper},
    entities::{E2eiEnrollment, Entity, EntityBase, EntityFindParams, EntityTransactionExt, StringEntityId},
    CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind,
};

impl Entity for E2eiEnrollment {
    fn id_raw(&self) -> &[u8] {
        &self.id[..]
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityBase for E2eiEnrollment {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "e2ei_enrollment";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::E2eiEnrollment
    }

    fn to_transaction_entity(self) -> crate::transaction::Entity {
        crate::transaction::Entity::E2eiEnrollment(self)
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let transaction = conn.transaction()?;
        let query: String = format!("SELECT rowid, id FROM e2ei_enrollment {}", params.to_sql());

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let entities = rows.try_fold(Vec::new(), |mut acc, row_res| {
            use std::io::Read as _;
            let (rowid, id) = row_res?;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "e2ei_enrollment", "content", rowid, false)?;

            let mut content = vec![];
            blob.read_to_end(&mut content)?;
            blob.close()?;

            acc.push(Self { id, content });

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
        let mut row_id = transaction
            .query_row("SELECT rowid FROM e2ei_enrollment WHERE id = ?", [id.as_slice()], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?;

        if let Some(rowid) = row_id.take() {
            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "e2ei_enrollment", "content", rowid, true)?;
            use std::io::Read as _;
            let mut buf = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut buf)?;
            blob.close()?;

            transaction.commit()?;

            Ok(Some(Self {
                id: id.to_bytes(),
                content: buf,
            }))
        } else {
            Ok(None)
        }
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        Ok(conn.query_row("SELECT COUNT(*) FROM e2ei_enrollment", [], |r| r.get(0))?)
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityTransactionExt for E2eiEnrollment {
    async fn save(&self, transaction: &TransactionWrapper<'_>) -> CryptoKeystoreResult<()> {
        use rusqlite::ToSql as _;

        Self::ConnectionType::check_buffer_size(self.content.len())?;

        // Attempt to insert directly, handling conflicts as errors
        let zb = rusqlite::blob::ZeroBlob(self.content.len() as i32);
        let sql = "INSERT INTO e2ei_enrollment (id, content) VALUES (?, ?) RETURNING rowid";

        let row_id_result: Result<i64, rusqlite::Error> =
            transaction.query_row(sql, [self.id.to_sql()?, zb.to_sql()?], |r| r.get(0));

        match row_id_result {
            Ok(row_id) => {
                // Open a blob to write the content data
                let mut blob = transaction.blob_open(
                    rusqlite::DatabaseName::Main,
                    "e2ei_enrollment",
                    "content",
                    row_id,
                    false,
                )?;

                use std::io::Write as _;
                blob.write_all(&self.content)?;
                blob.close()?;

                Ok(())
            }
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE => {
                Err(CryptoKeystoreError::AlreadyExists)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn delete(transaction: &TransactionWrapper<'_>, id: StringEntityId<'_>) -> CryptoKeystoreResult<()> {
        let updated = transaction.execute("DELETE FROM e2ei_enrollment WHERE id = ?", [id.as_slice()])?;

        if updated > 0 {
            Ok(())
        } else {
            Err(Self::to_missing_key_err_kind().into())
        }
    }
}
