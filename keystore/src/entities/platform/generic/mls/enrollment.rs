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
    entities::{E2eiEnrollment, Entity, EntityBase, EntityFindParams, StringEntityId},
    CryptoKeystoreError, MissingKeyErrorKind,
};

impl Entity for E2eiEnrollment {
    fn id_raw(&self) -> &[u8] {
        &self.id[..]
    }
}

#[async_trait::async_trait(?Send)]
impl EntityBase for E2eiEnrollment {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::E2eiEnrollment
    }

    async fn find_all(
        _conn: &mut Self::ConnectionType,
        _params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        Err(CryptoKeystoreError::ImplementationError)
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        use rusqlite::OptionalExtension as _;
        use rusqlite::ToSql as _;

        Self::ConnectionType::check_buffer_size(self.content.len())?;

        let transaction = conn.transaction()?;
        let existing_rowid = transaction
            .query_row("SELECT rowid FROM e2ei_enrollment WHERE id = ?", [&self.id], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?;

        let row_id = if existing_rowid.is_some() {
            return Err(CryptoKeystoreError::AlreadyExists);
        } else {
            let zb = rusqlite::blob::ZeroBlob(self.content.len() as i32);
            let params: [rusqlite::types::ToSqlOutput; 2] = [self.id.to_sql()?, zb.to_sql()?];
            transaction.execute("INSERT INTO e2ei_enrollment (id, content) VALUES (?, ?)", params)?;
            transaction.last_insert_rowid()
        };

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
            .query_row("SELECT rowid FROM e2ei_enrollment WHERE id = ?", [id.as_bytes()], |r| {
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
                id: id.into_bytes(),
                content: buf,
            }))
        } else {
            Ok(None)
        }
    }

    async fn count(_conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        Err(CryptoKeystoreError::ImplementationError)
    }

    async fn delete(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<()> {
        let transaction = conn.transaction()?;
        let len = ids.len();
        let mut updated = 0;
        for id in ids {
            updated += transaction.execute("DELETE FROM e2ei_enrollment WHERE id = ?", [id.as_bytes()])?;
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