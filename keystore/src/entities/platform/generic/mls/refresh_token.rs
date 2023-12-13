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

use std::io::Write;

use rusqlite::ToSql;

use crate::{
    connection::{DatabaseConnection, KeystoreDatabaseConnection},
    entities::MlsRefreshTokenExt,
    entities::{Entity, EntityBase, EntityFindParams, RefreshTokenEntity, StringEntityId},
    CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind,
};

const ID: usize = 0;

impl Entity for RefreshTokenEntity {
    fn id_raw(&self) -> &[u8] {
        &[0]
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl MlsRefreshTokenExt for RefreshTokenEntity {
    async fn find_unique(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Self> {
        let transaction = conn.transaction()?;
        use rusqlite::OptionalExtension as _;

        let maybe_content = transaction
            .query_row("SELECT content FROM e2ei_refresh_token WHERE id = ?", [ID], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()?;

        if let Some(content) = maybe_content {
            Ok(Self { content })
        } else {
            Err(CryptoKeystoreError::NotFound("refresh token", "".to_string()))
        }
    }

    async fn replace(&self, conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<()> {
        Self::ConnectionType::check_buffer_size(self.content.len())?;
        let zb_content = rusqlite::blob::ZeroBlob(self.content.len() as i32);

        let transaction = conn.transaction()?;

        let params: [rusqlite::types::ToSqlOutput; 2] = [ID.to_sql()?, zb_content.to_sql()?];

        transaction.execute(
            "INSERT OR REPLACE INTO e2ei_refresh_token (id, content) VALUES (?, ?)",
            params,
        )?;
        let row_id = transaction.last_insert_rowid();

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "e2ei_refresh_token",
            "content",
            row_id,
            false,
        )?;

        blob.write_all(&self.content)?;
        blob.close()?;

        transaction.commit()?;

        Ok(())
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityBase for RefreshTokenEntity {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::RefreshToken
    }

    async fn find_all(_conn: &mut Self::ConnectionType, _params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>> {
        return Err(CryptoKeystoreError::NotImplemented);
    }

    async fn save(&self, _conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<()> {
        return Err(CryptoKeystoreError::NotImplemented);
    }

    async fn find_one(_conn: &mut Self::ConnectionType, _id: &StringEntityId) -> CryptoKeystoreResult<Option<Self>> {
        return Err(CryptoKeystoreError::NotImplemented);
    }

    async fn count(_conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<usize> {
        return Err(CryptoKeystoreError::NotImplemented);
    }

    async fn delete(_conn: &mut Self::ConnectionType, _ids: &[StringEntityId]) -> CryptoKeystoreResult<()> {
        return Err(CryptoKeystoreError::NotImplemented);
    }
}