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

use crate::connection::DatabaseConnection;
use crate::entities::EntityFindParams;
use crate::entities::MlsIdentity;
use crate::entities::MlsIdentityExt;
use crate::entities::StringEntityId;
use crate::CryptoKeystoreResult;
use crate::{
    connection::KeystoreDatabaseConnection,
    entities::{Entity, EntityBase},
    MissingKeyErrorKind,
};

impl Entity for MlsIdentity {
    fn id_raw(&self) -> &[u8] {
        self.id.as_bytes()
    }
}

#[async_trait::async_trait(?Send)]
impl EntityBase for MlsIdentity {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsIdentityBundle
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let transaction = conn.transaction()?;
        let query: String = format!("SELECT rowid, id FROM mls_identities {}", params.to_sql());

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let entities = rows.try_fold(Vec::new(), |mut acc, rowid_result| {
            use std::io::Read as _;
            let (rowid, id) = rowid_result?;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_identities", "signature", rowid, true)?;

            let mut signature = vec![];
            blob.read_to_end(&mut signature)?;
            blob.close()?;

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_identities",
                "credential",
                rowid,
                true,
            )?;

            let mut credential = vec![];
            blob.read_to_end(&mut credential)?;
            blob.close()?;

            acc.push(Self {
                id,
                signature,
                credential,
            });

            crate::CryptoKeystoreResult::Ok(acc)
        })?;

        Ok(entities)
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        use rusqlite::OptionalExtension as _;

        let signature = &self.signature;
        let credential = &self.credential;

        Self::ConnectionType::check_buffer_size(signature.len())?;
        Self::ConnectionType::check_buffer_size(credential.len())?;

        let zb_sig = rusqlite::blob::ZeroBlob(signature.len() as i32);
        let zb_cred = rusqlite::blob::ZeroBlob(credential.len() as i32);

        let transaction = conn.transaction()?;
        let mut existing_rowid = transaction
            .query_row("SELECT rowid FROM mls_identities WHERE id = ?", [&self.id], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?;

        let row_id = if let Some(rowid) = existing_rowid.take() {
            let sig_zb = rusqlite::blob::ZeroBlob(self.signature.len() as i32);
            let cred_zb = rusqlite::blob::ZeroBlob(self.credential.len() as i32);

            use rusqlite::ToSql as _;
            transaction.execute(
                "UPDATE mls_identities SET signature = ?, credential = ? WHERE id = ?",
                [&sig_zb.to_sql()?, &cred_zb.to_sql()?, &self.id.to_sql()?],
            )?;
            rowid
        } else {
            use rusqlite::ToSql as _;
            let params: [rusqlite::types::ToSqlOutput; 3] = [self.id.to_sql()?, zb_sig.to_sql()?, zb_cred.to_sql()?];

            transaction.execute(
                "INSERT INTO mls_identities (id, signature, credential) VALUES (?, ?, ?)",
                params,
            )?;
            transaction.last_insert_rowid()
        };

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_identities",
            "signature",
            row_id,
            false,
        )?;

        use std::io::Write as _;
        blob.write_all(signature)?;
        blob.close()?;

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_identities",
            "credential",
            row_id,
            false,
        )?;

        blob.write_all(credential)?;
        blob.close()?;

        transaction.commit()?;

        Ok(())
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        let id: String = id.try_into()?;
        let transaction = conn.transaction()?;
        use rusqlite::OptionalExtension as _;
        let maybe_rowid = transaction
            .query_row("SELECT rowid FROM mls_identities WHERE id = ?", [&id], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?;

        if let Some(rowid) = maybe_rowid {
            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_identities", "signature", rowid, true)?;

            use std::io::Read as _;
            let mut signature = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut signature)?;
            blob.close()?;

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_identities",
                "credential",
                rowid,
                true,
            )?;

            let mut credential = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut credential)?;
            blob.close()?;

            Ok(Some(Self {
                id,
                signature,
                credential,
            }))
        } else {
            Ok(None)
        }
    }

    // async fn find_many(
    //     conn: &mut Self::ConnectionType,
    //     ids: &[StringEntityId],
    // ) -> crate::CryptoKeystoreResult<Vec<Self>> {
    //     let mut stmt = conn.prepare_cached("SELECT id FROM mls_identities ORDER BY rowid")?;

    //     unimplemented!("There is only one identity within a keystore, so this won't be implemented")
    // }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        Ok(conn.query_row("SELECT COUNT(*) FROM mls_identities", [], |r| r.get(0))?)
    }

    async fn delete(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<()> {
        let transaction = conn.transaction()?;
        let len = ids.len();
        let mut updated = 0;
        for id in ids {
            let id: String = id.try_into()?;
            updated += transaction.execute("DELETE FROM mls_identities WHERE id = ?", [id])?;
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

#[async_trait::async_trait(?Send)]
impl MlsIdentityExt for MlsIdentity {
    async fn find_by_signature(
        conn: &mut Self::ConnectionType,
        signature: &[u8],
    ) -> CryptoKeystoreResult<Option<Self>> {
        let transaction = conn.transaction()?;
        use rusqlite::OptionalExtension as _;
        let maybe_rowid = transaction
            .query_row(
                "SELECT rowid, id FROM mls_identities WHERE signature = ?",
                [&signature],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?;

        if let Some((rowid, id)) = maybe_rowid {
            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_identities", "signature", rowid, true)?;

            use std::io::Read as _;
            let mut signature = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut signature)?;
            blob.close()?;

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_identities",
                "credential",
                rowid,
                true,
            )?;

            let mut credential = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut credential)?;
            blob.close()?;

            Ok(Some(Self {
                id,
                signature,
                credential,
            }))
        } else {
            Ok(None)
        }
    }

    async fn delete_by_signature(conn: &mut Self::ConnectionType, signature: &[u8]) -> CryptoKeystoreResult<()> {
        let _ = conn.execute("DELETE FROM mls_identities WHERE signature = ?", [&signature])?;
        Ok(())
    }
}
