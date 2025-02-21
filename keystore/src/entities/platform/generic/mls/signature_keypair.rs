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
    CryptoKeystoreResult, MissingKeyErrorKind,
    connection::{DatabaseConnection, KeystoreDatabaseConnection, TransactionWrapper},
    entities::{Entity, EntityBase, EntityFindParams, EntityTransactionExt, MlsSignatureKeyPair, StringEntityId},
};
use std::io::{Read, Write};

#[async_trait::async_trait]
impl Entity for MlsSignatureKeyPair {
    fn id_raw(&self) -> &[u8] {
        self.pk.as_slice()
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let mut conn = conn.conn().await;
        let transaction = conn.transaction()?;
        let query: String = format!(
            "SELECT rowid, signature_scheme FROM mls_signature_keypairs {}",
            params.to_sql()
        );

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let entities = rows.try_fold(Vec::new(), |mut acc, rowid_result| {
            use std::io::Read as _;
            let (rowid, signature_scheme) = rowid_result?;

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_signature_keypairs",
                "keypair",
                rowid,
                true,
            )?;

            let mut keypair = vec![];
            blob.read_to_end(&mut keypair)?;
            blob.close()?;

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_signature_keypairs",
                "pk",
                rowid,
                true,
            )?;

            let mut pk = vec![];
            blob.read_to_end(&mut pk)?;
            blob.close()?;

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_signature_keypairs",
                "credential_id",
                rowid,
                true,
            )?;

            let mut credential_id = vec![];
            blob.read_to_end(&mut credential_id)?;
            blob.close()?;

            acc.push(Self {
                signature_scheme,
                keypair,
                pk,
                credential_id,
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
                "SELECT rowid, signature_scheme FROM mls_signature_keypairs WHERE pk = ?",
                [id.as_slice()],
                |r| Ok((r.get::<_, i64>(0)?, r.get(1)?)),
            )
            .optional()?;

        if let Some((rowid, signature_scheme)) = maybe_rowid {
            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_signature_keypairs",
                "pk",
                rowid,
                true,
            )?;

            let mut pk = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut pk)?;
            blob.close()?;

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_signature_keypairs",
                "keypair",
                rowid,
                true,
            )?;

            let mut keypair = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut keypair)?;
            blob.close()?;

            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_signature_keypairs",
                "credential_id",
                rowid,
                true,
            )?;

            let mut credential_id = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut credential_id)?;
            blob.close()?;

            Ok(Some(Self {
                signature_scheme,
                pk,
                keypair,
                credential_id,
            }))
        } else {
            Ok(None)
        }
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let conn = conn.conn().await;
        conn.query_row("SELECT COUNT(*) FROM mls_signature_keypairs", [], |r| r.get(0))
            .map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl EntityBase for MlsSignatureKeyPair {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "mls_signature_keypairs";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsSignatureKeyPair
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::SignatureKeyPair(self)
    }
}

#[async_trait::async_trait]
impl EntityTransactionExt for MlsSignatureKeyPair {
    async fn save(&self, transaction: &TransactionWrapper<'_>) -> CryptoKeystoreResult<()> {
        Self::ConnectionType::check_buffer_size(self.keypair.len())?;
        Self::ConnectionType::check_buffer_size(self.pk.len())?;
        Self::ConnectionType::check_buffer_size(self.credential_id.len())?;

        let zb_pk = rusqlite::blob::ZeroBlob(self.pk.len() as i32);
        let zb_keypair = rusqlite::blob::ZeroBlob(self.keypair.len() as i32);
        let zb_cred = rusqlite::blob::ZeroBlob(self.credential_id.len() as i32);

        use rusqlite::ToSql as _;
        let params: [rusqlite::types::ToSqlOutput; 4] = [
            self.signature_scheme.to_sql()?,
            zb_pk.to_sql()?,
            zb_keypair.to_sql()?,
            zb_cred.to_sql()?,
        ];

        let sql =
            "INSERT INTO mls_signature_keypairs (signature_scheme, pk, keypair, credential_id) VALUES (?, ?, ?, ?)";
        transaction.execute(sql, params)?;
        let row_id = transaction.last_insert_rowid();

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_signature_keypairs",
            "pk",
            row_id,
            false,
        )?;

        blob.write_all(&self.pk)?;
        blob.close()?;

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_signature_keypairs",
            "keypair",
            row_id,
            false,
        )?;

        blob.write_all(&self.keypair)?;
        blob.close()?;

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_signature_keypairs",
            "credential_id",
            row_id,
            false,
        )?;

        blob.write_all(&self.credential_id)?;
        blob.close()?;

        Ok(())
    }

    async fn delete_fail_on_missing_id(
        transaction: &TransactionWrapper<'_>,
        id: StringEntityId<'_>,
    ) -> CryptoKeystoreResult<()> {
        let updated = transaction.execute("DELETE FROM mls_signature_keypairs WHERE pk = ?", [id.as_slice()])?;

        if updated > 0 {
            Ok(())
        } else {
            Err(Self::to_missing_key_err_kind().into())
        }
    }
}
