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
    CryptoKeystoreResult,
    connection::TransactionWrapper,
    entities::{EntityIdStringExt, EntityTransactionExt},
};
use crate::{
    MissingKeyErrorKind,
    connection::{DatabaseConnection, KeystoreDatabaseConnection},
    entities::{Entity, EntityBase, EntityFindParams, MlsHpkePrivateKey, StringEntityId},
};
use rusqlite::ToSql;
use std::io::{Read, Write};

#[async_trait::async_trait]
impl Entity for MlsHpkePrivateKey {
    fn id_raw(&self) -> &[u8] {
        self.pk.as_slice()
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let mut conn = conn.conn().await;
        let transaction = conn.transaction()?;
        let query: String = format!("SELECT rowid FROM mls_hpke_private_keys {}", params.to_sql());

        let mut stmt = transaction.prepare_cached(&query)?;
        let mut rows = stmt.query_map([], |r| r.get(0))?;
        let entities = rows.try_fold(Vec::new(), |mut acc, rowid_result| {
            use std::io::Read as _;
            let rowid = rowid_result?;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_hpke_private_keys", "sk", rowid, true)?;

            let mut sk = vec![];
            blob.read_to_end(&mut sk)?;
            blob.close()?;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_hpke_private_keys", "pk", rowid, true)?;

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
        let mut conn = conn.conn().await;
        let transaction = conn.transaction()?;
        use rusqlite::OptionalExtension as _;
        let maybe_rowid = transaction
            .query_row(
                "SELECT rowid FROM mls_hpke_private_keys WHERE pk_sha256 = ?",
                [id.sha256()],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;

        if let Some(rowid) = maybe_rowid {
            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_hpke_private_keys", "pk", rowid, true)?;

            let mut pk = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut pk)?;
            blob.close()?;

            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_hpke_private_keys", "sk", rowid, true)?;

            let mut sk = Vec::with_capacity(blob.len());
            blob.read_to_end(&mut sk)?;
            blob.close()?;

            Ok(Some(Self { pk, sk }))
        } else {
            Ok(None)
        }
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let conn = conn.conn().await;
        conn.query_row("SELECT COUNT(*) FROM mls_hpke_private_keys", [], |r| r.get(0))
            .map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl EntityBase for MlsHpkePrivateKey {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "mls_hpke_private_keys";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsHpkePrivateKey
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::HpkePrivateKey(self)
    }
}

#[async_trait::async_trait]
impl EntityTransactionExt for MlsHpkePrivateKey {
    async fn save(&self, transaction: &TransactionWrapper<'_>) -> CryptoKeystoreResult<()> {
        Self::ConnectionType::check_buffer_size(self.sk.len())?;
        Self::ConnectionType::check_buffer_size(self.pk.len())?;
        let zb_pk = rusqlite::blob::ZeroBlob(self.pk.len() as i32);
        let zb_sk = rusqlite::blob::ZeroBlob(self.sk.len() as i32);

        // Use UPSERT (ON CONFLICT DO UPDATE)
        let sql = "
                INSERT INTO mls_hpke_private_keys (pk_sha256, pk, sk)
                VALUES (?, ?, ?)
                ON CONFLICT(pk_sha256) DO UPDATE SET pk = excluded.pk, sk = excluded.sk
                RETURNING rowid";

        // Execute the UPSERT and get the row_id of the affected row
        let row_id: i64 = transaction.query_row(
            sql,
            [&self.id_sha256().to_sql()?, &zb_pk.to_sql()?, &zb_sk.to_sql()?],
            |r| r.get(0),
        )?;

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_hpke_private_keys",
            "pk",
            row_id,
            false,
        )?;

        blob.write_all(&self.pk)?;
        blob.close()?;

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_hpke_private_keys",
            "sk",
            row_id,
            false,
        )?;

        blob.write_all(&self.sk)?;
        blob.close()?;

        Ok(())
    }

    async fn delete_fail_on_missing_id(
        transaction: &TransactionWrapper<'_>,
        id: StringEntityId<'_>,
    ) -> CryptoKeystoreResult<()> {
        let updated = transaction.execute("DELETE FROM mls_hpke_private_keys WHERE pk_sha256 = ?", [id.sha256()])?;

        if updated > 0 {
            Ok(())
        } else {
            Err(Self::to_missing_key_err_kind().into())
        }
    }
}
