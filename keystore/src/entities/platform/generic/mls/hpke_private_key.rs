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
    entities::{Entity, EntityBase, EntityFindParams, MlsHpkePrivateKey, StringEntityId},
    MissingKeyErrorKind,
};
use std::io::{Read, Write};

impl Entity for MlsHpkePrivateKey {
    fn id_raw(&self) -> &[u8] {
        self.pk.as_slice()
    }
}

#[async_trait::async_trait(?Send)]
impl EntityBase for MlsHpkePrivateKey {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsHpkePrivateKey
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
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

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        use rusqlite::OptionalExtension as _;

        Self::ConnectionType::check_buffer_size(self.sk.len())?;
        Self::ConnectionType::check_buffer_size(self.pk.len())?;

        let zb_pk = rusqlite::blob::ZeroBlob(self.pk.len() as i32);
        let zb_sk = rusqlite::blob::ZeroBlob(self.sk.len() as i32);

        let transaction = conn.transaction()?;
        let mut existing_rowid = transaction
            .query_row(
                "SELECT rowid FROM mls_hpke_private_keys WHERE pk = ?",
                [&self.pk],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;

        let row_id = if let Some(rowid) = existing_rowid.take() {
            use rusqlite::ToSql as _;
            transaction.execute(
                "UPDATE mls_hpke_private_keys SET pk = ?, sk = ? WHERE rowid = ?",
                [&zb_pk.to_sql()?, &zb_sk.to_sql()?, &rowid.to_sql()?],
            )?;
            rowid
        } else {
            use rusqlite::ToSql as _;
            let params: [rusqlite::types::ToSqlOutput; 2] = [zb_pk.to_sql()?, zb_sk.to_sql()?];

            transaction.execute("INSERT INTO mls_hpke_private_keys (pk, sk) VALUES (?, ?)", params)?;
            transaction.last_insert_rowid()
        };

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

        transaction.commit()?;

        Ok(())
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        let transaction = conn.transaction()?;
        use rusqlite::OptionalExtension as _;
        let maybe_rowid = transaction
            .query_row(
                "SELECT rowid FROM mls_hpke_private_keys WHERE pk = ?",
                [id.as_slice()],
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
        Ok(conn.query_row("SELECT COUNT(*) FROM mls_hpke_private_keys", [], |r| r.get(0))?)
    }

    async fn delete(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<()> {
        let transaction = conn.transaction()?;
        let len = ids.len();
        let mut updated = 0;
        for id in ids {
            updated += transaction.execute("DELETE FROM mls_hpke_private_keys WHERE pk = ?", [id.as_slice()])?;
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