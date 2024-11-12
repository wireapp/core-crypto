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

use crate::connection::TransactionWrapper;
use crate::entities::{EntityFindParams, EntityTransactionExt, ProteusIdentity, StringEntityId};
use crate::CryptoKeystoreError;
use crate::{
    connection::KeystoreDatabaseConnection,
    entities::{Entity, EntityBase},
    MissingKeyErrorKind,
};
use rusqlite::OptionalExtension;

#[async_trait::async_trait]
impl Entity for ProteusIdentity {
    fn id_raw(&self) -> &[u8] {
        b"1"
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        _params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let mut res = vec![];
        if let Some(identity) = Self::find_one(conn, &StringEntityId::default()).await? {
            res.push(identity);
        }

        Ok(res)
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        _id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        let transaction = conn.transaction()?;

        let mut row_id: Option<i64> = transaction
            .query_row(
                "SELECT rowid FROM proteus_identities ORDER BY rowid ASC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;

        let row_id = if let Some(rowid) = row_id.take() {
            rowid
        } else {
            return Ok(None);
        };

        use std::io::Read as _;
        let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "proteus_identities", "pk", row_id, true)?;
        if blob.len() != Self::PK_KEY_SIZE {
            return Err(CryptoKeystoreError::InvalidKeySize {
                expected: Self::PK_KEY_SIZE,
                actual: blob.len(),
                key: "pk",
            });
        }
        let mut pk = Vec::with_capacity(blob.len());
        blob.read_to_end(&mut pk)?;
        blob.close()?;

        let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "proteus_identities", "sk", row_id, true)?;
        if blob.len() != Self::SK_KEY_SIZE {
            return Err(CryptoKeystoreError::InvalidKeySize {
                expected: Self::SK_KEY_SIZE,
                actual: blob.len(),
                key: "sk",
            });
        }
        let mut sk = Vec::with_capacity(blob.len());
        blob.read_to_end(&mut sk)?;
        blob.close()?;

        Ok(Some(Self { pk, sk }))
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let count = conn.query_row("SELECT COUNT(*) FROM proteus_identities", [], |r| r.get(0))?;
        // This should always be less or equal 1
        debug_assert!(count <= 1);
        Ok(count)
    }
}

#[async_trait::async_trait]
impl EntityBase for ProteusIdentity {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "proteus_identities";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::ProteusIdentity
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::ProteusIdentity(self)
    }
}

#[async_trait::async_trait]
impl EntityTransactionExt for ProteusIdentity {
    async fn save(&self, transaction: &TransactionWrapper<'_>) -> crate::CryptoKeystoreResult<()> {
        use rusqlite::ToSql as _;
        transaction.execute(
            "INSERT INTO proteus_identities (sk, pk) VALUES (?, ?)",
            [
                rusqlite::blob::ZeroBlob(self.sk.len() as i32).to_sql()?,
                rusqlite::blob::ZeroBlob(self.pk.len() as i32).to_sql()?,
            ],
        )?;

        let row_id = transaction.last_insert_rowid();

        use std::io::Write as _;
        let mut blob =
            transaction.blob_open(rusqlite::DatabaseName::Main, "proteus_identities", "sk", row_id, false)?;
        blob.write_all(&self.sk)?;
        blob.close()?;

        let mut blob =
            transaction.blob_open(rusqlite::DatabaseName::Main, "proteus_identities", "pk", row_id, false)?;
        blob.write_all(&self.pk)?;
        blob.close()?;

        Ok(())
    }

    async fn delete_fail_on_missing_id(
        transaction: &TransactionWrapper<'_>,
        _id: StringEntityId<'_>,
    ) -> crate::CryptoKeystoreResult<()> {
        let row_id = transaction.query_row(
            "SELECT rowid FROM proteus_identities ORDER BY rowid ASC LIMIT 1",
            [],
            |r| r.get::<_, i64>(0),
        )?;
        use rusqlite::ToSql as _;
        transaction.execute("DELETE FROM proteus_identities WHERE rowid = ?", [row_id.to_sql()?])?;

        Ok(())
    }
}
