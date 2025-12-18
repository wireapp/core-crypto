use std::{
    borrow::Borrow,
    io::{Read, Write},
    time::SystemTime,
};

use async_trait::async_trait;
use rusqlite::{OptionalExtension as _, Row, Transaction, params};

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind, Sha256Hash,
    connection::{DatabaseConnection, KeystoreDatabaseConnection, TransactionWrapper},
    entities::{
        Entity, EntityBase, EntityFindParams, EntityIdStringExt as _, EntityTransactionExt, StoredCredential,
        StringEntityId, count_helper, count_helper_tx, delete_helper,
    },
    traits::{
        BorrowPrimaryKey, Entity as NewEntity, EntityBase as NewEntityBase, EntityDatabaseMutation,
        EntityDeleteBorrowed, KeyType,
    },
};

impl StoredCredential {
    fn load(
        transaction: &Transaction<'_>,
        rowid: i64,
        created_at: u64,
        ciphersuite: u16,
    ) -> CryptoKeystoreResult<Self> {
        let mut blob = transaction.blob_open(
            rusqlite::MAIN_DB,
            <Self as EntityBase>::COLLECTION_NAME,
            "session_id",
            rowid,
            true,
        )?;
        let mut session_id = vec![];
        blob.read_to_end(&mut session_id)?;
        blob.close()?;

        let mut blob = transaction.blob_open(
            rusqlite::MAIN_DB,
            <Self as EntityBase>::COLLECTION_NAME,
            "credential",
            rowid,
            true,
        )?;
        let mut credential = vec![];
        blob.read_to_end(&mut credential)?;
        blob.close()?;

        let mut blob = transaction.blob_open(
            rusqlite::MAIN_DB,
            <Self as EntityBase>::COLLECTION_NAME,
            "private_key",
            rowid,
            true,
        )?;
        let mut private_key = vec![];
        blob.read_to_end(&mut private_key)?;
        blob.close()?;

        let mut blob = transaction.blob_open(
            rusqlite::MAIN_DB,
            <Self as EntityBase>::COLLECTION_NAME,
            "public_key",
            rowid,
            true,
        )?;
        let mut public_key = vec![];
        blob.read_to_end(&mut public_key)?;
        blob.close()?;

        Ok(Self {
            session_id,
            credential,
            ciphersuite,
            created_at,
            public_key,
            private_key,
        })
    }

    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        let session_id = row.get("session_id")?;
        let credential = row.get("credential")?;
        let created_at = row.get("created_at")?;
        let ciphersuite = row.get("ciphersuite")?;
        let public_key = row.get("public_key")?;
        let private_key = row.get("private_key")?;

        Ok(Self {
            session_id,
            credential,
            created_at,
            ciphersuite,
            public_key,
            private_key,
        })
    }
}

#[async_trait::async_trait]
impl Entity for StoredCredential {
    fn id_raw(&self) -> &[u8] {
        &self.public_key
    }

    async fn find_all(
        conn: &mut Self::ConnectionType,
        params: EntityFindParams,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let mut conn = conn.conn().await;
        let transaction = conn.transaction()?;
        let query: String = format!(
            "SELECT rowid, unixepoch(created_at), ciphersuite FROM mls_credentials {}",
            params.to_sql()
        );

        transaction
            .prepare_cached(&query)?
            .query_map([], |row| {
                let rowid = row.get(0)?;
                let created_at = row.get(1)?;
                let ciphersuite = row.get(2)?;
                Ok((rowid, created_at, ciphersuite))
            })?
            .map(|rowid_result| -> CryptoKeystoreResult<_> {
                let (rowid, created_at, ciphersuite) = rowid_result?;
                Self::load(&transaction, rowid, created_at, ciphersuite)
            })
            .collect()
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        let mut conn = conn.conn().await;
        let transaction = conn.transaction()?;
        use rusqlite::OptionalExtension as _;
        let public_key_sha256 = id.sha256();
        transaction
            .query_row(
                "SELECT rowid, unixepoch(created_at), ciphersuite FROM mls_credentials WHERE public_key_sha256 = ?",
                [public_key_sha256],
                |r| Ok((r.get::<_, i64>(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .map(|(rowid, created_at, ciphersuite)| Self::load(&transaction, rowid, created_at, ciphersuite))
            .transpose()
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let conn = conn.conn().await;
        conn.query_row("SELECT COUNT(*) FROM mls_credentials", [], |r| r.get(0))
            .map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl EntityBase for StoredCredential {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = u64;
    const COLLECTION_NAME: &'static str = "mls_credentials";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::StoredCredential
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::StoredCredential(self.into())
    }
}

#[async_trait::async_trait]
impl EntityTransactionExt for StoredCredential {
    async fn save(&self, transaction: &TransactionWrapper<'_>) -> crate::CryptoKeystoreResult<()> {
        Self::ConnectionType::check_buffer_size(self.session_id.len())?;
        Self::ConnectionType::check_buffer_size(self.credential.len())?;
        Self::ConnectionType::check_buffer_size(self.private_key.len())?;
        Self::ConnectionType::check_buffer_size(self.public_key.len())?;

        let pk_sha256 = self.id_sha256();
        let zb_pk = rusqlite::blob::ZeroBlob(self.public_key.len() as i32);
        let zb_id = rusqlite::blob::ZeroBlob(self.session_id.len() as i32);
        let zb_cred = rusqlite::blob::ZeroBlob(self.credential.len() as i32);
        let zb_sk = rusqlite::blob::ZeroBlob(self.private_key.len() as i32);

        use rusqlite::ToSql as _;
        let params: [rusqlite::types::ToSqlOutput; 7] = [
            pk_sha256.to_sql()?,
            zb_pk.to_sql()?,
            zb_id.to_sql()?,
            zb_cred.to_sql()?,
            self.created_at.to_sql()?,
            self.ciphersuite.to_sql()?,
            zb_sk.to_sql()?,
        ];

        let sql = "INSERT INTO mls_credentials (
                public_key_sha256,
                public_key,
                session_id,
                credential,
                created_at,
                ciphersuite,
                private_key
            ) VALUES (?, ?, ?, ?, datetime(?, 'unixepoch'), ?, ?)";

        transaction.execute(sql, params)?;
        let row_id = transaction.last_insert_rowid();

        let mut blob = transaction.blob_open(
            rusqlite::MAIN_DB,
            <Self as EntityBase>::COLLECTION_NAME,
            "session_id",
            row_id,
            false,
        )?;

        blob.write_all(&self.session_id)?;
        blob.close()?;

        let mut blob = transaction.blob_open(
            rusqlite::MAIN_DB,
            <Self as EntityBase>::COLLECTION_NAME,
            "credential",
            row_id,
            false,
        )?;

        blob.write_all(&self.credential)?;
        blob.close()?;

        let mut blob = transaction.blob_open(
            rusqlite::MAIN_DB,
            <Self as EntityBase>::COLLECTION_NAME,
            "public_key",
            row_id,
            false,
        )?;

        blob.write_all(&self.public_key)?;
        blob.close()?;

        let mut blob = transaction.blob_open(
            rusqlite::MAIN_DB,
            <Self as EntityBase>::COLLECTION_NAME,
            "private_key",
            row_id,
            false,
        )?;

        blob.write_all(&self.private_key)?;
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
        let public_key_sha256 = id.sha256();
        let updated = transaction.execute(
            "DELETE FROM mls_credentials WHERE public_key_sha256 = ?",
            [public_key_sha256],
        )?;

        if updated > 0 {
            Ok(())
        } else {
            Err(Self::to_missing_key_err_kind().into())
        }
    }
}

impl NewEntityBase for StoredCredential {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = u64;
    const COLLECTION_NAME: &'static str = "mls_credentials";

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::StoredCredential(self.into())
    }
}

#[async_trait]
impl NewEntity for StoredCredential {
    type PrimaryKey = Sha256Hash;

    fn primary_key(&self) -> Self::PrimaryKey {
        Sha256Hash::hash_from(&self.public_key)
    }

    async fn get(conn: &mut Self::ConnectionType, key: &Self::PrimaryKey) -> CryptoKeystoreResult<Option<Self>> {
        let conn = conn.conn().await;
        let mut stmt = conn.prepare_cached(
            "SELECT
                session_id,
                credential,
                unixepoch(created_at) AS created_at,
                ciphersuite,
                public_key,
                private_key
            FROM mls_credentials
            WHERE public_key_sha256 = ?",
        )?;

        stmt.query_row([key], Self::from_row).optional().map_err(Into::into)
    }

    async fn count(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<u32> {
        count_helper::<Self>(conn).await
    }

    async fn load_all(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Vec<Self>> {
        let conn = conn.conn().await;
        let mut stmt = conn.prepare_cached(
            "SELECT
                session_id,
                credential,
                unixepoch(created_at) AS created_at,
                ciphersuite,
                public_key,
                private_key
            FROM mls_credentials",
        )?;
        stmt.query_map([], Self::from_row)?
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }
}

#[async_trait]
impl<'a> EntityDatabaseMutation<'a> for StoredCredential {
    type Transaction = TransactionWrapper<'a>;

    async fn pre_save(&mut self) -> CryptoKeystoreResult<Self::AutoGeneratedFields> {
        let now = SystemTime::now();
        let created_at = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| CryptoKeystoreError::TimestampError)?
            .as_secs();
        self.created_at = created_at;
        Ok(created_at)
    }

    async fn save(&'a self, tx: &Self::Transaction) -> CryptoKeystoreResult<()> {
        // note not "or replace": a duplicate credential is an error and will produce one in sql
        let mut stmt = tx.prepare_cached(
            "INSERT INTO mls_credentials (
                public_key_sha256,
                public_key,
                session_id,
                credential,
                created_at,
                ciphersuite,
                private_key
            ) VALUES (?, ?, ?, ?, datetime(?, 'unixepoch'), ?, ?)",
        )?;
        stmt.execute(params![
            self.primary_key(),
            self.public_key,
            self.session_id,
            self.credential,
            self.created_at,
            self.ciphersuite,
            self.private_key,
        ])?;

        Ok(())
    }

    async fn count(tx: &Self::Transaction) -> CryptoKeystoreResult<u32> {
        count_helper_tx::<Self>(tx).await
    }

    async fn delete(tx: &Self::Transaction, id: &<Self as NewEntity>::PrimaryKey) -> CryptoKeystoreResult<bool> {
        delete_helper::<Self>(tx, "public_key_sha256", id).await
    }
}
