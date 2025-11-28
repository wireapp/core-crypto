use std::io::{Read, Write};

use rusqlite::Transaction;

use crate::{
    CryptoKeystoreResult, MissingKeyErrorKind,
    connection::{DatabaseConnection, KeystoreDatabaseConnection, TransactionWrapper},
    entities::{Entity, EntityBase, EntityFindParams, EntityTransactionExt, StoredCredential, StringEntityId},
    migrations::{StoredSignatureKeypair, V5Credential, migrate_to_new_credential},
};

pub(crate) const VERSION: i32 = 16;

pub(crate) fn meta_migration(conn: &mut rusqlite::Connection) -> CryptoKeystoreResult<()> {
    let tx = conn.transaction()?;
    let mut stmt = tx.prepare(&format!(
        "SELECT
            id,
            credential,
            unixepoch(created_at) AS created_at,
            signature_scheme,
            pk,
            keypair,
            credential_id
         FROM {credential_table}, {keypair_table}
         WHERE {keypair_table}.credential_id = {credential_table}.id",
        credential_table = StoredCredential::COLLECTION_NAME,
        keypair_table = StoredSignatureKeypair::COLLECTION_NAME
    ))?;

    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let v5 = V5Credential {
            id: row.get("id")?,
            credential: row.get("credential")?,
            created_at: row.get("created_at")?,
        };

        let kp = StoredSignatureKeypair {
            signature_scheme: row.get("signature_scheme")?,
            pk: row.get("pk")?,
            keypair: row.get("keypair")?,
            credential_id: row.get("credential_id")?,
        };

        // Insert the new credential into temporary mls_credentials_new table, that will be renamed in the next
        // migration
        if let Some(c) = migrate_to_new_credential(&v5, &kp)? {
            tx.execute(
                "INSERT INTO mls_credentials_new (
                        id,
                        credential,
                        created_at,
                        signature_scheme,
                        public_key,
                        secret_key
                    )
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    c.id.clone(),
                    c.credential.clone(),
                    c.created_at,
                    c.signature_scheme,
                    c.public_key.clone(),
                    c.secret_key.clone(),
                ),
            )?;

            // Delete this credential from the old table, so that migration only happens once
            tx.execute(
                "DELETE FROM mls_credentials
                        WHERE id = ?1",
                (c.id.clone(),),
            )?;
        }
    }

    drop(rows);
    drop(stmt);

    tx.commit()?;

    Ok(())
}

impl StoredSignatureKeypair {
    fn load(transaction: &Transaction<'_>, rowid: i64, signature_scheme: u16) -> crate::CryptoKeystoreResult<Self> {
        let mut blob = transaction.blob_open(rusqlite::MAIN_DB, "mls_signature_keypairs", "keypair", rowid, true)?;

        let mut keypair = vec![];
        blob.read_to_end(&mut keypair)?;
        blob.close()?;

        let mut blob = transaction.blob_open(rusqlite::MAIN_DB, "mls_signature_keypairs", "pk", rowid, true)?;

        let mut pk = vec![];
        blob.read_to_end(&mut pk)?;
        blob.close()?;

        let mut blob = transaction.blob_open(
            rusqlite::MAIN_DB,
            "mls_signature_keypairs",
            "credential_id",
            rowid,
            true,
        )?;

        let mut credential_id = vec![];
        blob.read_to_end(&mut credential_id)?;
        blob.close()?;

        Ok(Self {
            signature_scheme,
            keypair,
            pk,
            credential_id,
        })
    }
}

#[async_trait::async_trait]
impl Entity for StoredSignatureKeypair {
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

        transaction
            .prepare_cached(&query)?
            .query_map([], |row| {
                let rowid = row.get(0)?;
                let signature_scheme = row.get(1)?;
                Ok((rowid, signature_scheme))
            })?
            .map(|rowid_result| -> crate::CryptoKeystoreResult<_> {
                let (rowid, signature_scheme) = rowid_result?;
                Self::load(&transaction, rowid, signature_scheme)
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
        transaction
            .query_row(
                "SELECT rowid, signature_scheme FROM mls_signature_keypairs WHERE pk = ?",
                [id.as_slice()],
                |r| Ok((r.get::<_, i64>(0)?, r.get(1)?)),
            )
            .optional()?
            .map(|(rowid, signature_scheme)| Self::load(&transaction, rowid, signature_scheme))
            .transpose()
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let conn = conn.conn().await;
        conn.query_row("SELECT COUNT(*) FROM mls_signature_keypairs", [], |r| r.get(0))
            .map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl EntityBase for StoredSignatureKeypair {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "mls_signature_keypairs";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::StoredSignatureKeypair
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        unimplemented!("signature keypair is not used in transactions")
    }
}

#[async_trait::async_trait]
impl EntityTransactionExt for StoredSignatureKeypair {
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

        let mut blob = transaction.blob_open(rusqlite::MAIN_DB, "mls_signature_keypairs", "pk", row_id, false)?;

        blob.write_all(&self.pk)?;
        blob.close()?;

        let mut blob = transaction.blob_open(rusqlite::MAIN_DB, "mls_signature_keypairs", "keypair", row_id, false)?;

        blob.write_all(&self.keypair)?;
        blob.close()?;

        let mut blob = transaction.blob_open(
            rusqlite::MAIN_DB,
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
