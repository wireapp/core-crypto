use crate::{
    CryptoKeystoreResult,
    entities::StoredCredential,
    migrations::{StoredSignatureKeypair, V5Credential, migrate_to_new_credential},
    traits::EntityBase,
};

pub(crate) const VERSION: i32 = 16;

pub(crate) fn meta_migration(conn: &mut rusqlite::Connection) -> CryptoKeystoreResult<()> {
    let tx = conn.transaction()?;
    let mut stmt = tx.prepare(&format!(
        "SELECT
            {credential_table}.rowid AS cred_rowid,
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
        keypair_table = "mls_signature_keypairs"
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
                        session_id,
                        credential,
                        created_at,
                        signature_scheme,
                        public_key,
                        private_key
                    )
                    VALUES (?1, ?2, datetime(?3, 'unixepoch'), ?4, ?5, ?6)",
                (
                    c.session_id.clone(),
                    c.credential.clone(),
                    c.created_at,
                    c.signature_scheme,
                    c.public_key.clone(),
                    c.private_key.clone(),
                ),
            )?;

            // Delete this credential from the old table, so that migration only happens once
            let rowid = row.get::<_, i32>("cred_rowid")?;
            tx.execute(
                "DELETE FROM mls_credentials
                        WHERE rowid = ?1",
                (rowid,),
            )?;
        }
    }

    drop(rows);
    drop(stmt);

    tx.commit()?;

    Ok(())
}
