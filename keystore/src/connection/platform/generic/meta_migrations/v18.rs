use crate::{
    CryptoKeystoreResult,
    entities::{EntityBase, StoredCredential},
    migrations::{V6Credential, ciphersuites_for_signature_scheme},
};

pub(crate) const VERSION: i32 = 18;

pub(crate) fn meta_migration(conn: &mut rusqlite::Connection) -> CryptoKeystoreResult<()> {
    let tx = conn.transaction()?;
    let mut stmt = tx.prepare(&format!(
        "SELECT
            id,
            credential,
            unixepoch(created_at) AS created_at,
            signature_scheme,
            public_key,
            secret_key
         FROM {credential_table}",
        credential_table = StoredCredential::COLLECTION_NAME,
    ))?;

    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let v6 = V6Credential {
            id: row.get("id")?,
            credential: row.get("credential")?,
            created_at: row.get("created_at")?,
            signature_scheme: row.get("signature_scheme")?,
            public_key: row.get("public_key")?,
            secret_key: row.get("secret_key")?,
        };

        // Insert the new credential into temporary mls_credentials_new table, that will be renamed in the next migration
        // note that this duplicates the credentials if more than one ciphersuite could map to the selected signature scheme:
        // this is less harmful than guessing.
        for ciphersuite in ciphersuites_for_signature_scheme(v6.signature_scheme) {
            tx.execute(
                "INSERT INTO mls_credentials_new (
                        id,
                        credential,
                        created_at,
                        ciphersuite,
                        public_key,
                        secret_key
                    )
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    v6.id.clone(),
                    v6.credential.clone(),
                    v6.created_at,
                    ciphersuite,
                    v6.public_key.clone(),
                    v6.secret_key.clone(),
                ),
            )?;
        }
    }

    drop(rows);
    drop(stmt);

    tx.commit()?;

    Ok(())
}
