use crate::{
    CryptoKeystoreResult,
    entities::{PersistedMlsGroup, StoredCredential},
    migrations::{V6Credential, make_ciphersuite_for_signature_scheme},
    traits::EntityBase as _,
};

pub(crate) const VERSION: i32 = 18;

pub(crate) fn meta_migration(conn: &mut rusqlite::Connection) -> CryptoKeystoreResult<()> {
    let tx = conn.transaction()?;

    let mut group_stmt = tx.prepare(&format!(
        "SELECT state FROM {mls_group_table}",
        mls_group_table = PersistedMlsGroup::COLLECTION_NAME,
    ))?;
    let persisted_mls_groups = group_stmt
        .query_map([], |row| {
            Ok(PersistedMlsGroup {
                state: row.get("state")?,
                id: Vec::new(),  // not relevant for this application
                parent_id: None, // not relevant for this application
            })
        })?
        .filter_map(|row| row.ok()); // rows which can't load at the SQL level are skipped
    let ciphersuite_for_signature_scheme = make_ciphersuite_for_signature_scheme(persisted_mls_groups)?;

    let mut credential_stmt = tx.prepare(&format!(
        "SELECT
            session_id,
            credential,
            unixepoch(created_at) AS created_at,
            signature_scheme,
            public_key,
            private_key
         FROM {credential_table}",
        credential_table = StoredCredential::COLLECTION_NAME,
    ))?;

    let mut rows = credential_stmt.query([])?;
    while let Some(row) = rows.next()? {
        let v6 = V6Credential {
            session_id: row.get("session_id")?,
            credential: row.get("credential")?,
            created_at: row.get("created_at")?,
            signature_scheme: row.get("signature_scheme")?,
            public_key: row.get("public_key")?,
            private_key: row.get("private_key")?,
        };

        // Insert the new credential into temporary mls_credentials_new table, that will be renamed in the next
        // migration
        if let Some(ciphersuite) = ciphersuite_for_signature_scheme(v6.signature_scheme) {
            tx.execute(
                "INSERT INTO mls_credentials_new (
                        session_id,
                        credential,
                        created_at,
                        ciphersuite,
                        public_key,
                        private_key
                    )
                    VALUES (?1, ?2, datetime(?3, 'unixepoch'), ?4, ?5, ?6)",
                (
                    v6.session_id.clone(),
                    v6.credential.clone(),
                    v6.created_at,
                    ciphersuite,
                    v6.public_key.clone(),
                    v6.private_key.clone(),
                ),
            )?;
        }
    }

    drop(rows);
    drop(credential_stmt);
    drop(ciphersuite_for_signature_scheme);
    drop(group_stmt);

    tx.commit()?;

    Ok(())
}
