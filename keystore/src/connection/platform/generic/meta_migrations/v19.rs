use crate::{
    CryptoKeystoreResult,
    entities::{EntityBase, PersistedMlsGroup, StoredCredential},
    migrations::{detect_duplicate_credentials, make_least_used_ciphersuite},
};

pub(crate) const VERSION: i32 = 19;

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
    let least_used_ciphersuite = make_least_used_ciphersuite(persisted_mls_groups)?;

    let mut credential_stmt = tx.prepare(&format!(
        "SELECT ciphersuite, public_key FROM {table}",
        table = StoredCredential::COLLECTION_NAME,
    ))?;

    let credentials = credential_stmt
        .query_map([], |row| {
            Ok(StoredCredential {
                ciphersuite: row.get("ciphersuite")?,
                public_key: row.get("public_key")?,
                id: Vec::new(),         // not relevant for this application
                credential: Vec::new(), // not relevant for this application
                created_at: 0,          // not relevant for this application
                secret_key: Vec::new(), // not relevant for this application
            })
        })?
        .filter_map(|row| row.ok())
        .collect::<Vec<_>>();

    let duplicates = detect_duplicate_credentials(&credentials);

    for (cred_a, cred_b) in duplicates.into_iter() {
        let outcome = least_used_ciphersuite(cred_a.ciphersuite, cred_b.ciphersuite);
        match outcome {
            None => {
                // If the least used ciphersuite couldn't be determined, something in the data is not what we assume
                // a) the duplicate doesn't form a pair of ciphersuites with a matching signature scheme (error in
                // previous meta migration) b) both ciphersuites don't get used in any mls group
                //
                // In both cases, what we want to do is delete both credentials.
                tx.execute(
                    "DELETE FROM mls_credentials
                            WHERE public_key = ?1",
                    [cred_a.public_key.clone()],
                )?;
            }
            Some(least_used_ciphersuite) => {
                // Delete the credential with less usage.
                tx.execute(
                    "DELETE FROM mls_credentials
                            WHERE public_key = ?1 AND ciphersuite = ?2",
                    rusqlite::params![cred_a.public_key, least_used_ciphersuite],
                )?;
            }
        };
    }

    drop(least_used_ciphersuite);
    drop(group_stmt);
    drop(credential_stmt);
    tx.commit()?;

    Ok(())
}
