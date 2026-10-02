use std::cmp::Ordering;

use const_format::formatcp;
use log::info;
use rusqlite::named_params;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Sha256Hash, migrations::StoredCredentialV36, traits::Entity as _,
};

pub(crate) const VERSION: i32 = 19;

pub(crate) fn meta_migration(conn: &mut rusqlite::Connection) -> CryptoKeystoreResult<()> {
    let tx = conn.transaction()?;
    let mut credential_stmt = tx.prepare(formatcp!(
        "SELECT ciphersuite, public_key, credential, unixepoch(created_at) AS created_at, rowid FROM {table}",
        table = StoredCredentialV36::TABLE_NAME,
    ))?;

    let mut credentials = credential_stmt
        .query_map([], |row| {
            let rowid = row.get::<_, i64>("rowid")?;
            let credential = StoredCredentialV36 {
                ciphersuite: row.get("ciphersuite")?,
                public_key: row.get("public_key")?,
                credential: row.get("credential")?,
                created_at: row.get("created_at")?,
                session_id: Vec::new(),  // not relevant for this application
                private_key: Vec::new(), // not relevant for this application
            };
            let ctype = credential.credential_type().ok();
            Ok((rowid, ctype, credential))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            CryptoKeystoreError::MigrationFailed(format!("could not load credential for v19 meta-migration: {err}"))
        })?;

    // group by public key
    credentials.sort_by_cached_key(|(_, _, credential)| credential.public_key.clone());
    // consider groups which have the same public key
    for group in credentials.chunk_by_mut(|(_, _, a), (_, _, b)| a.public_key == b.public_key) {
        // in this sort higher is better
        group.sort_unstable_by(|(a_rowid, a_type, a_cred), (b_rowid, b_type, b_cred)| {
            // first sort by credential type: basic is 1 and x509 is 2;
            // we always want x509 if available over basic, but if one was unparseable,
            // keep the one which did parse
            let type_ordering = match (a_type, b_type) {
                (Some(a), Some(b)) => a.cmp(b),
                (Some(_), None) => Ordering::Greater,
                (None, Some(_)) => Ordering::Less,
                (None, None) => Ordering::Equal,
            };
            // after credential type we take the most recent credential
            type_ordering
                .then(a_cred.created_at.cmp(&b_cred.created_at))
                // after that we take the highest rowid (the last one created; guaranteed nonequal)
                .then(a_rowid.cmp(b_rowid))
        });

        // we retain the "highest" member of this group, which is the best
        let (rowid, _, credential) = group.last().expect("group is guaranteed to have at least one member");
        let mut stmt = tx.prepare_cached(formatcp!(
            "DELETE FROM {table} WHERE public_key = :public_key AND rowid != :rowid",
            table = StoredCredentialV36::TABLE_NAME
        ))?;
        let affected_rows = stmt.execute(named_params! {":public_key": &credential.public_key, ":rowid": rowid})?;
        if affected_rows > 0 {
            let public_key_hash = Sha256Hash::hash_from(&credential.public_key);
            info!(affected_rows, public_key_hash:%; "deleted extraneous credentials as part of v19 meta-migration");
        }
    }

    drop(credential_stmt);
    tx.commit()?;

    Ok(())
}
