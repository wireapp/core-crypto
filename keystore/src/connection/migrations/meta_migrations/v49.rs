//! Fill `mls_credentials_new`, which V49 created, from `mls_credentials`.
//!
//! The expiration date only exists inside the serialized credential, so it can't be computed in SQL.

use log::warn;
use rusqlite::named_params;

use crate::{CryptoKeystoreResult, migrations::expiration_date_from_serialized};

pub(crate) const VERSION: i32 = 49;

pub(crate) fn meta_migration(tx: &rusqlite::Transaction<'_>) -> CryptoKeystoreResult<()> {
    let credentials: Vec<(Vec<u8>, u16, Vec<u8>)> = {
        let mut stmt = tx.prepare("SELECT public_key_sha256, credential_type, credential FROM mls_credentials")?;
        stmt.query_map([], |row| {
            Ok((
                row.get("public_key_sha256")?,
                row.get("credential_type")?,
                row.get("credential")?,
            ))
        })?
        .collect::<Result<_, _>>()?
    };

    let mut copy_stmt = tx.prepare(
        "INSERT INTO mls_credentials_new (
            public_key_sha256, credential_type, expiration_date,
            public_key, session_id, credential, created_at, ciphersuite, private_key
        )
        SELECT
            public_key_sha256, credential_type, :expiration_date,
            public_key, session_id, credential, created_at, ciphersuite, private_key
        FROM mls_credentials
        WHERE public_key_sha256 = :public_key_sha256 AND credential_type = :credential_type",
    )?;
    let mut delete_groups_stmt = tx.prepare(
        "DELETE FROM mls_groups
        WHERE credential_id = :public_key_sha256 AND credential_type = :credential_type",
    )?;
    let mut delete_credential_stmt = tx.prepare(
        "DELETE FROM mls_credentials
        WHERE public_key_sha256 = :public_key_sha256 AND credential_type = :credential_type",
    )?;

    for (public_key_sha256, credential_type, credential) in credentials {
        let key = named_params! {
            ":public_key_sha256": public_key_sha256,
            ":credential_type": credential_type,
        };

        match expiration_date_from_serialized(&credential) {
            Ok(expiration_date) => {
                copy_stmt.execute(named_params! {
                    ":expiration_date": expiration_date,
                    ":public_key_sha256": public_key_sha256,
                    ":credential_type": credential_type,
                })?;
            }
            Err(err) => {
                // This is deliberate. A credential we can't parse was never usable, and neither was
                // anything built on it, so dropping it loses nothing. Failing the migration would
                // leave the database impossible to open.
                //
                // Delete in the old schema, so the existing cascades and triggers clean up after
                // it: removing the groups removes their epoch data, counters and pending messages,
                // and removing the credential removes its key packages and their leaf keypairs.
                // `mls_groups` restricts deletion of a credential it references, so it goes first.
                warn!(
                    "dropping credential of type {credential_type} whose expiration date can't be read, along with \
                     its groups and key packages: {err}"
                );
                delete_groups_stmt.execute(key)?;
                delete_credential_stmt.execute(key)?;
            }
        }
    }

    Ok(())
}
