//! Fill `mls_credentials_new`, which V49 created, from `mls_credentials`.
//!
//! An X509 credential's `not_before` comes from its leaf certificate. That only exists inside the
//! serialized credential, so it can't be computed in SQL.

use log::warn;
use rusqlite::named_params;

use crate::{CryptoKeystoreResult, entities::StoredCredential, migrations::historical::not_before_from_serialized};

pub(crate) const VERSION: i32 = 49;

/// The MLS credential type `x509`.
const X509: u16 = 2;

pub(crate) fn meta_migration(tx: &rusqlite::Transaction<'_>) -> CryptoKeystoreResult<()> {
    // A basic credential has no certificate to take `not_before` from.
    tx.execute(
        "INSERT INTO mls_credentials_new (
            public_key_sha256, credential_type, not_before, public_key, session_id, credential, created_at,
            ciphersuite, private_key
        )
        SELECT
            public_key_sha256, credential_type, :not_before, public_key, session_id, credential, created_at,
            ciphersuite, private_key
        FROM mls_credentials
        WHERE credential_type != :x509",
        named_params! {
            ":not_before": StoredCredential::NOT_BEFORE_WITHOUT_CERTIFICATE,
            ":x509": X509,
        },
    )?;

    let credentials: Vec<(Vec<u8>, Vec<u8>)> = tx
        .prepare("SELECT public_key_sha256, credential FROM mls_credentials WHERE credential_type = :x509")?
        .query_map(named_params! { ":x509": X509 }, |row| {
            Ok((row.get("public_key_sha256")?, row.get("credential")?))
        })?
        .collect::<Result<_, _>>()?;

    let mut copy_stmt = tx.prepare(
        "INSERT INTO mls_credentials_new (
            public_key_sha256, credential_type, not_before, public_key, session_id, credential, created_at,
            ciphersuite, private_key
        )
        SELECT
            public_key_sha256, credential_type, :not_before, public_key, session_id, credential,
            -- releases before v11.0.0 stored the insertion time here; an X509 credential's
            -- earliest validity is its certificate's not_before
            datetime(:not_before, 'unixepoch'),
            ciphersuite, private_key
        FROM mls_credentials
        WHERE public_key_sha256 = :public_key_sha256 AND credential_type = :x509",
    )?;
    let mut delete_groups_stmt =
        tx.prepare("DELETE FROM mls_groups WHERE credential_id = :public_key_sha256 AND credential_type = :x509")?;
    let mut delete_credential_stmt = tx.prepare(
        "DELETE FROM mls_credentials WHERE public_key_sha256 = :public_key_sha256 AND credential_type = :x509",
    )?;

    for (public_key_sha256, credential) in credentials {
        match not_before_from_serialized(&credential) {
            Ok(not_before) => {
                copy_stmt.execute(named_params! {
                    ":not_before": not_before,
                    ":public_key_sha256": public_key_sha256,
                    ":x509": X509,
                })?;
            }
            Err(err) => {
                // This is deliberate. A credential we can't parse was never usable, and neither was
                // any group built on it, so dropping them loses nothing. Failing the migration would
                // leave the database impossible to open.
                //
                // Delete under the old schema, so the existing cascades and triggers clean up:
                // removing the groups removes their epoch data, counters and pending messages, and
                // removing the credential removes its key packages and their leaf keypairs.
                // `mls_groups` restricts deleting a credential it references, so it goes first.
                warn!("dropping an X509 credential whose certificate can't be read, along with its groups: {err}");
                let key = named_params! { ":public_key_sha256": public_key_sha256, ":x509": X509 };
                delete_groups_stmt.execute(key)?;
                delete_credential_stmt.execute(key)?;
            }
        }
    }

    Ok(())
}
