use std::{fs, io};

use security_framework::passwords as ios_keychain;
use sha2::Digest as _;

use crate::CryptoKeystoreResult;

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const WIRE_SERVICE_NAME: &str = "wire.com";

/// Location of the salt of the database at `path`.
fn salt_path(path: &str) -> String {
    format!("{path}.salt")
}

// To prevent iOS from killing backgrounded apps using a WAL-journaled file,
// we need to leave the first 32 bytes as plaintext, this way, iOS can see the
// `SQLite Format 3\0` magic bytes and identify the file as a SQLite database
// and when it does so, it treats this file "specially" and avoids killing the app
// when doing background work
// See more: https://github.com/sqlcipher/sqlcipher/issues/255
//
// Because the header is not encrypted, it cannot hold the salt sqlcipher derives the encryption
// key with, so we keep the salt in a file next to the database. Databases created by an older
// version of this library keep it in the iOS keychain instead; those get migrated on open by
// [`migrate_legacy_salt`].
pub(crate) fn handle_ios_wal_compat(conn: &rusqlite::Connection, path: &str) -> CryptoKeystoreResult<()> {
    match fs::read(salt_path(path)) {
        Ok(salt) => {
            conn.pragma_update(None, "cipher_salt", format!("x'{}'", hex::encode(salt)))?;
        }
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            // No salt file: either this database still keeps its salt in the keychain, or it was
            // just created and sqlcipher generated a salt we have yet to persist.
            if !migrate_legacy_salt(conn, path)? {
                persist_current_salt(conn, path)?;
            }
        }
        Err(e) => return Err(e.into()),
    }

    // Do not encrypt first 32 bytes of the database, so the header can be read by iOS.
    conn.pragma_update(None, "cipher_plaintext_header_size", 32)?;

    // cipher_plaintext_header_size operates in-memory only, until the first DB page is rewritten.
    // We can trigger such a rewrite by setting the user version, which is specified by sqlite
    // to be used for arbitrary user purposes. The write still goes through if we set it to the
    // same value it already had, which is useful, because we set it elsewhere to the value of
    // the currently-applied migration.
    let current_user_version = conn.pragma_query_value(None, "user_version", |row| row.get::<_, i32>(0))?;
    conn.pragma_update(None, "user_version", current_user_version)?;

    Ok(())
}

/// Move the salt of a pre-existing database out of the iOS keychain and into a file next to the
/// database.
///
/// Returns `false` if there is no keychain item for this database, i.e. there is nothing to
/// migrate.
fn migrate_legacy_salt(conn: &rusqlite::Connection, path: &str) -> CryptoKeystoreResult<bool> {
    let digest = sha2::Sha256::digest(path);
    let keychain_key = format!("keystore_salt_{}", hex::encode(digest));

    let salt = match ios_keychain::get_generic_password(WIRE_SERVICE_NAME, &keychain_key) {
        Ok(salt) => salt,
        Err(ref e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(false),
        Err(e) => return Err(e.into()),
    };

    // Write the salt file before deleting the keychain item so that an interrupted migration
    // leaves the salt in the keychain rather than nowhere at all.
    fs::write(salt_path(path), &salt)?;
    conn.pragma_update(None, "cipher_salt", format!("x'{}'", hex::encode(&salt)))?;

    // The salt now lives in the salt file, which is what we read from here on. Failing to clean up
    // the keychain item is therefore not worth failing the migration over; we'd only be denying
    // access to a database we can otherwise open just fine.
    if let Err(e) = ios_keychain::delete_generic_password(WIRE_SERVICE_NAME, &keychain_key) {
        log::warn!("failed to delete the legacy keystore salt from the keychain: {e}");
    }

    Ok(true)
}

/// Persist the salt sqlcipher is currently using into a file next to the database.
fn persist_current_salt(conn: &rusqlite::Connection, path: &str) -> CryptoKeystoreResult<()> {
    let salt = conn.pragma_query_value(None, "cipher_salt", |r| r.get::<_, String>(0))?;
    let mut bytes = [0u8; 16];
    hex::decode_to_slice(salt, &mut bytes).map_err(crate::CryptoKeystoreError::HexSaltDecodeError)?;
    fs::write(salt_path(path), bytes)?;

    Ok(())
}
