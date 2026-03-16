use zeroize::Zeroize as _;

use crate::{CryptoKeystoreResult, DatabaseKey};

/// Format a key pragma according to the raw form supported by sqlcipher and sqlite3mc
fn set_key_pragma(conn: &mut rusqlite::Connection, key: &DatabaseKey, pragma_name: &str) -> CryptoKeystoreResult<()> {
    // Make sqlite use raw key data, without key derivation. Also make sure to zeroize
    // the string containing the key after the call.
    let mut x_hex_key = format!("x'{}'", hex::encode(key));
    let result = conn.pragma_update(None, pragma_name, &x_hex_key);
    x_hex_key.zeroize();
    result.map_err(Into::into)
}

/// Decrypt the database by setting the key pragma appropriately
pub(super) fn decrypt(conn: &mut rusqlite::Connection, key: &DatabaseKey) -> CryptoKeystoreResult<()> {
    set_key_pragma(conn, key, "key")
}

/// Reencrypt the database with a new key.
pub(super) fn rekey(conn: &mut rusqlite::Connection, new_key: &DatabaseKey) -> CryptoKeystoreResult<()> {
    set_key_pragma(conn, new_key, "rekey")
}
