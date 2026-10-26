use zeroize::Zeroize as _;

use crate::{CryptoKeystoreResult, DatabaseKey};

/// Run `PRAGMA name = 'value'` without going through rusqlite's pragma helpers.
///
/// Since rusqlite 0.41, those helpers first look the name up in `pragma_pragma_list`. That query reads
/// the schema, which fails on an encrypted database before its key is set, and sqlcipher's `cipher_*`
/// pragmas are not listed there at all. Use this for the key pragmas, for sqlcipher's own pragmas,
/// and for anything which has to run before the key is set.
///
/// `name` is put into the SQL verbatim, so it must be a constant. `value` is quoted.
///
/// Upstream issue: <https://github.com/rusqlite/rusqlite/issues/1923>.
pub(super) fn set_pragma_unchecked(
    conn: &rusqlite::Connection,
    name: &'static str,
    value: &str,
) -> rusqlite::Result<()> {
    let mut sql = format!("PRAGMA {name} = '{}'", value.replace('\'', "''"));
    let result = conn.execute_batch(&sql);
    sql.zeroize();
    result
}

/// Format a key pragma according to the raw form supported by sqlcipher
fn set_key_pragma(
    conn: &mut rusqlite::Connection,
    key: &DatabaseKey,
    pragma_name: &'static str,
) -> CryptoKeystoreResult<()> {
    // Make sqlite use raw key data, without key derivation. Also make sure to zeroize
    // the string containing the key after the call.
    let mut x_hex_key = format!("x'{}'", hex::encode(key));
    let result = set_pragma_unchecked(conn, pragma_name, &x_hex_key);
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

/// Encrypt an unencrypted database with a key
pub(super) fn key(conn: &mut rusqlite::Connection, key: &DatabaseKey) -> CryptoKeystoreResult<()> {
    set_key_pragma(conn, key, "key")
}
