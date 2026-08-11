//! Rewrite sha256 keys which earlier migrations backfilled as hex text.
//!
//! `sha256_blob` is named for its input, not its output: it returns [`crate::sha256`], which is a
//! 64-character hex string. Every migration which used it to backfill a key column therefore wrote
//! TEXT, while [`Sha256Hash`] binds the 32 raw digest bytes. SQLite never compares a blob equal to
//! text, so those rows survive `load_all` but are invisible to `get` and `delete`, and so to the
//! transaction cache as well.
//!
//! Any database old enough to have run V12 or V20 therefore holds a mix: hex keys on rows those
//! migrations wrote, and raw keys on everything saved since.

use std::collections::HashSet;

use rusqlite::types::ValueRef;

use crate::{CryptoKeystoreResult, Sha256Hash};

pub(crate) const VERSION: i32 = 31;

/// The key columns which earlier migrations backfilled as hex text.
///
/// Spelled out literally rather than via entity constants, because a meta migration has to keep
/// describing the schema as it was at its own version, even if these tables are renamed later.
const HEX_BACKFILLED_KEY_COLUMNS: &[(&str, &str)] = &[
    // backfilled by V12
    ("mls_encryption_keypairs", "pk_sha256"),
    ("mls_hpke_private_keys", "pk_sha256"),
    ("mls_psk_bundles", "id_sha256"),
    // backfilled by V20
    ("mls_credentials", "public_key_sha256"),
];

pub(crate) fn meta_migration(conn: &mut rusqlite::Connection) -> CryptoKeystoreResult<()> {
    let tx = conn.transaction()?;

    for (table, column) in HEX_BACKFILLED_KEY_COLUMNS {
        rewrite_hex_keys_as_bytes(&tx, table, column)?;
    }

    tx.commit()?;

    Ok(())
}

/// How a row's key was stored, and what to do about it.
#[derive(Debug, Default)]
struct Outcome {
    /// Rows whose key was already stored correctly, and so were left alone.
    already_bytes: usize,
    /// Rows whose hex key was rewritten as bytes.
    rewritten: usize,
    /// Rows dropped because a correctly-keyed row for the same key already existed.
    superseded: usize,
    /// Rows whose key was neither a 32-byte blob nor 64 hex characters, and so were left alone.
    unrecognized: usize,
}

/// Rewrite every hex-encoded key in `table.column` as the raw digest bytes.
///
/// A hex key whose decoded form collides with a key already stored as bytes is dropped rather than
/// rewritten: the byte-keyed row was written by code that does the right thing, so it is the newer
/// of the two, and rewriting would collide with the column's uniqueness constraint anyway.
///
/// Rows whose key is neither a 32-byte blob nor 64 hex characters are left untouched. We did not
/// write them, so we cannot say what they mean, and a data-repair migration should not guess.
fn rewrite_hex_keys_as_bytes(tx: &rusqlite::Transaction<'_>, table: &str, column: &str) -> CryptoKeystoreResult<()> {
    let mut outcome = Outcome::default();

    // Probe every row first, so that the decision for each hex key can account for every key
    // already stored as bytes, not just the ones which happen to be read earlier.
    let mut stored_as_bytes = HashSet::new();
    let mut stored_as_hex = Vec::new();

    {
        let mut stmt = tx.prepare(&format!("SELECT rowid, {column} FROM {table}"))?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let rowid: i64 = row.get(0)?;
            match row.get_ref(1)? {
                ValueRef::Blob(bytes) => match Sha256Hash::from_existing_hash(bytes) {
                    Ok(key) => {
                        stored_as_bytes.insert(key);
                    }
                    Err(_) => outcome.unrecognized += 1,
                },
                ValueRef::Text(text) => stored_as_hex.push((rowid, text.to_owned())),
                // a null or numeric key is not something we ever wrote
                _ => outcome.unrecognized += 1,
            }
        }
    }

    outcome.already_bytes = stored_as_bytes.len();

    for (rowid, hex_key) in stored_as_hex {
        let Some(key) = decode_hex_key(&hex_key) else {
            outcome.unrecognized += 1;
            continue;
        };

        if stored_as_bytes.contains(&key) {
            tx.execute(&format!("DELETE FROM {table} WHERE rowid = ?"), [rowid])?;
            outcome.superseded += 1;
        } else {
            tx.execute(
                &format!("UPDATE {table} SET {column} = ?1 WHERE rowid = ?2"),
                rusqlite::params![key, rowid],
            )?;
            // Record it, so that a second hex key decoding to the same bytes is recognized as
            // superseded rather than rewritten into a uniqueness violation.
            stored_as_bytes.insert(key);
            outcome.rewritten += 1;
        }
    }

    if outcome.rewritten > 0 || outcome.superseded > 0 || outcome.unrecognized > 0 {
        log::info!(
            "{table}.{column}: rewrote {} hex keys as bytes, dropped {} superseded rows, left {} \
             already-correct and {} unrecognized rows alone",
            outcome.rewritten,
            outcome.superseded,
            outcome.already_bytes,
            outcome.unrecognized,
        );
    }

    Ok(())
}

/// Decode a stored hex key, or `None` if it is not one we could have written.
fn decode_hex_key(stored: &[u8]) -> Option<Sha256Hash> {
    let hex_str = str::from_utf8(stored).ok()?;
    let bytes = hex::decode(hex_str).ok()?;
    // `from_existing_hash` is what enforces the digest length, so a short or long value is rejected
    // here rather than written back as a key of the wrong size.
    Sha256Hash::from_existing_hash(bytes).ok()
}
