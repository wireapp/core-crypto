// Not all functions here are used when testing on wasm and it's not worth attributing each of them.
#![cfg_attr(target_os = "unknown", expect(dead_code))]

use tempfile::NamedTempFile;

use crate::DatabaseKey;
#[cfg(not(target_os = "unknown"))]
use crate::{connection::Database, migrations::MigrationTarget};

pub(crate) const DB: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../crypto-ffi/bindings/jvm/src/test/resources/db-v10002003.sqlite"
));
pub(crate) const OLD_KEY: &str = "secret";

/// Seed a fresh database at `schema_version`, then reopen it migrated all the way to latest.
///
/// The inner database is dropped before reopening, so that the reopen actually runs the
/// migrations under test against the seeded rows.
#[cfg(not(target_os = "unknown"))]
pub(crate) async fn seed_then_migrate(
    path: &str,
    key: &DatabaseKey,
    schema_version: u16,
    seed: impl FnOnce(&rusqlite::Connection),
) -> std::sync::Arc<Database> {
    seed_then_migrate_to(path, key, schema_version, MigrationTarget::Latest, seed).await
}

/// Like [`seed_then_migrate`], but stops migrating at `target`.
///
/// For tests of one migration's behaviour which a later migration deliberately changes.
#[cfg(not(target_os = "unknown"))]
pub(crate) async fn seed_then_migrate_to(
    path: &str,
    key: &DatabaseKey,
    schema_version: u16,
    target: MigrationTarget,
    seed: impl FnOnce(&rusqlite::Connection),
) -> std::sync::Arc<Database> {
    {
        let db = Database::open_at_schema_version(path, key, MigrationTarget::Version(schema_version))
            .await
            .expect("opening the database at the pre-migration schema version");
        let conn = db.conn().await;
        seed(&conn);
    }
    Database::open_at_schema_version(path, key, target)
        .await
        .expect("reopening migrated to the target version")
        .into()
}

/// The storage class and length of a stored key, so that a failure says *why* it failed.
///
/// A correctly backfilled key reads as `("blob", 32)`; a hex-encoded one as `("text", 64)`.
pub(crate) fn stored_key_encoding(conn: &rusqlite::Connection, table: &str, column: &str) -> (String, i64) {
    conn.query_row(
        &format!("SELECT typeof({column}), length({column}) FROM {table}"),
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .expect("reading back the stored key")
}

/// Every row of `mls_pending_messages` as `(conversation_id, message)`, sorted by message.
///
/// Reads the table directly rather than through an entity, so that it keeps working at whichever
/// schema version between V31 and V51 a test stops at.
pub(crate) fn pending_messages(conn: &rusqlite::Connection) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut stmt = conn
        .prepare("SELECT conversation_id, message FROM mls_pending_messages ORDER BY message")
        .expect("preparing to read pending messages");
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("reading pending messages")
        .collect::<Result<_, _>>()
        .expect("reading pending messages")
}

/// A temporary database path, kept alive by the returned file handle.
pub(crate) fn temp_db() -> (NamedTempFile, DatabaseKey) {
    (NamedTempFile::new().unwrap(), DatabaseKey::generate())
}

/// `field` with a one-byte variable-length prefix; `field` must be shorter than 64 bytes.
pub(crate) fn short_field(field: &[u8]) -> Vec<u8> {
    assert!(field.len() < 64, "a one-byte prefix only holds lengths up to 63");
    [&[field.len() as u8], field].concat()
}

/// A transient TNT message, up to and including its epoch, followed by bytes the parser must ignore.
pub(crate) fn transient_message(epoch: u64) -> Vec<u8> {
    [
        &[0x00, 0x01][..],      // tnt protocol version
        &[0xF0, 0x00],          // wire format: transient
        &[0x00, 0x01],          // group context: mls protocol version
        &[0x00, 0x01],          // group context: ciphersuite
        &short_field(b"group"), // group context: group id
        &epoch.to_be_bytes(),   // group context: epoch
        b"the rest of the group context, then sender, counter, payload, and signature",
    ]
    .concat()
}

/// A targeted TNT message of the given wire format, up to and including its epoch, followed by bytes the parser
/// must ignore.
pub(crate) fn targeted_message(wire_format: u16, epoch: u64) -> Vec<u8> {
    [
        &[0x00, 0x01][..],          // tnt protocol version
        &wire_format.to_be_bytes(), // wire format
        &[0, 0, 0, 7],              // counter
        &[0, 0, 0, 1],              // sender
        &[0, 0, 0, 2],              // recipient
        &short_field(b"bob"),       // recipient id
        &epoch.to_be_bytes(),       // epoch
        b"group id, payload, and signature",
    ]
    .concat()
}

/// An MLS `PrivateMessage` with the given content type and epoch.
///
/// Only the header is plaintext, and parsing never decrypts, so the encrypted fields can be any bytes.
pub(crate) fn private_message(content_type: u8, epoch: u64) -> Vec<u8> {
    private_message_with_ciphertext(content_type, epoch, b"ciphertext of whatever")
}

/// Like [`private_message`], but with the given ciphertext, so that several messages can share a header.
pub(crate) fn private_message_with_ciphertext(content_type: u8, epoch: u64, ciphertext: &[u8]) -> Vec<u8> {
    [
        &[0x00, 0x01][..],                      // mls protocol version
        &[0x00, 0x02],                          // wire format: private message
        &short_field(b"group"),                 // group id
        &epoch.to_be_bytes(),                   // epoch
        &[content_type],                        // content type
        &short_field(b""),                      // authenticated data
        &short_field(b"encrypted sender data"), // encrypted sender data
        &short_field(ciphertext),               // ciphertext
    ]
    .concat()
}

/// An MLS `PublicMessage` from a member, with the given epoch and content.
///
/// `content` is the content type followed by its body. Nothing verifies the signature or the tags while parsing,
/// so they can be any bytes.
pub(crate) fn public_message(epoch: u64, content: &[u8], is_commit: bool) -> Vec<u8> {
    // commits carry a confirmation tag; nothing else does
    let confirmation_tag = if is_commit {
        short_field(b"confirmation tag")
    } else {
        Vec::new()
    };
    [
        &[0x00, 0x01][..],              // mls protocol version
        &[0x00, 0x01],                  // wire format: public message
        &short_field(b"group"),         // group id
        &epoch.to_be_bytes(),           // epoch
        &[0x01, 0, 0, 0, 1],            // sender: member at leaf index 1
        &short_field(b""),              // authenticated data
        content,                        // content type and body
        &short_field(b"the signature"), // signature
        &confirmation_tag,
        &short_field(b"membership tag"), // a member sender carries a membership tag
    ]
    .concat()
}

/// A commit with no proposals and no update path: content type 3, an empty proposal list, and an absent path.
pub(crate) const EMPTY_COMMIT: &[u8] = &[0x03, 0x00, 0x00];

/// A proposal removing the member at leaf index 2: content type 2, proposal type 3 (remove), then the leaf index.
pub(crate) const REMOVE_PROPOSAL: &[u8] = &[0x02, 0x00, 0x03, 0, 0, 0, 2];
