# Keystore test fixtures

## `sqlcipher-v4-wal.sqlite`, `sqlcipher-v4-wal.sqlite-wal`

A keystore in SQLCipher's format, version 4, as the SQLCipher builds write it. The test
`a_keystore_written_by_a_sqlcipher_build_opens_and_keeps_its_format` in `keystore/src/connection/mod.rs` opens it.

It was written by the keystore at `17d1467af0`, built on macOS arm64 with SQLCipher 4.10.0 (SQLite 3.50.4) as bundled by
`libsqlite3-sys` 0.36, with the key `[0x42; 32]`:

1. `Database::open` on a new file, which creates the schema in WAL mode.
1. `PRAGMA wal_checkpoint(TRUNCATE)`, so that the schema is in the database file.
1. `CREATE TABLE marker (data BLOB)` and a row with `b"plaintext marker 4711"`, which only go into the WAL file.
1. Both files copied while the database was still open.
