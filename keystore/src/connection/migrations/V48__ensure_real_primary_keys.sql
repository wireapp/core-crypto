-- Give the oldest tables real primary keys, and make their columns NOT NULL.
--
-- - `proteus_prekeys.id` becomes INTEGER PRIMARY KEY, an alias for the rowid, so lookups no longer
--   go through a separate index.
-- - `proteus_identities` had no key at all; only the Rust code kept it to a single row. Now the
--   schema does too.
--
-- The hash columns of the MLS tables were declared TEXT, but have held raw bytes since V31. They are
-- now declared BLOB.
--
-- No current code path writes a NULL into any of these tables, but a row that holds one anyway is
-- dropped on the way across rather than failing the migration.

CREATE TABLE new_proteus_prekeys (
    id INTEGER PRIMARY KEY,
    key BLOB NOT NULL
);
-- An INTEGER PRIMARY KEY rejects anything that isn't an integer, and NULL would be assigned a fresh id,
-- so only keep ids which are already integers.
INSERT INTO new_proteus_prekeys (id, key)
SELECT id, key FROM proteus_prekeys
WHERE typeof(id) = 'integer' AND key IS NOT NULL;
DROP TABLE proteus_prekeys;
ALTER TABLE new_proteus_prekeys RENAME TO proteus_prekeys;

-- `id` is deliberately INT, not INTEGER. An INTEGER PRIMARY KEY aliases the rowid, which ignores
-- DEFAULT and assigns the next free rowid instead, so an insert which leaves out `id` (as
-- `ProteusIdentity::save` does) would get 1 and fail the CHECK.
CREATE TABLE new_proteus_identities (
    id INT NOT NULL DEFAULT 0 PRIMARY KEY CHECK (id = 0),
    sk BLOB NOT NULL,
    pk BLOB NOT NULL
);
-- `ProteusIdentity::save` refuses to write a second identity, so there should only ever be one.
-- If there are more, keep the one `ProteusIdentity::get` has been returning: the oldest.
INSERT INTO new_proteus_identities (sk, pk)
SELECT sk, pk FROM proteus_identities
WHERE sk IS NOT NULL AND pk IS NOT NULL
ORDER BY rowid ASC
LIMIT 1;
DROP TABLE proteus_identities;
ALTER TABLE new_proteus_identities RENAME TO proteus_identities;

CREATE TABLE new_proteus_sessions (
    id TEXT NOT NULL PRIMARY KEY,
    session BLOB NOT NULL
);
INSERT INTO new_proteus_sessions (id, session)
SELECT id, session FROM proteus_sessions
WHERE id IS NOT NULL AND session IS NOT NULL;
DROP TABLE proteus_sessions;
ALTER TABLE new_proteus_sessions RENAME TO proteus_sessions;

-- `delete_key_package_leaf_keypair` (from V46) deletes from `mls_encryption_keypairs`, and it has to be
-- out of the way while that table is rebuilt. Once the old table is dropped, the trigger refers to a
-- table which does not exist, and SQLite checks every trigger in the schema when renaming a table, so
-- the rename below would fail with "error in trigger delete_key_package_leaf_keypair: no such table".
-- It is recreated, unchanged, once the rebuilt table has its final name.
DROP TRIGGER delete_key_package_leaf_keypair;

CREATE TABLE new_mls_encryption_keypairs (
    pk_sha256 BLOB NOT NULL PRIMARY KEY,
    pk BLOB NOT NULL,
    sk BLOB NOT NULL
);
INSERT INTO new_mls_encryption_keypairs (pk_sha256, pk, sk)
SELECT pk_sha256, pk, sk FROM mls_encryption_keypairs
WHERE pk_sha256 IS NOT NULL AND pk IS NOT NULL AND sk IS NOT NULL;
DROP TABLE mls_encryption_keypairs;
ALTER TABLE new_mls_encryption_keypairs RENAME TO mls_encryption_keypairs;

CREATE TRIGGER delete_key_package_leaf_keypair
AFTER DELETE ON mls_key_packages
BEGIN
  DELETE FROM mls_encryption_keypairs WHERE pk_sha256 = OLD.leaf_encryption_key_hash;
END;

CREATE TABLE new_mls_psk_bundles (
    id_sha256 BLOB NOT NULL PRIMARY KEY,
    psk_id BLOB NOT NULL,
    psk BLOB NOT NULL
);
INSERT INTO new_mls_psk_bundles (id_sha256, psk_id, psk)
SELECT id_sha256, psk_id, psk FROM mls_psk_bundles
WHERE id_sha256 IS NOT NULL AND psk_id IS NOT NULL AND psk IS NOT NULL;
DROP TABLE mls_psk_bundles;
ALTER TABLE new_mls_psk_bundles RENAME TO mls_psk_bundles;
