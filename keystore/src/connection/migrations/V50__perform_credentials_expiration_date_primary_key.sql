-- Swap in `mls_credentials_new` from V49, and give `mls_groups` and `mls_key_packages` a
-- `credential_expiration_date` column, so their foreign keys can reference the new three-column
-- primary key.
--
-- This migration runs with foreign keys off (see `WITHOUT_FOREIGN_KEYS`), so dropping a table
-- doesn't cascade into the tables which reference it. Their `REFERENCES mls_groups` keeps its text,
-- and points at the new table once it has been renamed into place.
--
-- For the same reason, the rebuilt tables reference `mls_credentials` by its final name, even
-- though that is still the old table while they are filled. Referencing `mls_credentials_new` would
-- rely on the rename at the end rewriting the reference, which SQLite only does with foreign keys
-- off if `legacy_alter_table` is off too, and that is a connection setting this migration can't
-- vouch for.
--
-- Nothing checks the copied rows,
-- so every reference has to be valid by construction: meta migration v49 copied every credential it
-- could parse and deleted the rest along with their groups and key packages, so every remaining
-- group and key package has exactly one matching row in `mls_credentials_new`, and the joins below
-- neither drop nor duplicate anything.
--
-- A table's indexes and triggers are dropped along with it, so they are recreated at the end.

CREATE TABLE new_mls_groups (
  id BLOB NOT NULL PRIMARY KEY,
  -- we have to keep the whole state in a blob because openmls doesn't expose enough information
  -- to fully persist a mls group in any other way than via this opaque blob
  state BLOB,
  -- but we can store several small fields for our own information and sort/search/filter capabilities
  epoch INTEGER NOT NULL,
  ciphersuite INTEGER NOT NULL,
  credential_id BLOB NOT NULL,
  credential_type INTEGER NOT NULL,
  credential_expiration_date INTEGER NOT NULL,
  own_leaf_index INTEGER NOT NULL,
  -- this field distinguishes between proper groups and pending groups
  is_pending BOOLEAN NOT NULL DEFAULT 0,
  tnt_tx_counter INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (credential_id, credential_type, credential_expiration_date)
    REFERENCES mls_credentials (public_key_sha256, credential_type, expiration_date)
    ON DELETE RESTRICT
);

INSERT INTO new_mls_groups (
  id, state, epoch, ciphersuite,
  credential_id, credential_type, credential_expiration_date,
  own_leaf_index, is_pending, tnt_tx_counter
)
SELECT g.id, g.state, g.epoch, g.ciphersuite,
  g.credential_id, g.credential_type, c.expiration_date,
  g.own_leaf_index, g.is_pending, g.tnt_tx_counter
FROM mls_groups g
JOIN mls_credentials_new c
  ON c.public_key_sha256 = g.credential_id AND c.credential_type = g.credential_type;

DROP TABLE mls_groups;
ALTER TABLE new_mls_groups RENAME TO mls_groups;

CREATE TABLE new_mls_key_packages (
  key_package_ref BLOB NOT NULL PRIMARY KEY,
  key_package BLOB NOT NULL,
  credential_id BLOB NOT NULL,
  credential_type INTEGER NOT NULL,
  credential_expiration_date INTEGER NOT NULL,
  hpke_init_public_key_hash BLOB NOT NULL UNIQUE,
  leaf_encryption_key_hash BLOB NOT NULL UNIQUE,
  -- this has to be nullable because openmls insists on filling it in a separate statement
  -- because it thinks it's a separate entity
  hpke_init_private_key BLOB NULL,
  -- Deferred so that the credential only has to exist by the time the transaction commits. A history
  -- client stores its key package before it can add the credential: it recovers the credential from
  -- the stored key package.
  FOREIGN KEY (credential_id, credential_type, credential_expiration_date)
    REFERENCES mls_credentials (public_key_sha256, credential_type, expiration_date)
    ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED
);

INSERT INTO new_mls_key_packages (
  key_package_ref, key_package,
  credential_id, credential_type, credential_expiration_date,
  hpke_init_public_key_hash, leaf_encryption_key_hash,
  hpke_init_private_key
)
SELECT k.key_package_ref, k.key_package,
  k.credential_id, k.credential_type, c.expiration_date,
  k.hpke_init_public_key_hash, k.leaf_encryption_key_hash,
  k.hpke_init_private_key
FROM mls_key_packages k
JOIN mls_credentials_new c
  ON c.public_key_sha256 = k.credential_id AND c.credential_type = k.credential_type;

-- The implicit DELETE of a DROP TABLE fires no triggers, so `delete_key_package_leaf_keypair`
-- leaves the leaf keypairs alone. It is dropped along with the table and recreated below.
DROP TABLE mls_key_packages;
ALTER TABLE new_mls_key_packages RENAME TO mls_key_packages;

-- `mls_groups` and `mls_key_packages` already reference this name, so nothing needs rewriting.
DROP TABLE mls_credentials;
ALTER TABLE mls_credentials_new RENAME TO mls_credentials;

CREATE INDEX idx_mls_groups_credential_fk
  ON mls_groups (credential_id, credential_type, credential_expiration_date);

CREATE INDEX idx_mls_key_packages_credential_fk
  ON mls_key_packages (credential_id, credential_type, credential_expiration_date);

CREATE TRIGGER delete_key_package_leaf_keypair
AFTER DELETE ON mls_key_packages
BEGIN
  DELETE FROM mls_encryption_keypairs WHERE pk_sha256 = OLD.leaf_encryption_key_hash;
END;
