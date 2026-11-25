-- Drop what the V53 meta migration needed to convert the old openmls fork's data, and what nothing has used since.

-- The V53 meta migration converted every group's `state`, or dropped the group.
ALTER TABLE mls_groups DROP COLUMN state;

-- A key package's leaf encryption private key is in its own row now, so there's nothing in `mls_encryption_keypairs`
-- to delete along with it. That table only holds the key pairs of leaf nodes we proposed in updates.
DROP TRIGGER delete_key_package_leaf_keypair;

-- `leaf_encryption_key_hash` only served to find a key package's leaf key pair in `mls_encryption_keypairs`. It's
-- `UNIQUE`, which `DROP COLUMN` refuses, so the table is rebuilt without it.
CREATE TABLE new_mls_key_packages (
  key_package_ref BLOB NOT NULL PRIMARY KEY,
  key_package BLOB NOT NULL,
  credential_id BLOB NOT NULL,
  credential_type INTEGER NOT NULL,
  credential_not_before INTEGER NOT NULL,
  hpke_init_public_key_hash BLOB NOT NULL UNIQUE,
  -- The private keys are nullable because a key package is saved first, and its private keys by a separate
  -- statement.
  hpke_init_private_key BLOB,
  leaf_encryption_private_key BLOB,
  -- Deferred so that the credential only has to exist by the time the transaction commits. A history
  -- client stores its key package before it can add the credential: it recovers the credential from
  -- the stored key package.
  FOREIGN KEY (credential_id, credential_type, credential_not_before)
    REFERENCES mls_credentials (public_key_sha256, credential_type, not_before)
    ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED
);

INSERT INTO new_mls_key_packages (
  key_package_ref, key_package,
  credential_id, credential_type, credential_not_before,
  hpke_init_public_key_hash,
  hpke_init_private_key, leaf_encryption_private_key
)
SELECT key_package_ref, key_package,
  credential_id, credential_type, credential_not_before,
  hpke_init_public_key_hash,
  hpke_init_private_key, leaf_encryption_private_key
FROM mls_key_packages;

DROP TABLE mls_key_packages;
ALTER TABLE new_mls_key_packages RENAME TO mls_key_packages;

CREATE INDEX idx_mls_key_packages_credential_fk
  ON mls_key_packages (credential_id, credential_type, credential_not_before);
