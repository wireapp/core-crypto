-- Tighten the V45 columns, cascade from credentials, forward deletion to leaf keypairs, retire old table.

-- current state, from `composite-schema.sql`:
--
-- CREATE TABLE "mls_key_packages" (
--   key_package_ref BLOB UNIQUE,
--   key_package BLOB,
--   credential_id BLOB NULL,
--   credential_type INTEGER NULL,
--   hpke_init_public_key_hash BLOB NULL,
--   hpke_init_private_key BLOB NULL,
--   leaf_encryption_key_hash BLOB NULL
-- );

CREATE TABLE new_mls_key_packages (
    key_package_ref BLOB NOT NULL PRIMARY KEY,
    key_package BLOB NOT NULL,
    credential_id BLOB NOT NULL,
    credential_type INTEGER NOT NULL,
    hpke_init_public_key_hash BLOB NOT NULL UNIQUE,
    leaf_encryption_key_hash BLOB NOT NULL UNIQUE,
    -- this has to be nullable because openmls insists on filling it in a separate statement
    -- because it thinks it's a separate entity
    hpke_init_private_key BLOB NULL,
    -- Deferred so that the credential only has to exist by the time the transaction commits. A history
    -- client stores its key package before it can add the credential: it recovers the credential from
    -- the stored key package.
    FOREIGN KEY (credential_id, credential_type)
        REFERENCES mls_credentials (public_key_sha256, credential_type)
        ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED
);

INSERT INTO new_mls_key_packages (
    key_package_ref, key_package,
    credential_id, credential_type,
    hpke_init_public_key_hash, leaf_encryption_key_hash,
    hpke_init_private_key
)
SELECT key_package_ref, key_package,
    credential_id, credential_type,
    hpke_init_public_key_hash, leaf_encryption_key_hash,
    hpke_init_private_key
FROM mls_key_packages;

DROP TABLE mls_key_packages;

ALTER TABLE new_mls_key_packages RENAME TO mls_key_packages;

-- it's been copied directly into the relevant keypackage rows
DROP TABLE mls_hpke_private_keys;

-- ensure we don't need a full-table scan when cascade-deleting
CREATE INDEX idx_mls_key_packages_credential_fk ON mls_key_packages (credential_id, credential_type);

-- forward deletion of a keypackage to its encryption keypair
CREATE TRIGGER delete_key_package_leaf_keypair
AFTER DELETE ON mls_key_packages
BEGIN
  DELETE FROM mls_encryption_keypairs WHERE pk_sha256 = OLD.leaf_encryption_key_hash;
END;
