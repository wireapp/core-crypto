---- mls_encryption_keypairs ----
CREATE TABLE mls_encryption_keypairs_new (
    pk_sha256 TEXT UNIQUE,
    pk BLOB,
    sk BLOB
);

INSERT INTO mls_encryption_keypairs_new (pk_sha256, pk, sk)
SELECT sha256_blob(pk), pk, sk FROM mls_encryption_keypairs;

DROP TABLE mls_encryption_keypairs;

ALTER TABLE mls_encryption_keypairs_new RENAME TO mls_encryption_keypairs;

---- mls_epoch_encryption_keypairs ----
CREATE TABLE mls_epoch_encryption_keypairs_new (
    id_hex TEXT UNIQUE,
    keypairs BLOB
);

-- We convert the output of hex() for consistency, because the rust encoder returns lowercase.
INSERT INTO mls_epoch_encryption_keypairs_new (id_hex, keypairs)
SELECT LOWER(hex(id)), keypairs FROM mls_epoch_encryption_keypairs;

DROP TABLE mls_epoch_encryption_keypairs;

ALTER TABLE mls_epoch_encryption_keypairs_new RENAME TO mls_epoch_encryption_keypairs;