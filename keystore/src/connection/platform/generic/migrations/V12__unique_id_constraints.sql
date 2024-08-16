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