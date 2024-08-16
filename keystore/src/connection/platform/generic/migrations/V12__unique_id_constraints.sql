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

---- mls_hpke_private_keys ----
CREATE TABLE mls_hpke_private_keys_new (
    pk_sha256 TEXT UNIQUE,
    pk BLOB,
    sk BLOB
);

INSERT INTO mls_hpke_private_keys_new (pk_sha256, pk, sk)
SELECT sha256_blob(pk), pk, sk FROM mls_hpke_private_keys;

DROP TABLE mls_hpke_private_keys;

ALTER TABLE mls_hpke_private_keys_new RENAME TO mls_hpke_private_keys;

---- mls_keypackages ----
CREATE TABLE mls_keypackages_new (
    keypackage_ref_hex TEXT UNIQUE,
    keypackage BLOB
);

INSERT INTO mls_keypackages_new (keypackage_ref_hex, keypackage)
SELECT LOWER(hex(keypackage_ref)), keypackage FROM mls_keypackages;

DROP TABLE mls_keypackages;

ALTER TABLE mls_keypackages_new RENAME TO mls_keypackages;

---- mls_psk_bundles ----
CREATE TABLE mls_psk_bundles_new (
    id_sha256 TEXT UNIQUE,
    psk_id BLOB,
    psk BLOB
);

INSERT INTO mls_psk_bundles_new (id_sha256, psk_id, psk)
SELECT sha256_blob(psk_id), psk_id, psk FROM mls_psk_bundles;

DROP TABLE mls_psk_bundles;

ALTER TABLE mls_psk_bundles_new RENAME TO mls_psk_bundles;
