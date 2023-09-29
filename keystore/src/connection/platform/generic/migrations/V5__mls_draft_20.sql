-- Both those table are used only in MLS and we do not need to maintain backward compatibility there
DROP TABLE mls_keys;
DROP TABLE mls_identities;

CREATE TABLE mls_signature_keypairs (
    signature_scheme INT,
    keypair BLOB,
    pk BLOB,
    credential_id BLOB
);

CREATE TABLE mls_credentials (
    id BLOB,
    credential BLOB
);

CREATE TABLE mls_hpke_private_keys (
    pk BLOB,
    sk BLOB
);

CREATE TABLE mls_encryption_keypairs (
    pk BLOB,
    sk BLOB
);

CREATE TABLE mls_psk_bundles (
    psk_id BLOB,
    psk BLOB
);

CREATE TABLE mls_keypackages (
    keypackage_ref BLOB,
    keypackage BLOB
);