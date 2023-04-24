CREATE TABLE mls_credentials (
    id BLOB,
    credential BLOB
);

CREATE TABLE mls_signature_keypairs (
    signature_scheme INT,
    keypair BLOB,
    pk BLOB,
    credential_id BLOB
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

CREATE TABLE mls_groups (
    id BLOB,
    state BLOB,
    parent_id BLOB
);

CREATE TABLE mls_pending_groups (
    id BLOB,
    state BLOB,
    cfg BLOB,
    parent_id BLOB
);

CREATE TABLE proteus_prekeys (
    id INT UNIQUE,
    key BLOB
);

CREATE TABLE proteus_identities (
    pk BLOB,
    sk BLOB
);

CREATE TABLE proteus_sessions (
    id VARCHAR(255) UNIQUE,
    session BLOB
);

CREATE TABLE e2ei_enrollment (
    id VARCHAR(255) UNIQUE,
    content BLOB
);
