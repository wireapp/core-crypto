CREATE TABLE mls_keys (
    id VARCHAR(255) UNIQUE,
    key BLOB
);

CREATE TABLE mls_identities (
    id VARCHAR(255) UNIQUE,
    signature BLOB,
    credential BLOB
);

CREATE TABLE mls_groups (
    id BLOB,
    state BLOB
);

CREATE TABLE proteus_prekeys (
    id INT UNIQUE,
    key BLOB
);

CREATE TABLE mls_pending_groups (
    id BLOB,
    state BLOB,
    cfg BLOB
);
