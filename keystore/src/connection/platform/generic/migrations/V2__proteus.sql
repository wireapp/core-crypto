CREATE TABLE proteus_identities (
    sk BLOB,
    pk BLOB
);

CREATE TABLE proteus_sessions (
    id VARCHAR(255) UNIQUE,
    session BLOB
);