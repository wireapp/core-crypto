CREATE TABLE mls_credentials_new (
    public_key_sha256 BLOB NOT NULL,
    credential_type INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    session_id BLOB NOT NULL,
    credential BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    ciphersuite INTEGER NOT NULL,
    private_key BLOB NOT NULL,
    PRIMARY KEY (public_key_sha256, credential_type)
);
