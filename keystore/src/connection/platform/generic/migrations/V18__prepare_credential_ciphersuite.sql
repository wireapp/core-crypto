CREATE TABLE mls_credentials_new (
    id BLOB NOT NULL,
    credential BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    ciphersuite INT NOT NULL,
    public_key BLOB NOT NULL,
    secret_key BLOB NOT NULL
);
