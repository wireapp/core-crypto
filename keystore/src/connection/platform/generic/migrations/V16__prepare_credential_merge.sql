CREATE TABLE mls_credentials_new (
    id BLOB NOT NULL,
    credential BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    signature_scheme INT NOT NULL,
    public_key BLOB NOT NULL,
    private_key BLOB NOT NULL
);

