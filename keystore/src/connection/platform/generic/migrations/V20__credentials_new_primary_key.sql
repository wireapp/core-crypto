CREATE TABLE mls_credentials_new (
    public_key_sha256 TEXT UNIQUE NOT NULL,
    public_key BLOB NOT NULL,
    id BLOB NOT NULL,
    credential BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    ciphersuite INT NOT NULL,
    private_key BLOB NOT NULL
);

INSERT INTO mls_credentials_new (
    public_key_sha256,
    public_key,
    id,
    credential,
    created_at,
    ciphersuite,
    private_key
)
SELECT sha256_blob(public_key),
    public_key,
    id,
    credential,
    created_at,
    ciphersuite,
    private_key
FROM mls_credentials;

DROP TABLE mls_credentials;

ALTER TABLE mls_credentials_new RENAME TO mls_credentials;
