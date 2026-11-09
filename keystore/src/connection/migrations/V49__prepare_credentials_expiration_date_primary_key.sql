-- Add `expiration_date` to the primary key of `mls_credentials`.
--
-- A renewed X509 certificate keeps the same key pair and only gets a new expiration date, so
-- `(public_key_sha256, credential_type)` can't tell the old credential from the new one. During a
-- rotation both have to exist at once.
--
-- The expiration date only exists inside the serialized credential, so meta migration v49 fills
-- this table. V50 then swaps it in and rebuilds the tables whose foreign keys point at it.

CREATE TABLE mls_credentials_new (
    public_key_sha256 BLOB NOT NULL,
    credential_type INTEGER NOT NULL,
    -- Unix timestamp (seconds) of the leaf certificate's notAfter. Basic credentials don't expire,
    -- and use 0. Not NULL: SQLite treats NULLs in a primary key as distinct, and a foreign key with
    -- a NULL column isn't checked at all.
    expiration_date INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    session_id BLOB NOT NULL,
    credential BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    ciphersuite INTEGER NOT NULL,
    private_key BLOB NOT NULL,
    PRIMARY KEY (public_key_sha256, credential_type, expiration_date)
);
