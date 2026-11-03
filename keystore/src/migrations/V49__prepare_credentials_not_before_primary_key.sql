-- Add `not_before` to the primary key of `mls_credentials`.
--
-- A reissued X509 certificate can certify the same signature key as the one it replaces, so
-- `(public_key_sha256, credential_type)` can't tell the old credential from the new one, and during
-- a rotation both have to exist at once. The leaf certificate's `not_before` tells them apart, and a
-- group or key package can read it from its own leaf node, so it serves as the rest of the key.
--
-- `not_before` only exists inside the serialized certificate, so meta migration v49 fills this
-- table. V50 then swaps it in and rebuilds the tables whose foreign keys point at it.

CREATE TABLE mls_credentials_new (
  public_key_sha256 BLOB NOT NULL,
  credential_type INTEGER NOT NULL,
  -- Unix timestamp in seconds of the leaf certificate's `not_before` for an X509 credential, and 0
  -- for a basic one. A basic credential has no certificate to read it from, and there is only ever
  -- one per public key, so a constant is enough. `created_at` can't take this role: for a basic
  -- credential it is the insertion time, which a key package stored before its credential (as a
  -- history client does) has no way to know.
  not_before INTEGER NOT NULL,
  public_key BLOB NOT NULL,
  session_id BLOB NOT NULL,
  credential BLOB NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  ciphersuite INTEGER NOT NULL,
  private_key BLOB NOT NULL,
  PRIMARY KEY (public_key_sha256, credential_type, not_before)
);
