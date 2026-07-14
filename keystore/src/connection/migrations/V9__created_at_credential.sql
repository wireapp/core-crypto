ALTER TABLE mls_credentials ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE mls_signature_keypairs DROP COLUMN created_at;