DROP TABLE mls_credentials;
DROP TABLE mls_signature_keypairs;

ALTER TABLE mls_credentials_new RENAME TO mls_credentials;
