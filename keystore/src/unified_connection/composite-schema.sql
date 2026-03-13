CREATE TABLE proteus_prekeys (id INT UNIQUE, KEY BLOB);

CREATE TABLE mls_pending_groups (
  id BLOB,
  state BLOB,
  cfg BLOB,
  parent_id BLOB
);

CREATE TABLE proteus_identities (sk BLOB, pk BLOB);

CREATE TABLE proteus_sessions (id VARCHAR(255) UNIQUE, SESSION BLOB);

CREATE TABLE e2ei_enrollment (id VARCHAR(255) UNIQUE, content BLOB);

CREATE TABLE mls_pending_messages (
  id BLOB,
  message BLOB,
  FOREIGN KEY (id) REFERENCES mls_pending_groups(id)
);

CREATE TABLE e2ei_acme_ca (
  id INTEGER PRIMARY KEY CHECK (id = 0),
  content BLOB
);

CREATE TABLE e2ei_intermediate_certs (ski_aki_pair TEXT UNIQUE, content BLOB);

CREATE TABLE e2ei_crls (
  distribution_point TEXT UNIQUE,
  content BLOB
);

CREATE TABLE "mls_encryption_keypairs" (
  pk_sha256 TEXT UNIQUE,
  pk BLOB,
  sk BLOB
);

CREATE TABLE "mls_hpke_private_keys" (
  pk_sha256 TEXT UNIQUE,
  pk BLOB,
  sk BLOB
);

CREATE TABLE "mls_psk_bundles" (
  id_sha256 TEXT UNIQUE,
  psk_id BLOB,
  psk BLOB
);

CREATE TABLE consumer_data (
  id INTEGER PRIMARY KEY CHECK (id = 0),
  content BLOB
);

CREATE TABLE "mls_credentials" (
  public_key_sha256 TEXT UNIQUE NOT NULL,
  public_key BLOB NOT NULL,
  session_id BLOB NOT NULL,
  credential BLOB NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  ciphersuite INT NOT NULL,
  private_key BLOB NOT NULL
);

CREATE TABLE "mls_epoch_encryption_keypairs" (id BLOB UNIQUE, keypairs BLOB);

CREATE INDEX idx_mls_epoch_encryption_keypairs_id ON mls_epoch_encryption_keypairs(id);

CREATE TABLE "mls_keypackages" (
  keypackage_ref BLOB UNIQUE,
  keypackage BLOB
);

CREATE INDEX idx_mls_keypackages_keypackage_ref ON mls_keypackages(keypackage_ref);

CREATE TABLE "mls_groups" (
  id BLOB UNIQUE,
  state BLOB,
  parent_id BLOB
);

CREATE INDEX idx_mls_groups_id ON mls_groups(id);

CREATE TABLE "mls_buffered_commits" (
  conversation_id BLOB UNIQUE,
  commit_data BLOB
);

CREATE INDEX idx_mls_buffered_commits_conversation_id ON mls_buffered_commits(conversation_id);
