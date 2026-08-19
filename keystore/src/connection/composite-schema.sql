CREATE TABLE proteus_prekeys (id INT UNIQUE, KEY BLOB);

CREATE TABLE proteus_identities (sk BLOB, pk BLOB);

CREATE TABLE proteus_sessions (id VARCHAR(255) UNIQUE, SESSION BLOB);

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

CREATE TABLE "mls_key_packages" (
  key_package_ref BLOB UNIQUE,
  key_package BLOB
);

CREATE INDEX idx_mls_keypackages_keypackage_ref ON "mls_key_packages"(key_package_ref);

CREATE TABLE "mls_groups" (id BLOB UNIQUE, state BLOB);

CREATE INDEX idx_mls_groups_id ON mls_groups(id);

CREATE TABLE "mls_buffered_commits" (
  conversation_id BLOB UNIQUE,
  commit_data BLOB
);

CREATE INDEX idx_mls_buffered_commits_conversation_id ON mls_buffered_commits(conversation_id);

CREATE TABLE "mls_pending_groups" (
  id BLOB PRIMARY KEY,
  state BLOB,
  cfg BLOB,
  parent_id BLOB
);

CREATE TABLE x509_trust_anchor (
  fingerprint TEXT PRIMARY KEY,
  content BLOB NOT NULL
);

CREATE TABLE x509_intermediate_certs (
  ski_aki_pair TEXT PRIMARY KEY NOT NULL,
  content BLOB NOT NULL
);

CREATE TABLE x509_crls (
  distribution_point TEXT PRIMARY KEY NOT NULL,
  content BLOB NOT NULL
);

CREATE TABLE "mls_pending_messages" (
  hash_sha256 BLOB PRIMARY KEY NOT NULL,  -- hash of the concatenation of (conversation_id, message)
  conversation_id BLOB NOT NULL,
  message BLOB NOT NULL
);

CREATE INDEX idx_mls_pending_messages_conversation_id ON mls_pending_messages(conversation_id);

CREATE TABLE targeted_message_tx_counters (
  conversation_id BLOB NOT NULL,
  receiver INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (conversation_id, receiver),
  FOREIGN KEY (conversation_id) REFERENCES mls_groups(id) ON DELETE CASCADE
);

CREATE TABLE tnt_secrets (
  conversation_id BLOB NOT NULL,
  epoch INTEGER NOT NULL,
  hpke_private_key BLOB NOT NULL,
  group_context BLOB NOT NULL,
  targeted_message_psk BLOB NOT NULL,
  PRIMARY KEY (conversation_id, epoch),
  FOREIGN KEY (conversation_id) REFERENCES mls_groups(id) ON DELETE CASCADE
);

CREATE TABLE targeted_message_rx_counters (
  conversation_id BLOB NOT NULL,
  sender INTEGER NOT NULL,
  epoch INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (conversation_id, sender, epoch),
  FOREIGN KEY (conversation_id) REFERENCES mls_groups(id) ON DELETE CASCADE
);
