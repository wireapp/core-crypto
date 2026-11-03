CREATE TABLE consumer_data (
  id INTEGER PRIMARY KEY CHECK (id = 0),
  content BLOB
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

CREATE TABLE "mls_credentials" (
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

CREATE TABLE "mls_groups" (
  id BLOB NOT NULL PRIMARY KEY,
  -- we have to keep the whole state in a blob because openmls doesn't expose enough information
  -- to fully persist a mls group in any other way than via this opaque blob
  state BLOB,
  -- but we can store several small fields for our own information and sort/search/filter capabilities
  epoch INTEGER NOT NULL,
  ciphersuite INTEGER NOT NULL,
  credential_id BLOB NOT NULL,
  credential_type INTEGER NOT NULL,
  own_leaf_index INTEGER NOT NULL,
  -- this field distinguishes between proper groups and pending groups
  is_pending BOOLEAN NOT NULL DEFAULT 0,
  tnt_tx_counter INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (credential_id, credential_type) REFERENCES mls_credentials (public_key_sha256, credential_type) ON DELETE RESTRICT
);

CREATE TABLE "targeted_message_rx_counters" (
  conversation_id BLOB NOT NULL,
  sender INTEGER NOT NULL,
  epoch INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (conversation_id, sender, epoch),
  FOREIGN KEY (conversation_id) REFERENCES "mls_groups"(id) ON DELETE CASCADE
);

CREATE TABLE "transient_message_rx_counters" (
  conversation_id BLOB NOT NULL,
  sender INTEGER NOT NULL,
  epoch INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (conversation_id, sender, epoch),
  FOREIGN KEY (conversation_id) REFERENCES "mls_groups"(id) ON DELETE CASCADE
);

CREATE TABLE "mls_buffered_commits" (
  conversation_id BLOB NOT NULL PRIMARY KEY,
  commit_data BLOB,
  FOREIGN KEY (conversation_id) REFERENCES "mls_groups"(id) ON DELETE CASCADE
);

CREATE TABLE "epoch_encryption_keypairs" (
  conversation_id BLOB NOT NULL,
  own_leaf_index INTEGER NOT NULL,
  epoch INTEGER NOT NULL,
  keypairs BLOB NOT NULL,
  PRIMARY KEY (conversation_id, own_leaf_index, epoch),
  -- DEFERRABLE INITIALLY DEFERRED means that we only enforce this constraint
  -- when the outermost transaction / savepoint is committed.
  FOREIGN KEY (conversation_id) REFERENCES mls_groups(id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE old_epoch_data (
  conversation_id BLOB NOT NULL,
  epoch INTEGER NOT NULL,
  hpke_private_key BLOB NOT NULL,
  group_context BLOB NOT NULL,
  targeted_message_psk BLOB NOT NULL,
  own_leaf_index INTEGER NOT NULL,
  PRIMARY KEY (conversation_id, epoch),
  FOREIGN KEY (conversation_id) REFERENCES mls_groups(id) ON DELETE CASCADE
);

CREATE TABLE foreign_credentials (
  hash BLOB NOT NULL PRIMARY KEY,  -- hash of length-prefixed credential and signature key
  credential BLOB NOT NULL,
  signature_key BLOB NOT NULL
);

CREATE TABLE old_epoch_member_data (
  conversation_id BLOB NOT NULL,
  epoch INTEGER NOT NULL,
  leaf_node_index INTEGER NOT NULL,
  foreign_credential_hash BLOB NOT NULL,
  PRIMARY KEY (conversation_id, epoch, leaf_node_index),
  FOREIGN KEY (conversation_id, epoch) REFERENCES old_epoch_data(conversation_id, epoch) ON DELETE CASCADE,
  FOREIGN KEY (foreign_credential_hash) REFERENCES foreign_credentials(hash) ON DELETE RESTRICT
);

CREATE INDEX old_epoch_member_data_foreign_credential_hash ON old_epoch_member_data (foreign_credential_hash);

CREATE TRIGGER drop_unreferenced_foreign_credential
AFTER
  DELETE ON old_epoch_member_data
BEGIN
DELETE FROM
  foreign_credentials
WHERE
  hash = OLD.foreign_credential_hash
  AND NOT EXISTS (
    SELECT
      1
    FROM
      old_epoch_member_data
    WHERE
      foreign_credential_hash = OLD.foreign_credential_hash
  );
END;

CREATE TABLE "mls_pending_messages" (
  hash_sha256 BLOB PRIMARY KEY NOT NULL,  -- hash of the concatenation of (conversation_id, message)
  conversation_id BLOB NOT NULL,
  message BLOB NOT NULL,
  FOREIGN KEY (conversation_id) REFERENCES mls_groups (id) ON DELETE CASCADE
);

CREATE INDEX idx_mls_pending_messages_conversation_id ON mls_pending_messages (conversation_id);

CREATE TABLE "mls_key_packages" (
  key_package_ref BLOB NOT NULL PRIMARY KEY,
  key_package BLOB NOT NULL,
  credential_id BLOB NOT NULL,
  credential_type INTEGER NOT NULL,
  hpke_init_public_key_hash BLOB NOT NULL UNIQUE,
  leaf_encryption_key_hash BLOB NOT NULL UNIQUE,
  -- this has to be nullable because openmls insists on filling it in a separate statement
  -- because it thinks it's a separate entity
  hpke_init_private_key BLOB NULL,
  -- Deferred so that the credential only has to exist by the time the transaction commits. A history
  -- client stores its key package before it can add the credential: it recovers the credential from
  -- the stored key package.
  FOREIGN KEY (credential_id, credential_type) REFERENCES mls_credentials (public_key_sha256, credential_type) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX idx_mls_key_packages_credential_fk ON mls_key_packages (credential_id, credential_type);

CREATE INDEX idx_mls_groups_credential_fk ON mls_groups (credential_id, credential_type);

CREATE TABLE "proteus_prekeys" (
  id INTEGER PRIMARY KEY,
  KEY BLOB NOT NULL
);

CREATE TABLE "proteus_identities" (
  id INT NOT NULL DEFAULT 0 PRIMARY KEY CHECK (id = 0),
  sk BLOB NOT NULL,
  pk BLOB NOT NULL
);

CREATE TABLE "proteus_sessions" (
  id TEXT NOT NULL PRIMARY KEY,
  SESSION BLOB NOT NULL
);

CREATE TABLE "mls_encryption_keypairs" (
  pk_sha256 BLOB NOT NULL PRIMARY KEY,
  pk BLOB NOT NULL,
  sk BLOB NOT NULL
);

CREATE TRIGGER delete_key_package_leaf_keypair
AFTER
  DELETE ON mls_key_packages
BEGIN
DELETE FROM
  mls_encryption_keypairs
WHERE
  pk_sha256 = OLD.leaf_encryption_key_hash;
END;

CREATE TABLE "mls_psk_bundles" (
  id_sha256 BLOB NOT NULL PRIMARY KEY,
  psk_id BLOB NOT NULL,
  psk BLOB NOT NULL
);
