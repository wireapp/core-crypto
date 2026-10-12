ALTER TABLE tnt_secrets RENAME TO old_epoch_data;

-- this table stores the actual foreign credentials
-- we store each one exactly once per distinct signature key
-- because they can be quite large.
CREATE TABLE foreign_credentials (
  hash BLOB NOT NULL PRIMARY KEY, -- hash of length-prefixed credential and signature key
  credential BLOB NOT NULL,
  signature_key BLOB NOT NULL
);

-- we associate foreign credential data, per conversation, epoch, and leaf.
-- in the normal case where a credential is constant over multiple epochs and conversations, it only needs to be stored once.
CREATE TABLE old_epoch_member_data (
  conversation_id BLOB NOT NULL,
  epoch INTEGER NOT NULL,
  leaf_node_index INTEGER NOT NULL,
  foreign_credential_hash BLOB NOT NULL,
  PRIMARY KEY (conversation_id, epoch, leaf_node_index),
  FOREIGN KEY (conversation_id, epoch) REFERENCES old_epoch_data(conversation_id, epoch) ON DELETE CASCADE,
  FOREIGN KEY (foreign_credential_hash) REFERENCES foreign_credentials(hash) ON DELETE RESTRICT
);

CREATE INDEX old_epoch_member_data_foreign_credential_hash
ON old_epoch_member_data (foreign_credential_hash);

CREATE TRIGGER drop_unreferenced_foreign_credential
AFTER DELETE ON old_epoch_member_data
BEGIN
  DELETE FROM foreign_credentials
  WHERE hash = OLD.foreign_credential_hash
  AND NOT EXISTS (
    SELECT 1 FROM old_epoch_member_data
    WHERE foreign_credential_hash = OLD.foreign_credential_hash
  );
END;
