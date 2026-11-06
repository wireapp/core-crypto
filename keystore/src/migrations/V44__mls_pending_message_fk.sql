-- Add a foreign key to mls_pending_messages.
--
-- We couldn't do this in the past because pending messages might reference a real conversation, or
-- a pending one. But we've unified those into a single table, so now we can have a real FK.

CREATE TABLE new_mls_pending_messages (
  hash_sha256 BLOB PRIMARY KEY NOT NULL,  -- hash of the concatenation of (conversation_id, message)
  conversation_id BLOB NOT NULL,
  message BLOB NOT NULL,
  FOREIGN KEY (conversation_id) REFERENCES mls_groups (id) ON DELETE CASCADE
);

INSERT INTO new_mls_pending_messages (hash_sha256, conversation_id, message)
SELECT hash_sha256, conversation_id, message
FROM mls_pending_messages
WHERE conversation_id IN (SELECT id FROM mls_groups);

DROP TABLE mls_pending_messages;

ALTER TABLE new_mls_pending_messages RENAME TO mls_pending_messages;

CREATE INDEX idx_mls_pending_messages_conversation_id ON mls_pending_messages (conversation_id);
