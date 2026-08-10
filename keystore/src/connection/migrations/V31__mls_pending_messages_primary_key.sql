-- The absence of a primary key on the `mls_pending_messages` table is causing real problems.
-- This migration creates a primary key by concatenating the conversation id with the message and hashing.

CREATE TABLE mls_pending_messages_new (
    hash_sha256 BLOB PRIMARY KEY NOT NULL, -- hash of the concatenation of (conversation_id, message)
    conversation_id BLOB NOT NULL,
    message BLOB NOT NULL,
    FOREIGN KEY(conversation_id) REFERENCES mls_pending_groups(id)
);

INSERT INTO mls_pending_messages_new (
    hash_sha256,
    conversation_id,
    message
)
SELECT
    -- `printf('%016x', ...)` is a big-endian u64 length prefix on the conversation id, without
    -- which the boundary between the two hashed fields would be ambiguous.
    -- Despite its name, `sha256_blob` returns hex text. `Sha256Hash` binds the raw digest, and
    -- SQLite never compares a blob equal to text, so the outer `unhex` is what makes the
    -- backfilled keys reachable from Rust.
    unhex(sha256_blob(unhex(concat(printf('%016x', length(id)), hex(id), hex(message))))), -- concat doesn't work on raw blobs
    id,
    message
FROM mls_pending_messages;

DROP TABLE mls_pending_messages;

ALTER TABLE mls_pending_messages_new RENAME TO mls_pending_messages;

-- most of the time we actually search pending messages by the conversation id
CREATE INDEX idx_mls_pending_messages_conversation_id ON mls_pending_messages(conversation_id);
