-- The absence of a primary key on the `mls_pending_messages` table is causing real problems.
-- This migration creates a primary key by concatenating the conversation id with the message and hashing.
--
-- Rebuilding the table is also the only way to drop a constraint in SQLite, so this migration takes the
-- opportunity to drop the foreign key which V7 declared on this table. That removal is deliberate and it
-- fixes a bug:
--
-- V7 introduced `mls_pending_messages` for a single purpose: holding messages which arrived for a group we
-- had joined by external commit but had not yet merged. Every such group has a row in `mls_pending_groups`,
-- so `FOREIGN KEY(id) REFERENCES mls_pending_groups(id)` described the data accurately, and the column was
-- named `foreign_id` to match.
--
-- That is no longer the only writer. `ConversationMut::buffer_future_message` buffers messages which arrive
-- for epoch `n + 1` while we are still in epoch `n`, and it does so for conversations which are fully
-- established: they have a row in `mls_groups` and, by definition, none in `mls_pending_groups`. The
-- constraint therefore rejected every save from that path. Buffering a future message and committing the
-- transaction failed with `FOREIGN KEY constraint failed`.
--
-- Retargeting the constraint is not possible, because there is no single parent table. A buffered message
-- belongs to whichever of `mls_groups` or `mls_pending_groups` holds its conversation, and SQLite cannot
-- express a reference which may point into either one. So the constraint goes, and the relationship between
-- a buffered message and its conversation is maintained by the code which owns both tables.
--
-- Keeping it would also have made this migration a hazard in its own right: the backfill below is an
-- `INSERT ... SELECT` into the new table, so a single pre-existing row whose conversation is not a pending
-- group would fail the check and leave the database unopenable.

CREATE TABLE mls_pending_messages_new (
    hash_sha256 BLOB PRIMARY KEY NOT NULL, -- hash of the concatenation of (conversation_id, message)
    conversation_id BLOB NOT NULL,
    message BLOB NOT NULL
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
