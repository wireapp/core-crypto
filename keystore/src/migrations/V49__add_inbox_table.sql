-- Create a single Inbox table.
--
-- This needs to be populated by a meta-migration, but it replaces both
-- `mls_pending_messages` and `mls_buffered_commits`.

-- waiting_for is an enum, but Sqlite doesn't do enums, so we encode
-- waiting_for as an integer with this mapping:
--
-- 1. PendingJoin: these messages arrived for a pending group which has not yet been merged
-- 2. Epoch: these messages were delivered for a future epoch
-- 3. Proposal: this commit message references a proposal which was not yet received

-- content_type comes directly from OpenMLS, and we depend on it for ordering.
--
-- 1. Application
-- 2. Proposal
-- 3. Commit
--
-- We don't check these values in case OpenMLS decides to add new content types in the future.

-- arrival_sequence must be provided externally, and is thus vulnerable to TOCTOU.
-- we do have two advantages:
-- 1. Sqlite can do the uniqueness check for us, which avoids TOCTOU
-- 2. Its uniqueness check impl means that we get an efficient query on `SELECT MAX(arrival_sequence) FROM mls_inbox`.
--
-- Note also: it doesn't matter if the table drains and we end up resetting the arrival sequence to 0.
-- The only property that matters to us is that they increase monotonically within the table.

CREATE TABLE mls_inbox (
    conversation_id BLOB NOT NULL,
    message BLOB NOT NULL,
    message_hash BLOB NOT NULL CHECK (length(message_hash) = 32), -- sha256sum(message); so the PK index doesn't store the whole message
    content_type INTEGER NOT NULL, -- mls content type, used for ordering the messages for replay
    waiting_for INTEGER NOT NULL CHECK (waiting_for IN (1, 2, 3)), -- what we are fundamentally waiting for
    epoch INTEGER NOT NULL CHECK (epoch >= 0), -- the epoch of the message
    arrival_sequence INTEGER NOT NULL UNIQUE, -- we have to provide this ourselves
    PRIMARY KEY (conversation_id, message_hash), -- one identical message per conversation
    CHECK (content_type = 3 OR waiting_for <> 3), -- a missing proposal row is always a commit
    FOREIGN KEY (conversation_id) REFERENCES mls_groups (id) ON DELETE CASCADE
);

CREATE INDEX idx_mls_inbox_conversation_id_waiting_for_epoch ON mls_inbox (conversation_id, waiting_for, epoch);
