-- Ensure that the epoch_encryption_keypairs table references a live conversation
-- Sqlite doesn't support adding new constraints to a live table, so we have to add the foreign key
-- to a new table and copy all the data over.

CREATE TABLE new_epoch_encryption_keypairs (
    conversation_id BLOB NOT NULL,
    own_leaf_index INTEGER NOT NULL,
    epoch INTEGER NOT NULL,
    keypairs BLOB NOT NULL,
    PRIMARY KEY (conversation_id, own_leaf_index, epoch),

    -- DEFERRABLE INITIALLY DEFERRED means that we only enforce this constraint
    -- when the outermost transaction / savepoint is committed.
    FOREIGN KEY (conversation_id) REFERENCES mls_groups(id)
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
);

INSERT OR IGNORE
INTO new_epoch_encryption_keypairs (
    conversation_id,
    own_leaf_index,
    epoch,
    keypairs
)
SELECT conversation_id,
    own_leaf_index,
    epoch,
    keypairs
FROM epoch_encryption_keypairs
WHERE conversation_id IN (SELECT id FROM mls_groups);

DROP TABLE epoch_encryption_keypairs;

ALTER TABLE new_epoch_encryption_keypairs RENAME TO epoch_encryption_keypairs;
