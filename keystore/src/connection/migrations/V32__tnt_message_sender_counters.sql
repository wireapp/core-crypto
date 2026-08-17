ALTER TABLE mls_groups DROP COLUMN sender_nonce;

CREATE TABLE targeted_message_tx_counters (
    conversation_id BLOB NOT NULL,
    receiver INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (conversation_id, receiver),
    FOREIGN KEY (conversation_id) REFERENCES mls_groups(id) ON DELETE CASCADE
);
