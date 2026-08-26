CREATE TABLE transient_message_tx_counters (
    conversation_id BLOB NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (conversation_id),
    FOREIGN KEY (conversation_id) REFERENCES mls_groups(id) ON DELETE CASCADE
);
