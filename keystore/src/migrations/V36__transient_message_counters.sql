CREATE TABLE tnt_message_tx_counters (
    conversation_id BLOB NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (conversation_id),
    FOREIGN KEY (conversation_id) REFERENCES mls_groups(id) ON DELETE CASCADE
);

CREATE TABLE transient_message_rx_counters (
    conversation_id BLOB NOT NULL,
    sender INTEGER NOT NULL,
    epoch INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (conversation_id, sender, epoch),
    FOREIGN KEY (conversation_id) REFERENCES mls_groups(id) ON DELETE CASCADE
);
