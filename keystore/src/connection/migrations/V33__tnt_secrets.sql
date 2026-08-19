CREATE TABLE tnt_secrets (
    conversation_id BLOB NOT NULL,
    epoch INTEGER NOT NULL,
    hpke_private_key BLOB NOT NULL,
    group_context BLOB NOT NULL,
    targeted_message_psk BLOB NOT NULL,
    PRIMARY KEY (conversation_id, epoch),
    FOREIGN KEY (conversation_id) REFERENCES mls_groups(id) ON DELETE CASCADE
);
