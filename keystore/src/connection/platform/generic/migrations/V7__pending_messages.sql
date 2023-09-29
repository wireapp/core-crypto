CREATE TABLE mls_pending_messages (
    id BLOB,
    message BLOB,
    FOREIGN KEY(id) REFERENCES mls_pending_groups(id)
);
