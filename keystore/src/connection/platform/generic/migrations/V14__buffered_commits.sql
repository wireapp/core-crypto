CREATE TABLE mls_buffered_commits (
    conversation_id_hex TEXT UNIQUE,
    commit_data BLOB
);
