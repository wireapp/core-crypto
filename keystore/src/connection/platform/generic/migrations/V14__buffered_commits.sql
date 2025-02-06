CREATE TABLE mls_buffered_commits (
    conversation_id_hex TEXT UNIQUE,
    concatenated_proposal_references BLOB
);
