-- we can correctly restrict credential deletion without this index, but it turns out
-- there's no implicit index created, so it relies on a full-table scan.
-- adding this index means that we can perform the restriction check quickly.
CREATE INDEX idx_mls_groups_credential_fk ON mls_groups (credential_id, credential_type);
