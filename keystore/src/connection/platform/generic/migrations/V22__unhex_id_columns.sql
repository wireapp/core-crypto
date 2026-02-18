---- mls_epoch_encryption_keypairs ----
CREATE TABLE mls_epoch_encryption_keypairs_new (
    id BLOB UNIQUE,
    keypairs BLOB
);

INSERT INTO mls_epoch_encryption_keypairs_new (id, keypairs)
SELECT unhex(id_hex), keypairs
FROM mls_epoch_encryption_keypairs;

DROP TABLE mls_epoch_encryption_keypairs;

ALTER TABLE mls_epoch_encryption_keypairs_new
RENAME TO mls_epoch_encryption_keypairs;

CREATE INDEX idx_mls_epoch_encryption_keypairs_id
ON mls_epoch_encryption_keypairs(id);


---- mls_keypackages ----
CREATE TABLE mls_keypackages_new (
    keypackage_ref BLOB UNIQUE,
    keypackage BLOB
);

INSERT INTO mls_keypackages_new (keypackage_ref, keypackage)
SELECT unhex(keypackage_ref_hex), keypackage
FROM mls_keypackages;

DROP TABLE mls_keypackages;

ALTER TABLE mls_keypackages_new
RENAME TO mls_keypackages;

CREATE INDEX idx_mls_keypackages_keypackage_ref
ON mls_keypackages(keypackage_ref);


---- mls_groups ----
CREATE TABLE mls_groups_new (
    id BLOB UNIQUE,
    state BLOB,
    parent_id BLOB
);

INSERT INTO mls_groups_new (id, parent_id, state)
SELECT unhex(id_hex), parent_id, state
FROM mls_groups;

DROP TABLE mls_groups;

ALTER TABLE mls_groups_new
RENAME TO mls_groups;

CREATE INDEX idx_mls_groups_id
ON mls_groups(id);


---- mls_buffered_commits ----
CREATE TABLE mls_buffered_commits_new (
    conversation_id BLOB UNIQUE,
    commit_data BLOB
);

INSERT INTO mls_buffered_commits_new (conversation_id, commit_data)
SELECT unhex(conversation_id_hex), commit_data
FROM mls_buffered_commits;

DROP TABLE mls_buffered_commits;

ALTER TABLE mls_buffered_commits_new
RENAME TO mls_buffered_commits;

CREATE INDEX idx_mls_buffered_commits_conversation_id
ON mls_buffered_commits(conversation_id);
