CREATE TABLE new_mls_groups (
  id BLOB NOT NULL PRIMARY KEY,
  -- we have to keep the whole state in a blob because openmls doesn't expose enough information
  -- to fully persist a mls group in any other way than via this opaque blob
  state BLOB,
  -- but we can store several small fields for our own information and sort/search/filter capabilities
  epoch INTEGER NULL,
  ciphersuite INTEGER NULL,
  credential_id BLOB NULL,
  credential_type INTEGER NULL,
  own_leaf_index INTEGER NULL,
  -- this field distinguishes between proper groups and pending groups
  is_pending BOOLEAN NOT NULL DEFAULT 0
);

-- copy the pending groups first: if both exist, a rejoining join-by-external-commit is in progress
-- and the pending group should take priority over an existing group
-- note we intentionally discard cfg, parent_id; both were dead fields already omitted
-- from the code which uses this DB
INSERT INTO new_mls_groups (id, state, is_pending)
SELECT id, state, 1
FROM mls_pending_groups;

-- copy the real groups, discarding any which conflict with a pending group
INSERT OR IGNORE INTO new_mls_groups (id, state)
SELECT id, state
FROM mls_groups;

-- migrate a bunch of secondary tables which all need to reference the correct new table

-- tnt_secrets
CREATE TABLE new_tnt_secrets (
  conversation_id BLOB NOT NULL,
  epoch INTEGER NOT NULL,
  hpke_private_key BLOB NOT NULL,
  group_context BLOB NOT NULL,
  targeted_message_psk BLOB NOT NULL,
  PRIMARY KEY (conversation_id, epoch),
  FOREIGN KEY (conversation_id) REFERENCES new_mls_groups(id) ON DELETE CASCADE
);

INSERT INTO new_tnt_secrets (conversation_id, epoch, hpke_private_key, group_context, targeted_message_psk)
SELECT conversation_id, epoch, hpke_private_key, group_context, targeted_message_psk
FROM tnt_secrets
WHERE conversation_id IN (SELECT id FROM new_mls_groups);

DROP TABLE tnt_secrets;

ALTER TABLE new_tnt_secrets RENAME TO tnt_secrets;

-- targeted_message_rx_counters
CREATE TABLE new_targeted_message_rx_counters (
  conversation_id BLOB NOT NULL,
  sender INTEGER NOT NULL,
  epoch INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (conversation_id, sender, epoch),
  FOREIGN KEY (conversation_id) REFERENCES new_mls_groups(id) ON DELETE CASCADE
);

INSERT INTO new_targeted_message_rx_counters (conversation_id, sender, epoch, count)
SELECT conversation_id, sender, epoch, count
FROM targeted_message_rx_counters
WHERE conversation_id IN (SELECT id FROM new_mls_groups);

DROP TABLE targeted_message_rx_counters;

ALTER TABLE new_targeted_message_rx_counters RENAME TO targeted_message_rx_counters;

-- tnt_message_tx_counters
CREATE TABLE new_tnt_message_tx_counters (
  conversation_id BLOB NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (conversation_id),
  FOREIGN KEY (conversation_id) REFERENCES new_mls_groups(id) ON DELETE CASCADE
);

INSERT INTO new_tnt_message_tx_counters (conversation_id, count)
SELECT conversation_id, count
FROM tnt_message_tx_counters
WHERE conversation_id IN (SELECT id FROM new_mls_groups);

DROP TABLE tnt_message_tx_counters;

ALTER TABLE new_tnt_message_tx_counters RENAME TO tnt_message_tx_counters;

-- transient_message_rx_counters
CREATE TABLE new_transient_message_rx_counters (
  conversation_id BLOB NOT NULL,
  sender INTEGER NOT NULL,
  epoch INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (conversation_id, sender, epoch),
  FOREIGN KEY (conversation_id) REFERENCES new_mls_groups(id) ON DELETE CASCADE
);

INSERT INTO new_transient_message_rx_counters (conversation_id, sender, epoch, count)
SELECT conversation_id, sender, epoch, count
FROM transient_message_rx_counters
WHERE conversation_id IN (SELECT id FROM new_mls_groups);

DROP TABLE transient_message_rx_counters;

ALTER TABLE new_transient_message_rx_counters RENAME TO transient_message_rx_counters;

-- now replace the old tables
DROP TABLE mls_groups;
DROP TABLE mls_pending_groups;
ALTER TABLE new_mls_groups RENAME TO mls_groups;

-- finally regenerate mls_buffered_commits, which previously couldn't have a foreign key
-- because it might point to a pending group or a real one.
CREATE TABLE new_mls_buffered_commits (
  conversation_id BLOB NOT NULL PRIMARY KEY,
  commit_data BLOB,
  FOREIGN KEY (conversation_id) REFERENCES mls_groups(id) ON DELETE CASCADE
);

INSERT INTO new_mls_buffered_commits (conversation_id, commit_data)
SELECT conversation_id, commit_data
FROM mls_buffered_commits
WHERE conversation_id IN (SELECT id FROM mls_groups);

DROP TABLE mls_buffered_commits;

ALTER TABLE new_mls_buffered_commits RENAME TO mls_buffered_commits;

-- note that we don't add a corresponding foreign key to `mls_pending_message` because
-- we still have to be able to buffer messages which arrive from future groups which
-- themselves have not yet been persisted
