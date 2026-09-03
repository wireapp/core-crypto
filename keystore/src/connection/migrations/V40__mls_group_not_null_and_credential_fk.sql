-- V39's meta migration guarantees every surviving `mls_groups` row has `epoch`, `ciphersuite`, and
-- `own_leaf_index` populated (they're always derivable once `state` deserializes), and that any
-- non-null `credential_id` actually resolves to a row in `mls_credentials`. This migration makes
-- those guarantees part of the schema: the three always-derivable columns become `NOT NULL`, and
-- `(credential_id, credential_type)` gets a real (optional) foreign key. These two fields together
-- comprise the foreign key, and should be null together when no associated credential exists.
--
-- Rebuilding `mls_groups` means dropping it and recreating it under the same name. With
-- `foreign_keys` on, dropping a table cascades through every `ON DELETE CASCADE` foreign key onto
-- it, wiping the rows in every table below rather than just leaving them referencing a
-- soon-to-be-recreated table. So those tables have to be copied out and rebuilt too, exactly as in
-- V39. Unlike V39, this doesn't change which ids exist in `mls_groups`, so there's no need to filter
-- out orphans on the way back in: every row already satisfies the foreign key it was inserted under.

CREATE TABLE new_mls_groups (
  id BLOB NOT NULL PRIMARY KEY,
  -- we have to keep the whole state in a blob because openmls doesn't expose enough information
  -- to fully persist a mls group in any other way than via this opaque blob
  state BLOB,
  -- but we can store several small fields for our own information and sort/search/filter capabilities
  epoch INTEGER NOT NULL,
  ciphersuite INTEGER NOT NULL,
  credential_id BLOB NOT NULL,
  credential_type INTEGER NOT NULL,
  own_leaf_index INTEGER NOT NULL,
  -- this field distinguishes between proper groups and pending groups
  is_pending BOOLEAN NOT NULL DEFAULT 0,
  FOREIGN KEY (credential_id, credential_type) REFERENCES mls_credentials (public_key_sha256, credential_type)
    ON DELETE RESTRICT
);

INSERT INTO new_mls_groups (id, state, epoch, ciphersuite, credential_id, credential_type, own_leaf_index, is_pending)
SELECT id, state, epoch, ciphersuite, credential_id, credential_type, own_leaf_index, is_pending
FROM mls_groups;

-- In order to add a foreign key link (above) we have to do the create -> insert select -> drop -> rename dance.
-- But in order that we don't drop all other related data having foreign keys into this table, we need to
-- do that for each of them also, before doing the main drop step.

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
FROM tnt_secrets;

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
FROM targeted_message_rx_counters;

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
FROM tnt_message_tx_counters;

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
FROM transient_message_rx_counters;

DROP TABLE transient_message_rx_counters;

ALTER TABLE new_transient_message_rx_counters RENAME TO transient_message_rx_counters;

-- mls_buffered_commits
CREATE TABLE new_mls_buffered_commits (
  conversation_id BLOB NOT NULL PRIMARY KEY,
  commit_data BLOB,
  FOREIGN KEY (conversation_id) REFERENCES new_mls_groups(id) ON DELETE CASCADE
);

INSERT INTO new_mls_buffered_commits (conversation_id, commit_data)
SELECT conversation_id, commit_data
FROM mls_buffered_commits;

DROP TABLE mls_buffered_commits;

ALTER TABLE new_mls_buffered_commits RENAME TO mls_buffered_commits;

-- now replace mls_groups; this also fixes up the tables above, whose foreign keys still say
-- `new_mls_groups` until the rename below retargets them at the final name
DROP TABLE mls_groups;
ALTER TABLE new_mls_groups RENAME TO mls_groups;
