-- 1. Create the new table with the correct constraint
CREATE TABLE mls_pending_groups_new (
  id BLOB PRIMARY KEY,
  state BLOB,
  cfg BLOB,
  parent_id BLOB
);

-- 2. Copy existing data
INSERT INTO mls_pending_groups_new (id, state, cfg, parent_id)
SELECT id, state, cfg, parent_id
FROM mls_pending_groups;

-- 3. Drop old table
DROP TABLE mls_pending_groups;

-- 4. Rename new table
ALTER TABLE mls_pending_groups_new RENAME TO mls_pending_groups;
