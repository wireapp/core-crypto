-- The v49 meta-migration copied all relevant data into the new `mls_inbox` table,
-- so we can get rid of the leftovers now.

DROP TABLE mls_pending_messages;
DROP TABLE mls_buffered_commits;
