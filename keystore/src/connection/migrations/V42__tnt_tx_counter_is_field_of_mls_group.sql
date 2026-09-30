-- We had a separate table, tnt_message_tx_counters, with two fields:
-- `(conversation_id PRIMARY KEY, count)`. That's equivalent to making
-- the count a field on the conversation, so let's just do that.

ALTER TABLE mls_groups
ADD COLUMN tnt_tx_counter INTEGER NOT NULL DEFAULT 0;

UPDATE mls_groups SET tnt_tx_counter = tnt_message_tx_counters.count
FROM tnt_message_tx_counters
WHERE tnt_message_tx_counters.conversation_id = mls_groups.id;

DROP TABLE tnt_message_tx_counters;
