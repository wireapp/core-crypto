-- This isn't this table's Final Form.
--
-- The `keypairs` blob is a serialized vector of `(public_key, private_key)` pairs.
-- In principle, there's no reason that we couldn't make this a type primarily accessed
-- via bulk actions, with rowid as the primary key and an index over the
-- (conversation_id, own_leaf_index, epoch) tuple for efficient bulk queries.
-- Adding and removing keypairs would be more efficient if the table looked like that;
-- there would be no need for a read->deser->modify->ser->write pipeline in that case.
--
-- We don't do that today because ultimately this is an OpenMLS table and that
-- pipeline is built into the OpenMLS assumptions. It's been like that since
-- 51a7e1393ac277f0e621b5d2866c666edf74c687 in 2023, and changing it would require
-- adjusting the `MlsEntity` and `OpenMlsKeyStore` traits.
CREATE TABLE epoch_encryption_keypairs (
    conversation_id BLOB NOT NULL,
    own_leaf_index INTEGER NOT NULL,
    epoch INTEGER NOT NULL,
    keypairs BLOB NOT NULL,
    PRIMARY KEY (conversation_id, own_leaf_index, epoch)
);
