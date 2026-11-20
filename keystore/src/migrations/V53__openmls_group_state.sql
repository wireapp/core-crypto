-- Storage for the state openmls writes through its `StorageProvider` that the existing schema has no place for:
-- group state, and the leaf encryption private key of a key package.
--
-- openmls persists a group piece by piece. The pieces that exist once per group become columns of `mls_groups`;
-- the two which are lists get child tables. core-crypto inserts the `mls_groups` row before openmls writes anything,
-- so openmls only ever updates an existing row.
--
-- A NULL column means openmls hasn't written that piece, or has deleted it.
--
-- Most pieces are postcard-serialized openmls types, opaque to us. Where a piece has a meaningful SQL type it gets
-- one:
--
-- - `own_leaf_index` already exists, and openmls writes it directly. `epoch` and `ciphersuite` already exist too,
--   and are kept in step with `context`.
-- - `interim_transcript_hash` and `confirmation_tag` are the raw hash and MAC bytes.
-- - `group_status` encodes openmls's `MlsGroupState`:
--
--   0. Operational
--   1. PendingCommit: the commit itself is in `pending_commit`
--   2. Inactive
--
-- The V53 meta migration converts `mls_groups.state`, the whole group as serialized by the old openmls fork, to
-- these columns.

ALTER TABLE mls_groups ADD COLUMN join_config BLOB;
ALTER TABLE mls_groups ADD COLUMN tree BLOB;
ALTER TABLE mls_groups ADD COLUMN context BLOB;
ALTER TABLE mls_groups ADD COLUMN interim_transcript_hash BLOB;
ALTER TABLE mls_groups ADD COLUMN confirmation_tag BLOB;
ALTER TABLE mls_groups ADD COLUMN group_status INTEGER CHECK (group_status IN (0, 1, 2));
ALTER TABLE mls_groups ADD COLUMN pending_commit BLOB CHECK ((pending_commit IS NOT NULL) = (group_status IS 1));
ALTER TABLE mls_groups ADD COLUMN message_secrets BLOB;
ALTER TABLE mls_groups ADD COLUMN resumption_psk_store BLOB;
ALTER TABLE mls_groups ADD COLUMN epoch_secrets BLOB;

-- openmls stores a key package together with both of its private keys, as one `KeyPackageBundle`. The public key
-- package stays in `key_package` and the HPKE init private key in `hpke_init_private_key`. This column holds the
-- third part: the private half of the leaf node's encryption key.
--
-- The old openmls fork kept that key in `mls_encryption_keypairs`. The V53 meta migration moves it here.
ALTER TABLE mls_key_packages ADD COLUMN leaf_encryption_private_key BLOB;

-- Leaf nodes we have proposed for ourselves, in the order openmls appended them.
--
-- `id` is the rowid. SQLite assigns a new rowid one past the largest in the table, so ordering by it gives append
-- order within a group.
CREATE TABLE mls_group_own_leaf_nodes (
    id INTEGER PRIMARY KEY,
    group_id BLOB NOT NULL,
    leaf_node BLOB NOT NULL,
    FOREIGN KEY (group_id) REFERENCES mls_groups (id) ON DELETE CASCADE
);

CREATE INDEX idx_mls_group_own_leaf_nodes_group_id ON mls_group_own_leaf_nodes (group_id);

-- Proposals queued for the next commit.
--
-- `id` is the rowid, so ordering by it gives the order the proposals were queued, as in `mls_group_own_leaf_nodes`.
-- It has to be declared: `VACUUM` may renumber an implicit rowid.
CREATE TABLE mls_group_queued_proposals (
    id INTEGER PRIMARY KEY,
    group_id BLOB NOT NULL,
    proposal_ref BLOB NOT NULL,
    proposal BLOB NOT NULL,
    UNIQUE (group_id, proposal_ref),
    FOREIGN KEY (group_id) REFERENCES mls_groups (id) ON DELETE CASCADE
);
