-- Adjust keypackage storage. We want keypackages to cascade-delete from credentials,
-- and hpke init and leaf keys to cascade-delete when the keypackages do.
--
-- To get there, we need a 3 step process:
--
-- 1. add nullable fields (this migration)
-- 2. fill those fields (following meta-migration)
-- 3. make the new fields non-nullable (where applicable), foreign keys (where applicable), triggers, etc.

-- We want a foreign key such that when a credential is removed the key packages remove by cascade.
ALTER TABLE mls_key_packages ADD COLUMN credential_id BLOB NULL;
ALTER TABLE mls_key_packages ADD COLUMN credential_type INTEGER NULL;

-- There's a 1:1 relationship between key packages and "hpke private keys" (init keys).
-- Openmls thinks they're distinct entities, but it always (in our usage) writes a triple
-- (key package, leaf key, init key) and then deletes each element right after related key packages,
-- except for the leaf keys, which may be deleted sooner due to processing a Welcome.
-- So we're just going to combine the init keys into the key packages table.
-- This isn't entirely free--openmls will still use separate reads/writes as though
-- they were in fact separate entities--but it greatly simplifies lifecycle management.

-- we don't need to store the whole public init key, because that's already part of the
-- serialized keypackage blob. We only store the hash so we can find the right keypackage
-- when operating on the synthetic init key entity.
ALTER TABLE mls_key_packages ADD COLUMN hpke_init_public_key_hash BLOB NULL;
ALTER TABLE mls_key_packages ADD COLUMN hpke_init_private_key BLOB NULL;
CREATE UNIQUE INDEX idx_mls_key_packages_hpke_init_public_key_hash ON mls_key_packages(hpke_init_public_key_hash);

-- mls_encryption_keypairs stores two kinds of keys in one table:
-- - keypackage leaf keys
-- - group update leaf keys
--
-- Even though there's also a 1:1 relationship between a keypackage and a related leaf key,
-- no invocation of `store::<EncryptionKeyPair>` knows what kind of key it is, so we retain
-- a separate table. Even so, we add a column to the keypackage table; we can't have a foreign key
-- from mls_encryption_keypairs to mls_key_packages (because then the group update leaf keys couldn't store),
-- but we can have a trigger forwarding deletions from the keypackage table to the encryption keypairs table.
ALTER TABLE mls_key_packages ADD COLUMN leaf_encryption_key_hash BLOB NULL;
CREATE UNIQUE INDEX idx_mls_key_packages_leaf_encryption_key_hash ON mls_key_packages(leaf_encryption_key_hash);
