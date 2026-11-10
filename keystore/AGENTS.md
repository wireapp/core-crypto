# Keystore migrations

These rules extend the root `AGENTS.md` for work on the keystore crate.

- SQL migrations are applied by refinery. Whether you can edit one depends on whether it has been released:
  - Added on the current branch: edit freely.
  - Already on `main` but not in any release: editing is acceptable, but tell the human first. Only plain `vX.Y.Z` tags
    are releases. Tags with a suffix, such as `v10.0.0-pre.12` or `v10.3.1-test1`, are not: people installing those know
    the risks. To show a migration is unreleased, find the commit that added it with
    `git log --diff-filter=A --format=%H -- <file>`, then check that
    `git tag --contains <sha> 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$'` prints nothing. Let the human decide whether
    to edit it or add a new migration. There's no team convention for this yet.
  - Released: don't edit it. Fix forward with a new migration. We have occasionally edited released migrations to fix
    catastrophic bugs, but that's a team decision, not something to propose casually.
- Some tables are rebuilt by later migrations, so the `CREATE TABLE` in any single file can be misleading. To see the
  real end state, use `compile-schema` (<https://github.com/wireapp/compile-schema>):
  `compile-schema keystore/src/connection/migrations`. The migrations register a custom `sha256_blob` function, so the
  plain `sqlite3` CLI can't apply them.
- `keystore/src/connection/composite-schema.sql` is generated. CI fails if it's stale. Regenerate it with
  `compile-schema` after changing migrations. Never edit it by hand, and never add comments to it.
- `released_migration_checksums_are_unchanged` pins every migration's checksum. Append an entry when you add a
  migration; the failing test prints the tuple to add. Editing an unreleased migration means updating its entry. For a
  released migration, a failure here is the test telling you to fix forward instead.
- When a migration meets a row that breaks the new invariants, such as a stray `NULL`, a value of the wrong type, or a
  dangling reference, drop the row and let the migration succeed. A failed migration means the consumer can't open the
  database at all, and they have no way to recover. Rows like that were already unreachable or unloadable, so dropping
  them loses nothing usable. In a table rebuild, guard the `INSERT … SELECT` with a `WHERE`. In a meta migration, log a
  warning and delete the row. Say in a comment that this is deliberate.
- Much of what the keystore stores is opaque bytes: group state, key packages, key material, serialized credentials and
  so on. Keystore tests, including migration tests, only need to show those bytes survive exactly, so arbitrary bytes
  are fine. Building real values (an `MlsGroup` and matching credential, say) usually needs a crypto provider the
  keystore crate doesn't have. Only do it if it covers a gap no other test covers, and say which gap.
- The exception is a blob some meta migration parses, as V39 does with group state. That migration drops rows it can't
  read, so arbitrary bytes don't survive to the latest schema. To test such a migration, run it over the bundled real
  database `crypto-ffi/bindings/jvm/src/test/resources/db-v10002003.sqlite` (the `DB` constant in the migration tests)
  rather than building values.
- `keystore/src/connection/idb_migration/legacy/` exists only to move old IndexedDB data into SQLite once. It's in
  minimal-maintenance mode. If a change there works, it ships. Don't propose style or fidelity cleanups.
- The import writes into the schema as of V22, through each entity's `save`. When an entity's shape changes, the import
  needs a frozen copy of the old shape, like `StoredCredentialV36` or `V33StoredEpochEncryptionKeypair` in
  `keystore/src/migrations.rs`.
