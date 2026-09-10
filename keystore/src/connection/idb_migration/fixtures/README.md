# Legacy IndexedDB fixtures

`legacy-idb-v10.1.0.json` is a dump of every object store of a keystore written by core-crypto v10.1.0, the
last release whose wasm keystore stored data in IndexedDB. `imports_a_database_captured_from_v10_1_0` in the
parent module restores it and runs the import over it.

The file records the database version, the encryption key, and for each object store its rows as
`{"key", "value"}` pairs. Byte strings are tagged as `{"$u8": "<hex>"}`, because JSON cannot otherwise
distinguish a `Uint8Array` from an array of numbers, and IndexedDB keys of the two kinds do not compare equal.

## Regenerating

The rows are the same as the `seed` module in the parent module's tests. To regenerate:

1. `git worktree add /tmp/cc-v10.1.0 v10.1.0`
2. Copy `generate-legacy-idb-v10.1.0.rs` to `/tmp/cc-v10.1.0/keystore/tests/fixture_gen.rs`, dropping the
   leading comment.
3. In the worktree, run the keystore wasm tests for that file only:
   `CARGO_PROFILE_TEST_STRIP=symbols wasm-pack test --headless --chrome -- ./keystore --locked --test fixture_gen`
4. The test fails on purpose, with the fixture JSON between `FIXTURE_BEGIN` and `FIXTURE_END` in its panic
   message. Copy that JSON here, removing the indentation the test harness adds to every line.
