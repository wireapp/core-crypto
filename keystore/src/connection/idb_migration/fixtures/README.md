# Legacy IndexedDB fixtures

Each `legacy-idb-<version>.json` is a dump of every object store of a keystore written by that core-crypto release.
The tests in the parent module restore them into IndexedDB and run the legacy upgrade chain and the import over
them. They exist because the legacy entities in this crate both write and read, so they always agree with
themselves; only data an old client actually wrote can show where the code has drifted from the field.

Each file records the database version, the encryption key, and for each object store its rows as
`{"key", "value"}` pairs. Byte strings are tagged as `{"$u8": "<hex>"}`, because JSON cannot otherwise
distinguish a `Uint8Array` from an array of numbers, and IndexedDB keys of the two kinds do not compare equal.

## `legacy-idb-v9.3.4.json`

The v9 series wrote IndexedDB schema version 5, so restoring this exercises the legacy chain's v6 to v11 upgrade
steps on real rows before the import runs. The keystore was populated through that release's public API, so every
row is one a real client could have written: a basic credential and its signature keypair, an established
conversation with a second member, a conversation the client is in the middle of joining by external commit
together with a message buffered for it, Proteus state including a session with the other client, a PKI
environment of trust anchor, intermediate, and CRL, and consumer data. The ids and contents the loader asserts on
are constants at the top of `generate-legacy-idb-v9.3.4.rs`.

## `legacy-idb-v10.1.0.json`

v10.1.0 was the last release whose wasm keystore wrote IndexedDB, at schema version 11. Its rows are the ones the
`seed` module in the parent module's tests describes, saved one per store through that release's keystore API. It
is kept alongside the v9.3.4 capture because the two generations keyed some rows differently, unique entities in
particular, and each capture catches what the other cannot.

## Regenerating

Both generators are kept next to the fixtures. Neither compiles here: each is written against the API of the tag
it captures, and only builds in a checkout of that tag.

1. `git worktree add /tmp/cc-<tag> <tag>`
2. Copy the generator into the worktree as an integration test, dropping the leading comment:
   `crypto/tests/fixture_gen.rs` for v9.3.4, `keystore/tests/fixture_gen.rs` for v10.1.0.
3. For v9.3.4 only: in the worktree's `crypto/Cargo.toml`, add `wasm-bindgen-test = "0.3"` and
   `console_error_panic_hook = "0.1"` to `[dev-dependencies]`, and move `tempfile`, `smol`, and `smol-macros`
   into the `[target.'cfg(not(target_family = "wasm"))'.dev-dependencies]` section. They pull in native-only
   crates, and that release never built its crypto tests for wasm.
4. Run the one test target. For v10.1.0, `wasm-pack test --headless --chrome -- ./keystore --test fixture_gen`
   works. For v9.3.4, `wasm-pack test` would also build the crate's unit tests, which do not build for wasm, so
   drive the runner directly, with a `wasm-bindgen-test-runner` matching the `wasm-bindgen` version in the
   worktree's `Cargo.lock` (`cargo install wasm-bindgen-cli --version <that version>`):

   ```sh
   CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=<path to wasm-bindgen-test-runner> \
   CHROMEDRIVER=<path to chromedriver> WASM_BINDGEN_TEST_ONLY_WEB=1 \
   cargo test --target wasm32-unknown-unknown -p core-crypto --test fixture_gen
   ```

5. The test fails on purpose, with the fixture JSON between `FIXTURE_BEGIN` and `FIXTURE_END` in its panic
   message. Copy that JSON here, removing the indentation the test harness adds to every line.

The certificates embedded in the v9.3.4 generator were made with openssl: an Ed25519 root, an intermediate signed
by it, and an empty CRL issued by the intermediate.
