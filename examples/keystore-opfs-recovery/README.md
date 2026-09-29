# Keystore OPFS recovery browser test

This standalone test uses the real encrypted keystore and JSPI OPFS I/O worker VFS. It commits a 4 MiB value with autocheckpoint
disabled, confirms the WAL is large, then reloads the page without closing SQLite. Reopening through `Database::open`
must preserve the value, pass `integrity_check`, restore the WAL settings, and publish a zero-length WAL before another
write. A second fixture injects an actual worker access-handle WAL truncate error during startup, checks that open fails, then retries and verifies
the data. The test exercises page termination, not power-loss durability.

Run from the repository root with Node 20+, Chrome with JSPI, and a matching ChromeDriver:

```sh
RUSTC_WRAPPER= WASM_BINDGEN_EXTERNREF=1 wasm-pack build --target web examples/keystore-opfs-recovery
CHROME_BIN=/path/to/chrome CHROMEDRIVER=/path/to/chromedriver node examples/keystore-opfs-recovery/run.mjs
```

The runner starts a localhost server with a fresh browser profile. The fixture feature is enabled only for this example
and is excluded from application builds.

The worker fixture stores files under `core-crypto/worker-v1`. Existing legacy OPFS
stores are rejected by the worker format gate; this integration does not migrate them.
