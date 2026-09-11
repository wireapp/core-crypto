# SQLite3 Multiple Ciphers in libsqlite3-sys

With the `bundled-sqlite3mc` feature, this copy of libsqlite3-sys 0.36.0 compiles SQLite3 Multiple Ciphers instead of
SQLite or SQLCipher, set up to read and write SQLCipher's format. The keystore uses it on all native targets except
Android and iOS, which keep SQLCipher; see `keystore/Cargo.toml`. The wasm keystore already uses SQLite3 Multiple
Ciphers through `sqlite-wasm-rs`.

Apart from this directory, the crate is the one published on crates.io, whose `.crate` file has the SHA-256
`95b4103cffefa72eb8428cb6b47d6627161e51c2739fc5e3b734584157bc642a` (the checksum in `Cargo.lock` before the crate was
vendored). The only changes are the `bundled-sqlite3mc` feature in `../Cargo.toml` and `../Cargo.toml.orig`, and its
handling in `../build.rs`.

## Source

- SQLite3 Multiple Ciphers 2.4.0, based on SQLite 3.53.4. For comparison, `sqlite-wasm-rs` 0.5.5 bundles 2.3.3 for the
  wasm keystore.
- `sqlite3mc-2.4.0-sqlite-3.53.4-amalgamation.zip` from
  <https://github.com/utelle/SQLite3MultipleCiphers/releases/tag/v2.4.0>
- SHA-256 of the zip: `fab0fa8838b670b2b8c392d7294a0ef3c02ce2794d5c06de3eb9a649cfb4b8c2`. It matches
  `sqlite3mc-2.4.0-SHA256SUMS`, whose Sigstore signature checks out against the certificate issued to
  `https://github.com/utelle/SQLite3MultipleCiphers/.github/workflows/build-reusable.yml@refs/heads/main`.
- Taken unchanged from the zip, with their SHA-256:
  - `sqlite3mc_amalgamation.c`: `da697f352eba8dc225279195e2cd32c2435280857227a17de665778e640ebc49`
  - `sqlite3mc_amalgamation.h`: `eae796d67d1a8236ed47b3fff858beb2d2a34f3b7ca0d8b6ea97e21729967374`
  - `sqlite3.h`: `919e7f2e8ed1d8f56ac17b412b8971c76aa5d1a879752cc6058f75e7d5910e1d`
  - `sqlite3ext.h`: `ac9645e5c9ff0cf176efdd6e75cb5e98f46295d38e02db5c4d208826a39ab4be`
- `LICENSE` is the MIT license of SQLite3 Multiple Ciphers, from the `v2.4.0` tag of its repository; the zip doesn't
  include it.
- `bindgen_bundled_version.rs` and `bindgen_bundled_version_ext.rs` are copies of the bindings in `../sqlite3/`,
  generated for SQLite 3.51.1. SQLite's C API only grows, so they cover a subset of 3.53.4. For the same reason,
  `ffi::SQLITE_VERSION` and `ffi::SQLITE_VERSION_NUMBER` say 3.51.1, while `sqlite3_libversion()` returns the version
  that actually runs, 3.53.4.

## Build configuration

See `build_bundled` in `../build.rs`:

- The default cipher scheme is SQLCipher's, version 4 in legacy mode (`CODEC_TYPE_SQLCIPHER`,
  `SQLITE3MC_USE_SQLCIPHER_LEGACY`): AES-256-CBC with an HMAC-SHA512 per page, 4096-byte pages, and the salt in the
  first 16 bytes of the file. Databases are read and written in the same format as with SQLCipher, and raw `x'…'` keys
  are taken the same way.
- The other schemes (AES-128-CBC, AES-256-CBC, RC4, Ascon, AEGIS) are left out. ChaCha20-Poly1305 stays in, unused: the
  value-level encryption of SQLite3 Multiple Ciphers doesn't build without ChaCha20 or Ascon. No crypto library is
  linked: SQLite3 Multiple Ciphers brings its own AES, SHA-512 and random number generator.
- AES uses the CPU's AES instructions where SQLite3 Multiple Ciphers supports them, after checking for them at run time:
  AES-NI on x86_64, and the Armv8 crypto extension when building for arm64 with Clang. Otherwise it runs in software.
- Temporary files stay in memory (`SQLITE_TEMP_STORE=2`), as in the SQLCipher build.
- No SQLite3 Multiple Ciphers extensions (`fileio`, `csv` and the like) are enabled; they are all opt-in.
- On Windows, advapi32 is linked for `RtlGenRandom`.

## Updating

1. Download the new amalgamation zip and its `SHA256SUMS`, `.sig` and `.pem` from the release.
1. Check the checksum and the signature, e.g.
   `cosign verify-blob --certificate …SHA256SUMS.pem --signature …SHA256SUMS.sig --certificate-identity-regexp '^https://github.com/utelle/SQLite3MultipleCiphers/' --certificate-oidc-issuer https://token.actions.githubusercontent.com …SHA256SUMS`.
1. Replace the four files above, and `LICENSE` if it changed, and update this README.
1. Keep the version close to the one `sqlite-wasm-rs` bundles for the wasm keystore.
