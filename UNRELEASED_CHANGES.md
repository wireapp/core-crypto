# Changelog

## Unreleased

### Features

- introduce `Metabuilder` (f556fc7)
- support instantiating sessions with mixed credential types (c8471b2)
- allow session instantiation with test chain and basic credentials (c700f04)
- add all required abstactions (a59c587)
- [**breaking**] crypto-ffi: remove wasmFilePath (92e6dad)
- [**breaking**] crypto-ffi: bindings: remove getCredentialInUse (81a75a8)
- crypto: remove generate_raw_keypairs (1ea2b76)
- [**breaking**] crypto-ffi: remove mls_generate_keypairs (5d5cdc1)
- [**breaking**] crypto-ffi: bindings: remove mlsGenerateKeypairs (ad9a6b8)
- [**breaking**] crypto: remove init_with_external_client_id (625cbec)
- [**breaking**] crypto-ffi: remove mls_init_with_client_id (40bbbeb)
- [**breaking**] crypto-ffi: bindings: remove mlsInitWithClientId (10a80ca)
- add `remove_guarded()` (6733dad)
- add `update_guarded_with()` (8d98ef2)
- add `advance_epoch()` API (f2c2592)

### Bug Fixes

- unreleased changes generation had an extra token (bc56760)
- crypto-ffi: fix field names in X509Identity on wasm (6481d8c)
- initWasm was being called with the wrong property field. (ca52dbf)
- allow registering epoch observer before calling mls_init (0cad9a3)

### Documentation

- publish unreleased changes to github pages (6c33a70)
- add internal links to high-level documents (0ca52eb)
- simplify docs directory structure (e9a7c2f)
- eliminate fake docs module / submodules (a459167)

### Testing

- remove leaf node validation tests [WPB-18083] (c2ae76d)
- fix: `TestContext::sessions_x509()` should always create x509 sessions (49ee4e6)
- add test handling self-commit after failed transaction [WPB-17464] (01a6d46)

### Other Breaking Changes

- [**breaking**] eliminate certain wasm-specific discrepancies from core-crypto-ffi (1143d11)


