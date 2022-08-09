# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2022-08-08

### Bug Fixes

- Updated RustCrypto dependencies to match hpke-rs requirements
- Group was not persisted after decrypting an application message
- UniFFI wrong type defs
- Aes_gcm compilation issue
- WASM persistence & CoreCrypto Async edition
- 'client_keypackages' does not require mutable access on 'mls_client'
- Add_member/remove_member IoError
- Incorrect number of keypackages returned
- Added support for MLS Group persistence [CL-5]

### Documentation

- Added bindings docs where appropriate + generated gh-pages
- Fix Client struct documentation
- Improving docs of Core-Crypto - [CL-50] ([#60](https://github.com/wireapp/core-crypto/issues/60))

### Features

- Add API to wipe specific group from core crypto [CL-55] ([#81](https://github.com/wireapp/core-crypto/issues/81))
- Adding validation to external proposal [CL-51] ([#71](https://github.com/wireapp/core-crypto/issues/71))
- Decrypting a commit now also return a delay when there are pending proposals
- Decrypting a commit now also return a delay when there are pending proposals
- 'commit_delay' now uses openmls provided leaf index instead of computing it ourselves. It is also now infallible.
- Ensure consistent state
- [**breaking**] Add commit delay when a message with prending proposals is processed [CL-52] ([#67](https://github.com/wireapp/core-crypto/issues/67))
- Added KeyPackage Pruning
- Added support for external entropy seed
- Join by external commit support - CL-47 ([#57](https://github.com/wireapp/core-crypto/issues/57))
- Added Entity testing to keystore
- External remove proposal support
- Supports and validates x509 certificates as credential
- Expose function to self update the key package to FFI and Wasm #CL-17 ([#48](https://github.com/wireapp/core-crypto/issues/48))
- Added support for wasm32-unknown-unknown target
- Support external add proposal
- Added method to leave a conversation
- Enforce (simple) invariants on MlsCentralConfiguration
- Expose add/update/remove proposal

### Miscellaneous Tasks

- Remove 'group()' test helper and inlined it
- Fix cli compilation and update it a bit
- Removed CryptoError variant `CentralConfigurationError`
- Avoid cloning credential
- Use shorthand for not using generics in conversation
- Factorize group accessors in conversation.rs
- Fix some clippy warnings
- Remove .idea in sample anroid app
- Remove unnecessary path prefixes imports
- Remove useless mutable borrow in Client methods
- Add Intellij files to gitignore
- Bump jvm and android version
- Add jvm linux support

### Performance

- Avoid cloning conversation extra members when creating the former

### Refactor

- Moved run_with_* test utils in a test_utils mod
- Use shorthand for generics in Central
- Factorize keystore update when group state change from a conversation pov

### Testing

- Use central instead of conversation
- Fix minor clippy lints in tests
- Apply clippy suggestions on test sources
- Reorganize tests in conversation.rs
- Nest conversation tests in dedicated modules
- Verify adding a keypackage to a ConversationMember

## [0.2.0] - 2022-03-22

### Bug Fixes

- Set correct path to toolchain depending on platform & copy bindings
- Fix broken tests
- Tests fix
- Fixed iOS WAL behavior for SQLite-backed stores
- Fix Keystore trait having update method removed
- Clippy + fmt pass on core-crypto
- Fmt + clippy pass
- Migrations were incorrectly defined

### Features

- Add android project
- Add tasks for building and copying jvm resources
- Add jvm project
- WIP hand-written ts bindings
- Generate Swift & Kotlin bindings 🎉
- Updated deps
- Added salt in keychain management instead of flat AES-encrypted file
- Added WIP DS mockup based on QUIC
- Added ability to create conversations (!!!)
- Added api support for in-memory keystore
- Added in-memory faculties for keystore
- Added benches for the MLS key management
- Added benches & fixed performance issues
- Added integration tests + fixes
- Implemented LRU cache for keystore
- Added support for Proteus PreKeys
- Progress + fix store compilation to WASM

### Miscellaneous Tasks

- Configure wire maven repository
- Clean up gradle files

