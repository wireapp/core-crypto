# Changelog

Platform support legends:

* ✅ = tier 1 support. Things just work.
* ⚠️ = tier 2 support. Things compile but *might* not work as expected. Basically works but with papercuts
    * Note: the papercuts will majorly be with the build process. Things might be very rough to integrate as no polish at all has been given yet.
* ❌ = tier 3 support. It doesn't work just yet, but we plan to make it work.

## [0.5.0] - 2022-14-09

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Wee_alloc memory leak + NPM publish issue
- Unreachable pub struct breaks docgen
- Fixed iOS SQLCipher salt handling within keychain
- [**breaking**] Changed misleading callback API and docs
- [**breaking**] Added missing TS API to set CoreCrypto callbacks
- Force software implementation for sha2 on target architectures not supporting hardware implementation (i686 & armv7 in our case)

### Documentation

- Add forgotten 0.4.0 changelog

### Features

- [**breaking**] 'commit_pending_proposals' now returns an optional CommitBundle when there is no pending proposals to commit

### Miscellaneous Tasks

- Release v0.5.0
- Update node version from 12 to 16 LTS
- Update dependencies
- Remove es2020-specific operators and target es2020 only
- Updated changelog

</details>

* **[BREAKING]**: `commit_pending_proposals` now returns an optional `CommitBundle`
    * This was made to handle the case where there are no queued proposals to commit and this method would be called, causing the operation to fail.
* **[BREAKING]**: Changed the API for callbacks for clarity
    * This also contains documentation changes that make the use and intent of callbacks easier to understand.
* Fixed the iOS-specific database salt handling to allow using several databases on the same device.
* TypeScript bindings:
    * Removed the use of ES2020-specific operators (`??` Null-coalescing operator) to allow downstream to compile without transpiling.
    * Added callbacks API
    * Removed the usage of `wee_alloc` allocator as it leaks memory: https://github.com/rustwasm/wee_alloc/issues/106

## [0.4.2] - 2022-09-05

<details>
    <summary>git-conventional changelog</summary>

</details>

* Fixes runtime issues on Android caused by the [sha2](https://github.com/RustCrypto/hashes/tree/master/sha2) crate.

## [0.4.1] - 2022-09-01

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Uniffi breaking changes in patch release and ffi error due to unused `TlsMemberAddedMessages`

</details>

* Fixes build issues for mobile target

## [0.4.0] - 2022-08-31

### CoreCrypto

* Allow rollbacking proposals. Now every method for creating a proposal also returns a proposal reference
(unique identifier) one can use later on to `clear_pending_proposal`
* Add `clear_pending_proposal` to wipe out local pending proposals
* Add `clear_pending_commit` to wipe out local pending commit
* Add `conversation_epoch` to get the current conversation's MLS epoch
* Now `decrypt_message` returns the sender client_id when the message is an application message. To use in calling.
* Durability: Now all the mutable operations are checked for durability i.e. would a process crash turn the application
into an inconsistent state. It boils down to verifying that we persist the MLS group in the keystore after every
operation mutating it
* Added a clean and documented Swift wrapper and tasks to build it more easily
* use 128 bytes of padding when encrypting messages instead of 16 previously
* Add some commit methods `final_add_clients_to_conversation`, `final_remove_clients_from_conversation`,
`final_update_keying_material` & `final_commit_pending_proposals` which return a TLS serialized CommitBundle. It cannot
be used now since wire-server does not yet have an endpoint for supplying it. It can be used to test the endpoint.
In the end, the `final_` prefix will removed and the not prefixed methods will be deprecated.
* Benchmarks have been improved and now also cover MLS operations

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Ensure durable methods are well tested and actually durable

### Features

- Commits and group creation return a TLS serialized CommitBundle. The latter also contains a PublicGroupStateBundle to prepare future evolutions
- [**breaking**] 'decrypt_message' returns the sender client id
- Use 128 bytes of padding when encrypting messages instead of 16 previously
- Add function to return current epoch of a group [CL-80] ([#96](https://github.com/wireapp/core-crypto/issues/96))
- Adding a wrapper for the swift API and initial docs [CL-62] ([#89](https://github.com/wireapp/core-crypto/issues/89))
- Add '#[durable]' macro to verify the method is tolerant to crashes and persists the MLS group in keystore
- Expose 'clear_pending_commit' method
- Allow rollbacking a proposal
- [**breaking**] Expose 'clear_pending_commit' method
- [**breaking**] Allow rollbacking a proposal

### Miscellaneous Tasks

- Migrate benchmarks to async and write some for core crypto operations
- Fixed WASM E2E tests

### Testing

- Add reminder for x509 certificate tests

</details>

## [0.3.1] - 2022-08-16

<details>
    <summary>git-conventional changelog</summary>

### Miscellaneous Tasks

- Release v0.3.1

</details>

Maintenance release to prepare for the next release

* Pinned all git dependencies via git tags to avoid breakage in the future


## [0.3.0] - 2022-08-12

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Clippy fix impl eq
- Libgcc swizzling for android was removed
- Cleaned up FFI names for clearer intent
- Caught up WASM api with the internal API changes
- Doctests were failing because included markdown snippets were parsed and compiled
- Defer validation that a callback has to be set for validating external add proposal after incoming proposal identified as such
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

- Review external add proposal validation and remove 'InvalidProposalType' error
- Remove required KeyPackage when creating an external add proposal
- Remove commits auto-merge behaviour
- Expose GroupInfo after commit operation
- Use draft-16 implementation of external sender. Expose a correct type through ffi for remove key
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

- Bump WASM bundle version to 0.3.0
- Added Changelog generator
- Fix nits on CHANGELOG-HUMAN.md
- Add changelog generator configuration + human changelog
- Disable crate publishing + UniFFI catchup
- Rename 'group_info' into 'public_group_state' to remain consistent with draft-12
- Remove 'SelfKeypackageNotFound' error which is not used
- Fix some clippy lints
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

- Add tests for 'commit_pending_proposals'
- Verify that commit operation are returning a valid welcome if any
- Use Index trait to access conversation from Central instead of duplicate accessor
- Use central instead of conversation
- Fix minor clippy lints in tests
- Apply clippy suggestions on test sources
- Reorganize tests in conversation.rs
- Nest conversation tests in dedicated modules
- Verify adding a keypackage to a ConversationMember

</details>

This second major release focuses on expanding our platform support and featureset

Platform support status:

* x86_64-unknown-linux-gnu ✅
* x86_64-apple-darwin ✅
* x86_64-pc-windows-msvc ❌
* armv7-linux-androideabi ✅ (⚠️)
* aarch64-linux-android ✅ (⚠️)
* i686-linux-android ✅ (⚠️)
* x86_64-linux-android ✅ (⚠️)
* aarch64-apple-ios ✅ (⚠️)
* aarch64-apple-ios-sim ✅ (⚠️)
* x86_64-apple-ios ✅ (⚠️)
* wasm32-unknown-unknown ✅

Note: all the platforms marked with (⚠️) above will get a round of polish for the build process & documentation in the next release.

### CoreCrypto

* Majorly improved documentation across all crates. Documentation for the `main` branch can be found here. The `HEAD` of this branch should only be a tagged version.
    * This documentation is available here: <https://wireapp.github.io/core-crypto/core_crypto/>
* Moved the codebase to `async`
    * This was a requirement to make everything work on the WASM target, as we cannot block the JavaScript runtime without making the browsers freeze up completely
    * As a consequence, we forked `openmls` to [wireapp/openmls](https://github.com/wireapp/openmls)
        * Our incremental changes, including the `async` rewrite of `openmls` is located [here](https://github.com/wireapp/openmls/pull/4)
* Added support for MLS Group Persistence, as this was preventing clients from continuing use of their joined groups (oops!)
* **All methods creating a commit e.g. `add_clients_to_conversation` now require to call `commit_accepted` when Delivery Service responds `200 OK`. Otherwise, it might indicate there was a `409 CONFLICT`, i.e. another client sent a commit for current epoch before and got accepted. In that case, do nothing and let things get reconciled in `decrypt_message`**
* Added support for lifetime-expired Keypackage pruning
* Added support for external CSPRNG entropy pool seeding
* Dropped the `openmls-rust-crypto-provider` in favour of our `mls-crypto-provider` with support for more ciphersuites and updated dependencies
    * As a consequence, we forked `hpke-rs` to [wireapp/hpke-rs](https://github.com/wireapp/hpke-rs)
        * Our changes can be found [here](https://github.com/wireapp/hpke-rs/tree/fix/updated-deps)
    * Ciphersuite support details:
        * `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` ✅
        * `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` ✅
        * `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` ✅
        * `MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448` ❌
            * There is no suitable `ed448` rust crate yet
        * `MLS_256_DHKEMP521_AES256GCM_SHA512_P521` ❌
            * `p521` RustCrypto crate is a WIP and not ready just yet. It shouldn't take too long though.
        * `MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448` ❌
            * There is no suitable `ed448` rust crate yet
        * `MLS_256_DHKEMP384_AES256GCM_SHA384_P384` ✅

* Expanded the API to include:
    * Conversations:
        * Ability to wipe
        * Ability to leave
        * Ability to force clients to update their keying material (i.e. self-update)
    * Support for MLS proposals
        * Exposed methods to create `Add` / `Remove` / `Update` proposals
    * Support for MLS external commits
        * Added ability to export MLS Public Group State for a given conversation
            * A `PublicGroupState` is also returned everytime you create a commit. This comes from the need to keep the MLS Delivery Service up to date on the `PublicGroupState` so that external commits can be made by other clients.
        * Added support for creating an external commit to join a conversation (`join_by_external_commit`)
    * Support for MLS external Add (`new_external_add_proposal`) and Remove Proposal (`new_external_remove_proposal`).
    * Support for X.509 credentials
    * Added a commit delay hint to prevent clients from rushing to commit to the server - which would cause epoch conflicts and high load
        * Returned in `decrypt_message`
* Changed most `message` fields to be named `commit`, as this would cause less confusion for consumers. Those fields always contained MLS commits and should be treated as such.
* All commit methods now return a `CommitBundle` struct containing
      * the commit message
      * an optional `Welcome` if there were pending add proposals
      * a `PublicGroupState` to upload to the Delivery Service
    * `decrypt_message` now returns a `DecryptedMessage` struct containing:
      * an optional application message
      * optional pending proposals renewed for next epoch to fan out
      * a `is_active` boolean indicating if the decrypted commit message caused the client to be removed from the group
      * the aforementioned commit delay

### FFI

* Added WASM bindings support to target `wasm32-unknown-unknown` as a new tier 1 target.
    * Added a full-fledged TypeScript wrapper with a full documentation to abstract the wasm-specific issues.
    * This now means that CoreCrypto is also now a NPM package. It is currently published at [@otak/core-crypto](https://www.npmjs.com/package/@otak/core-crypto)
* Incremental improvements to the Kotlin & Swift UniFFI bindings
    * Caught up the bindings' API to match our internal CoreCrypto APIs
* Added a C-FFI for maybe future work involving other targets than Kotlin & Swift


### Keystore

* Added support for WASM through an AES-GCM256-encrypted IndexedDB backend
    * This introduced a major refactoring to structure the code around having different backends depending on the platform.

## [0.2.0] - 2022-03-22

<details>
    <summary>git-conventional changelog</summary>

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

</details>

Initial stable release with a reduced featureset

Platform support status:

* x86_64-unknown-linux-gnu ✅
* x86_64-apple-darwin ✅
* x86_64-pc-windows-msvc ❌
* armv7-linux-androideabi ⚠️
* aarch64-linux-android ⚠️
* i686-linux-android ⚠️
* x86_64-linux-android ⚠️
* aarch64-apple-ios ⚠️
* aarch64-apple-ios-sim ⚠️
* x86_64-apple-ios ⚠️
* wasm32-unknown-unknown ❌

This release contains the following features:

### CoreCrypto

* Client abstraction
    * Handles creating/retrieving the locally stored client identity automatically
* Conversation handling
    * Ability to create conversations
    * Message encryption/decryption
    * Ability to add/remove users from a conversation
* Encrypted-at-rest Keystore for persistence of client keying material and keypackages

### FFI

* Added Swift and Kotlin bindings through UniFFI

### Keystore

* Added support for Proteus PreKeys
* Fixed iOS-specific WAL behavior to preserve backgrounding capabilities
    * See the comment at `https://wireapp.github.io/core-crypto/src/core_crypto_keystore/connection/platform/generic/mod.rs#99` for more details
* Fix for migrations being incorrectly defined


